"""
Cross-scan analytics — aggregates every scan belonging to one user into
fleet-level intelligence: posture leaderboards, riskiest hosts, per-domain
trends over time, and a crypto/algorithm rollup.

Two rules this module follows deliberately:

1. **It never re-implements scoring.** Every number comes from
   ``quantum_risk_engine.calculate_quantum_risk`` / ``summarize_fleet``, the
   same functions the per-scan dashboard and the exported reports use. A
   second scoring path here would let the analytics page and the dashboard
   disagree about the same host, which is exactly the class of bug the
   engine was centralised to kill.

2. **It reads scan status from ``scans``, never ``user_scans``.**
   ``user_scans.status`` is written once at queue time and never updated, so
   it still reads 'queued' for scans that finished hours ago. The join row is
   used only to establish ownership.

Aggregation is set-based: all of a user's scans are fetched in a fixed
number of queries and scored in one in-memory pass. The older
``/domain/{domain}/scans`` endpoint opens a fresh DB connection per scan
inside a loop; at fleet scale that pattern is what makes an analytics page
feel broken, so it is not repeated here.
"""

from collections import Counter, defaultdict

from database import get_connection
from quantum_risk_engine import (
    calculate_quantum_risk, summarize_fleet, get_risk_label,
    get_host_posture_tier, POSTURE_TIERS,
    COMPONENT_WEIGHTS, COMPONENT_LABELS,
)

# Best -> worst, derived from the engine rather than retyped. A boundary or
# name change in the scoring model must never leave this module describing
# tiers that no longer exist.
TIER_ORDER: list[str] = [tier for _, _, tier in POSTURE_TIERS]
TIER_RANGES: dict[str, tuple[int, int]] = {
    tier: (low, high) for low, high, tier in POSTURE_TIERS
}


def _placeholders(n: int) -> str:
    return ",".join("?" * n)


def _flag(value):
    return None if value is None else bool(value)


def _tls_input(row) -> tuple[dict, dict]:
    """Build the engine's two input dicts from a tls_results row."""
    tls = {"tls_version": row["tls_version"], "cipher_suite": row["cipher_suite"]}
    cert = {
        "key_algorithm": row["key_algorithm"],
        "key_size": row["key_size"],
        "signature_algorithm": row["signature_algorithm"],
        "certificate_expiry": row["certificate_expiry"],
        "is_expired": _flag(row["is_expired"]),
        "is_self_signed": _flag(row["is_self_signed"]),
        "hostname_mismatch": _flag(row["hostname_mismatch"]),
        "days_until_expiry": row["days_until_expiry"],
    }
    return tls, cert


def load_user_fleet(user_id: int | None = None) -> dict:
    """
    Fetch and score every asset across every scan a user owns — or, when
    ``user_id`` is None, across every scan in the system regardless of
    owner. This is the single place per-user scoping happens in the whole
    analytics module (see the module docstring); every ``build_*``
    function below operates in-memory on whatever fleet dict it's given,
    so admin_routes.py reuses them unmodified for fleet-wide views by
    calling this with ``user_id=None`` instead of duplicating the
    aggregation logic.

    Returns a dict with:
      ``scans``  — one record per scan, newest first, with its own fleet summary
      ``assets`` — one scored record per TLS result, tagged with scan + domain
    Both are plain lists so the individual report builders below can slice them
    without touching the database again.
    """
    conn = get_connection()
    try:
        if user_id is None:
            scan_rows = conn.execute(
                """
                SELECT id, target_domain, status, created_at, source
                FROM scans
                ORDER BY created_at DESC;
                """
            ).fetchall()
        else:
            scan_rows = conn.execute(
                """
                SELECT s.id, s.target_domain, s.status, s.created_at, s.source
                FROM user_scans us
                JOIN scans s ON s.id = us.scan_id
                WHERE us.user_id = ?
                ORDER BY s.created_at DESC;
                """,
                (user_id,),
            ).fetchall()

        scan_ids = [r["id"] for r in scan_rows]
        if not scan_ids:
            return {"scans": [], "assets": []}

        ph = _placeholders(len(scan_ids))

        tls_rows = conn.execute(
            f"""SELECT scan_id, hostname, port, tls_version, cipher_suite,
                       key_algorithm, key_size, signature_algorithm, certificate_expiry,
                       hostname_mismatch, is_self_signed, is_expired, days_until_expiry, issuer
                FROM tls_results WHERE scan_id IN ({ph});""",
            scan_ids,
        ).fetchall()

        hndl_rows = conn.execute(
            f"""SELECT scan_id, hostname, service_type, hndl_multiplier, risk_level
                FROM hndl_results WHERE scan_id IN ({ph});""",
            scan_ids,
        ).fetchall()

        algo_rows = conn.execute(
            f"""SELECT scan_id, hostname, key_exchange, signature, encryption, hash
                FROM algorithm_analysis WHERE scan_id IN ({ph});""",
            scan_ids,
        ).fetchall()

        failure_counts = {
            r["scan_id"]: r["cnt"]
            for r in conn.execute(
                f"SELECT scan_id, COUNT(*) cnt FROM scan_failures WHERE scan_id IN ({ph}) GROUP BY scan_id;",
                scan_ids,
            ).fetchall()
        }

        discovered_counts = {
            r["scan_id"]: r["cnt"]
            for r in conn.execute(
                f"SELECT scan_id, COUNT(*) cnt FROM discovered_assets WHERE scan_id IN ({ph}) GROUP BY scan_id;",
                scan_ids,
            ).fetchall()
        }
    finally:
        conn.close()

    hndl_map = {(r["scan_id"], r["hostname"]): dict(r) for r in hndl_rows}
    algo_map = {(r["scan_id"], r["hostname"]): dict(r) for r in algo_rows}

    scan_meta = {r["id"]: r for r in scan_rows}
    assets = []
    for row in tls_rows:
        key = (row["scan_id"], row["hostname"])
        tls, cert = _tls_input(row)
        result = calculate_quantum_risk(tls, cert, hndl_map.get(key), algo_map.get(key))
        meta = scan_meta[row["scan_id"]]

        # The component that contributed most to THIS asset's composite —
        # the single highest-leverage fix, used for the fleet-wide
        # "most common weakest link" rollup.
        top = max(COMPONENT_WEIGHTS, key=lambda k: result["breakdown"][k] * COMPONENT_WEIGHTS[k])

        assets.append({
            "scan_id": row["scan_id"],
            "domain": meta["target_domain"],
            "scanned_at": meta["created_at"],
            "hostname": row["hostname"],
            "port": row["port"],
            "tls_version": row["tls_version"],
            "cipher_suite": row["cipher_suite"],
            "key_algorithm": row["key_algorithm"],
            "key_size": row["key_size"],
            "signature_algorithm": row["signature_algorithm"],
            "issuer": row["issuer"],
            "days_until_expiry": row["days_until_expiry"],
            "is_expired": _flag(row["is_expired"]),
            "is_self_signed": _flag(row["is_self_signed"]),
            "hostname_mismatch": _flag(row["hostname_mismatch"]),
            "risk_score": result["total_score"],
            "risk_label": result["risk_label"],
            # Posture tier of this single host. A fleet of one host is that
            # host, so the engine's rating -> tier chain applied to one score
            # is that host's tier by definition — same boundaries the fleet
            # headline uses, never a second set defined here.
            "posture_tier": get_host_posture_tier(result["total_score"]),
            "composite_score": result["composite_score"],
            "applied_floor": result["applied_floor"],
            "breakdown": result["breakdown"],
            "quantum_safe_key_exchange": result["quantum_safe_key_exchange"],
            "quantum_safe_signature": result["quantum_safe_signature"],
            "hndl_multiplier": result["hndl"]["multiplier"],
            "service_type": (hndl_map.get(key) or {}).get("service_type"),
            "hndl_risk_level": (hndl_map.get(key) or {}).get("risk_level"),
            "top_component": top,
            "top_component_label": COMPONENT_LABELS[top],
            "top_component_score": result["breakdown"][top],
            "algorithm": algo_map.get(key) or {},
        })

    assets_by_scan = defaultdict(list)
    for a in assets:
        assets_by_scan[a["scan_id"]].append(a)

    scans = []
    for r in scan_rows:
        scan_assets = assets_by_scan.get(r["id"], [])
        fleet = summarize_fleet([a["risk_score"] for a in scan_assets])
        scans.append({
            "scan_id": r["id"],
            "domain": r["target_domain"],
            # Real status, from scans — user_scans.status is stale by design.
            "status": r["status"],
            "source": r["source"],
            "created_at": r["created_at"],
            "assets_discovered": discovered_counts.get(r["id"], 0),
            "assets_scanned": len(scan_assets),
            "assets_failed": failure_counts.get(r["id"], 0),
            "average_risk_score": fleet["average_risk_score"],
            "enterprise_rating": fleet["enterprise_rating"],
            "posture_tier": fleet["posture_tier"],
            "band_counts": fleet["band_counts"],
            "has_crypto_data": len(scan_assets) > 0,
        })

    return {"scans": scans, "assets": assets}


def _latest_asset_per_host(assets: list) -> list:
    """
    Collapse repeat observations of the same host to its most recent scan.

    Without this, a domain scanned five times contributes the same host five
    times to the "riskiest hosts" table and dominates it purely by being
    scanned often rather than by being risky.
    """
    newest = {}
    for a in assets:
        key = (a["hostname"], a["port"])
        current = newest.get(key)
        if current is None or (a["scanned_at"] or "") > (current["scanned_at"] or ""):
            newest[key] = a
    return list(newest.values())


def build_overview(fleet: dict) -> dict:
    """Headline numbers across every scan the user owns."""
    scans, assets = fleet["scans"], fleet["assets"]
    latest = _latest_asset_per_host(assets)
    summary = summarize_fleet([a["risk_score"] for a in latest])

    pqc_kex = sum(1 for a in latest if a["quantum_safe_key_exchange"])
    pqc_sig = sum(1 for a in latest if a["quantum_safe_signature"])
    total = len(latest)

    # Per-host posture tiers, counted over the same latest-observation list as
    # the risk bands so the two distributions always reconcile against
    # unique_hosts. Every tier keeps a row even at zero: "Legacy: 0" is a
    # finding, and dropping empty tiers would silently change the chart's
    # category set from one account to the next.
    tier_counts = {tier: 0 for tier in TIER_ORDER}
    for a in latest:
        if a["posture_tier"] in tier_counts:
            tier_counts[a["posture_tier"]] += 1

    return {
        "total_scans": len(scans),
        "total_domains": len({s["domain"] for s in scans}),
        "scans_with_crypto_data": sum(1 for s in scans if s["has_crypto_data"]),
        "unique_hosts": total,
        "assets_discovered": sum(s["assets_discovered"] for s in scans),
        "assets_failed": sum(s["assets_failed"] for s in scans),
        # Fleet posture is computed over the latest observation of each host,
        # so re-scanning a domain does not double-count it.
        "average_risk_score": summary["average_risk_score"],
        "enterprise_rating": summary["enterprise_rating"],
        "posture_tier": summary["posture_tier"],
        "band_counts": summary["band_counts"],
        "tier_counts": tier_counts,
        "tier_distribution": [
            {
                "tier": tier,
                "hosts": tier_counts[tier],
                "percent": round(tier_counts[tier] / total * 100, 1) if total else 0.0,
                "rating_min": TIER_RANGES[tier][0],
                "rating_max": TIER_RANGES[tier][1],
            }
            for tier in TIER_ORDER
        ],
        "pqc_key_exchange_hosts": pqc_kex,
        "pqc_signature_hosts": pqc_sig,
        "pqc_key_exchange_percent": round(pqc_kex / total * 100, 1) if total else 0.0,
        "pqc_signature_percent": round(pqc_sig / total * 100, 1) if total else 0.0,
        "last_scan_at": scans[0]["created_at"] if scans else None,
    }


def build_history(fleet: dict) -> dict:
    """Flat newest-first list of every scan — replaces the old My Scans grid."""
    return {"total_scans": len(fleet["scans"]), "scans": fleet["scans"]}


def build_domain_leaderboard(fleet: dict) -> dict:
    """
    One row per domain, ranked worst posture first, using each domain's most
    recent scan that actually produced crypto data.

    Ranking on the latest *data-bearing* scan matters: a domain whose newest
    scan reached zero hosts would otherwise rank as risk 0 and appear to be
    the safest company in the estate.
    """
    by_domain = defaultdict(list)
    for s in fleet["scans"]:
        by_domain[s["domain"]].append(s)

    assets_by_domain = defaultdict(list)
    for a in fleet["assets"]:
        assets_by_domain[a["domain"]].append(a)

    rows = []
    for domain, scans in by_domain.items():
        ordered = sorted(scans, key=lambda s: s["created_at"] or "", reverse=True)
        with_data = [s for s in ordered if s["has_crypto_data"]]
        latest = with_data[0] if with_data else ordered[0]

        domain_assets = [a for a in assets_by_domain[domain] if a["scan_id"] == latest["scan_id"]]
        worst = max(domain_assets, key=lambda a: a["risk_score"], default=None)

        rows.append({
            "domain": domain,
            "scan_count": len(ordered),
            "latest_scan_id": latest["scan_id"],
            "latest_scan_at": latest["created_at"],
            "has_crypto_data": latest["has_crypto_data"],
            "assets_scanned": latest["assets_scanned"],
            "assets_failed": latest["assets_failed"],
            "assets_discovered": latest["assets_discovered"],
            "average_risk_score": latest["average_risk_score"],
            "enterprise_rating": latest["enterprise_rating"],
            "posture_tier": latest["posture_tier"],
            "band_counts": latest["band_counts"],
            "worst_host": worst["hostname"] if worst else None,
            "worst_host_score": worst["risk_score"] if worst else None,
            "comparable": len(ordered) > 1,
        })

    # Domains with no crypto data sort last: they are unranked, not safe.
    rows.sort(key=lambda r: (r["has_crypto_data"], r["average_risk_score"]), reverse=True)
    return {"total_domains": len(rows), "domains": rows}


def build_domain_trend(fleet: dict, domain: str) -> dict:
    """
    Posture movement across repeat scans of one domain, oldest to newest,
    with a per-scan delta and an improved/regressed/unchanged verdict.
    """
    scans = [s for s in fleet["scans"] if s["domain"] == domain]
    scans.sort(key=lambda s: s["created_at"] or "")

    points = []
    previous = None
    for s in scans:
        rating_delta = None if previous is None else s["enterprise_rating"] - previous["enterprise_rating"]
        risk_delta = None if previous is None else s["average_risk_score"] - previous["average_risk_score"]
        if rating_delta is None:
            verdict = "baseline"
        elif rating_delta > 0:
            verdict = "improved"
        elif rating_delta < 0:
            verdict = "regressed"
        else:
            verdict = "unchanged"

        points.append({
            "scan_id": s["scan_id"],
            "created_at": s["created_at"],
            "status": s["status"],
            "has_crypto_data": s["has_crypto_data"],
            "assets_scanned": s["assets_scanned"],
            "assets_failed": s["assets_failed"],
            "average_risk_score": s["average_risk_score"],
            "enterprise_rating": s["enterprise_rating"],
            "posture_tier": s["posture_tier"],
            "band_counts": s["band_counts"],
            "rating_delta": rating_delta,
            "risk_delta": risk_delta,
            "verdict": verdict,
        })
        # Only data-bearing scans form the comparison baseline; a scan that
        # reached no hosts is not evidence that posture changed.
        if s["has_crypto_data"]:
            previous = s

    comparable = [p for p in points if p["has_crypto_data"]]
    overall = None
    if len(comparable) >= 2:
        first, last = comparable[0], comparable[-1]
        overall = {
            "from_scan_id": first["scan_id"],
            "to_scan_id": last["scan_id"],
            "rating_change": last["enterprise_rating"] - first["enterprise_rating"],
            "risk_change": last["average_risk_score"] - first["average_risk_score"],
            "tier_from": first["posture_tier"],
            "tier_to": last["posture_tier"],
        }

    return {
        "domain": domain,
        "total_scans": len(points),
        "comparable_scans": len(comparable),
        # The UI uses this to show an honest "needs 2+ data-bearing scans"
        # state rather than plotting a single point as though it were a trend.
        "has_trend": len(comparable) >= 2,
        "points": points,
        "overall": overall,
    }


def build_risky_assets(fleet: dict, limit: int = 25) -> dict:
    """Riskiest individual hosts across the whole estate, worst first."""
    latest = _latest_asset_per_host(fleet["assets"])
    latest.sort(key=lambda a: (a["risk_score"], a["hndl_multiplier"]), reverse=True)
    top = latest[:limit]

    return {
        "total_hosts": len(latest),
        "returned": len(top),
        "hosts": [
            {
                "hostname": a["hostname"],
                "port": a["port"],
                "domain": a["domain"],
                "scan_id": a["scan_id"],
                "scanned_at": a["scanned_at"],
                "risk_score": a["risk_score"],
                "risk_label": a["risk_label"],
                "posture_tier": a["posture_tier"],
                "composite_score": a["composite_score"],
                "applied_floor": a["applied_floor"],
                "tls_version": a["tls_version"],
                "cipher_suite": a["cipher_suite"],
                "key_algorithm": a["key_algorithm"],
                "key_size": a["key_size"],
                "service_type": a["service_type"],
                "hndl_multiplier": a["hndl_multiplier"],
                "hndl_risk_level": a["hndl_risk_level"],
                "top_component": a["top_component"],
                "top_component_label": a["top_component_label"],
                "top_component_score": a["top_component_score"],
                "is_expired": a["is_expired"],
                "is_self_signed": a["is_self_signed"],
                "hostname_mismatch": a["hostname_mismatch"],
                "days_until_expiry": a["days_until_expiry"],
            }
            for a in top
        ],
    }


def _distribution(values) -> list:
    """Counter -> list of {value, count, percent}, most common first."""
    counts = Counter(v if v not in (None, "") else "unknown" for v in values)
    total = sum(counts.values())
    return [
        {"value": value, "count": count,
         "percent": round(count / total * 100, 1) if total else 0.0}
        for value, count in counts.most_common()
    ]


def build_crypto_rollup(fleet: dict) -> dict:
    """
    Fleet-wide algorithm inventory: what crypto is actually deployed across
    every host the user has scanned, plus where the weakest links cluster.
    """
    latest = _latest_asset_per_host(fleet["assets"])

    # Weakest-component tally, counted per host by whichever component
    # contributed most to that host's score.
    weakest = Counter(a["top_component"] for a in latest)
    total = len(latest)

    cert_findings = {
        "expired": sum(1 for a in latest if a["is_expired"]),
        "self_signed": sum(1 for a in latest if a["is_self_signed"]),
        "hostname_mismatch": sum(1 for a in latest if a["hostname_mismatch"]),
        "expiring_within_30_days": sum(
            1 for a in latest
            if not a["is_expired"] and isinstance(a["days_until_expiry"], int)
            and 0 <= a["days_until_expiry"] < 30
        ),
    }

    return {
        "hosts_analyzed": total,
        "tls_versions": _distribution(a["tls_version"] for a in latest),
        "cipher_suites": _distribution(a["cipher_suite"] for a in latest),
        "key_algorithms": _distribution(a["key_algorithm"] for a in latest),
        "signature_algorithms": _distribution(a["signature_algorithm"] for a in latest),
        "key_exchanges": _distribution((a["algorithm"] or {}).get("key_exchange") for a in latest),
        "hashes": _distribution((a["algorithm"] or {}).get("hash") for a in latest),
        "encryptions": _distribution((a["algorithm"] or {}).get("encryption") for a in latest),
        "service_types": _distribution(a["service_type"] for a in latest),
        "hndl_levels": _distribution(a["hndl_risk_level"] for a in latest),
        "issuers": _distribution(a["issuer"] for a in latest),
        "risk_bands": _distribution(a["risk_label"] for a in latest),
        "weakest_components": [
            {
                "key": key,
                "label": COMPONENT_LABELS[key],
                "weight": COMPONENT_WEIGHTS[key],
                "hosts": count,
                "percent": round(count / total * 100, 1) if total else 0.0,
            }
            for key, count in weakest.most_common()
        ],
        "certificate_findings": cert_findings,
    }
