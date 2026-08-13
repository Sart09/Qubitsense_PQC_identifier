"""
Report export module — builds the full scan report in three shapes:
JSON (dict, used directly by the /report endpoint), a CycloneDX 1.6
cryptographic-asset BOM, and a printable PDF. All three are derived from
the same underlying data gather so every format contains the identical
set of findings, never a subset — including scan failures, which the
dashboard shows but earlier export versions dropped.
"""

import io
import json
from datetime import datetime, timezone

from database import get_connection
from quantum_risk_engine import (
    calculate_quantum_risk, summarize_fleet, get_scoring_model,
)
from remediation import build_recommendations

APP_NAME = "Quantum Proof System Scanner"
APP_VERSION = "0.2.0"


def _parse_classification(raw: str) -> dict:
    """The `classification` column is a JSON string (family breakdown per
    algorithm role). Parse it so every export format can use it as
    structured data instead of dumping the raw JSON text."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _quantum_safe(name: str) -> bool:
    name_upper = (name or "").upper()
    return any(tag in name_upper for tag in ("KYBER", "ML-KEM", "DILITHIUM", "ML-DSA", "FALCON", "SPHINCS", "SLH-DSA", "PQ"))


def build_report_data(scan_id: int) -> dict:
    """
    Gather every piece of data recorded for a scan: assets, TLS results,
    quantum risk scoring, HNDL results, algorithm analysis, scan failures,
    and a summary (asset count / enterprise rating / posture tier /
    vulnerable count) computed with the exact same formula the dashboard
    UI uses, so every export format agrees with what the dashboard shows.
    """
    conn = get_connection()
    try:
        scan = conn.execute(
            "SELECT id, target_domain, status, created_at FROM scans WHERE id = ?;",
            (scan_id,),
        ).fetchone()
        if scan is None:
            return None

        assets = conn.execute(
            "SELECT hostname, ip_address, discovery_method FROM discovered_assets WHERE scan_id = ?;",
            (scan_id,),
        ).fetchall()

        tls = conn.execute(
            """SELECT hostname, port, tls_version, cipher_suite,
                      key_algorithm, key_size, signature_algorithm, certificate_expiry,
                      hostname_mismatch, is_self_signed, is_expired, days_until_expiry, issuer
               FROM tls_results WHERE scan_id = ?;""",
            (scan_id,),
        ).fetchall()

        hndl = conn.execute(
            "SELECT hostname, port, service_type, hndl_multiplier, risk_level FROM hndl_results WHERE scan_id = ?;",
            (scan_id,),
        ).fetchall()

        algo = conn.execute(
            """SELECT hostname, cipher_suite, key_exchange, signature,
                      encryption, hash, classification, quantum_risk_estimate
               FROM algorithm_analysis WHERE scan_id = ?;""",
            (scan_id,),
        ).fetchall()

        failures = conn.execute(
            """SELECT hostname, failure_category, failure_reason, attempt_count, created_at
               FROM scan_failures WHERE scan_id = ? ORDER BY created_at ASC;""",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    hndl_map = {row["hostname"]: dict(row) for row in hndl}
    algo_map = {row["hostname"]: dict(row) for row in algo}
    qr_list = []
    for t in tls:
        hostname = t["hostname"]
        tls_dict = {"tls_version": t["tls_version"], "cipher_suite": t["cipher_suite"]}
        cert_dict = {
            "key_algorithm": t["key_algorithm"],
            "key_size": t["key_size"],
            "signature_algorithm": t["signature_algorithm"],
            "certificate_expiry": t["certificate_expiry"],
            "is_expired": t["is_expired"],
            "is_self_signed": t["is_self_signed"],
            "hostname_mismatch": t["hostname_mismatch"],
            "days_until_expiry": t["days_until_expiry"],
        }
        risk_res = calculate_quantum_risk(
            tls_dict, cert_dict, hndl_map.get(hostname), algo_map.get(hostname)
        )
        b = risk_res["breakdown"]
        qr_list.append({
            "hostname": hostname,
            "port": t["port"],
            "risk_score": risk_res["total_score"],
            "risk_label": risk_res["risk_label"],
            # All ten weighted components, so the exported report carries the
            # full derivation rather than a six-field subset of it.
            "key_exchange_score": b["key_exchange"],
            "signature_score": b["signature"],
            "tls_score": b["tls_version"],
            "key_size_penalty": b["key_size"],
            "certificate_validity_score": b["certificate"],
            "cipher_score": b["cipher"],
            "forward_secrecy_score": b["forward_secrecy"],
            "cipher_mode_score": b["cipher_mode"],
            "hash_score": b["hash"],
            "certificate_trust_score": b["certificate_trust"],
            "composite_score": risk_res["composite_score"],
            "applied_floor": risk_res["applied_floor"],
            "hndl_multiplier": risk_res["hndl"]["multiplier"],
            "hndl_uplift": risk_res["hndl"]["uplift"],
            "quantum_safe_key_exchange": risk_res["quantum_safe_key_exchange"],
            "quantum_safe_signature": risk_res["quantum_safe_signature"],
        })

    algo_list = []
    for a in algo:
        row = dict(a)
        row["classification"] = _parse_classification(row.get("classification"))
        row["quantum_safe"] = _quantum_safe(row.get("key_exchange")) and _quantum_safe(row.get("signature"))
        algo_list.append(row)

    # Fleet aggregation comes from the engine so the report's rating and
    # tier are computed by exactly the same code as the dashboard's.
    fleet = summarize_fleet([r["risk_score"] for r in qr_list])
    vulnerable_critical = sum(1 for r in qr_list if r["risk_label"] in ("Quantum Vulnerable", "Critical"))
    failures_list = [dict(r) for r in failures]

    return {
        "scan_id": scan["id"],
        "domain": scan["target_domain"],
        "status": scan["status"],
        "created_at": scan["created_at"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "assets_discovered": len(assets),
            "assets_scanned": len(tls),
            "assets_failed": len(failures_list),
            "average_risk_score": fleet["average_risk_score"],
            "enterprise_rating": fleet["enterprise_rating"],
            "posture_tier": fleet["posture_tier"],
            "vulnerable_or_critical_assets": vulnerable_critical,
            "risk_band_counts": fleet["band_counts"],
        },
        "assets": [dict(r) for r in assets],
        "tls_results": [dict(r) for r in tls],
        "quantum_risk": qr_list,
        "hndl_results": [dict(r) for r in hndl],
        "algorithm_analysis": algo_list,
        "scan_failures": failures_list,
        # The scoring model travels with the report: anyone auditing an
        # exported score can see the exact weights and thresholds that
        # produced it without needing access to the source.
        "scoring_model": get_scoring_model(),
    }


def build_host_report_data(asset_id: int) -> dict | None:
    """
    Gather everything needed for a single host's remediation report: the
    same tls_results/hndl_results/algorithm_analysis rows the /asset/{id}
    drill-down endpoint (server.py) reads, plus the owning scan's context
    (domain, scan id, scan date), so a downloaded PDF is never orphaned
    from which scan it came from. Returns None if the asset doesn't exist.
    """
    conn = get_connection()
    try:
        tls = conn.execute(
            """SELECT id, scan_id, hostname, port, tls_version, cipher_suite,
                      key_algorithm, signature_algorithm, key_size, certificate_expiry,
                      hostname_mismatch, is_self_signed, is_expired, days_until_expiry, issuer
               FROM tls_results WHERE id = ?;""",
            (asset_id,),
        ).fetchone()
        if tls is None:
            return None

        scan = conn.execute(
            "SELECT id, target_domain, status, created_at FROM scans WHERE id = ?;",
            (tls["scan_id"],),
        ).fetchone()

        hndl = conn.execute(
            """SELECT service_type, hndl_multiplier, risk_level FROM hndl_results
               WHERE scan_id = ? AND hostname = ?;""",
            (tls["scan_id"], tls["hostname"]),
        ).fetchone()

        algo = conn.execute(
            """SELECT key_exchange, signature, encryption, hash FROM algorithm_analysis
               WHERE scan_id = ? AND hostname = ?;""",
            (tls["scan_id"], tls["hostname"]),
        ).fetchone()
    finally:
        conn.close()

    tls_dict = {"tls_version": tls["tls_version"], "cipher_suite": tls["cipher_suite"]}
    cert_dict = {
        "key_algorithm": tls["key_algorithm"],
        "key_size": tls["key_size"],
        "signature_algorithm": tls["signature_algorithm"],
        "certificate_expiry": tls["certificate_expiry"],
        "is_expired": tls["is_expired"],
        "is_self_signed": tls["is_self_signed"],
        "hostname_mismatch": tls["hostname_mismatch"],
        "days_until_expiry": tls["days_until_expiry"],
    }
    qr_res = calculate_quantum_risk(
        tls_dict, cert_dict,
        dict(hndl) if hndl else None,
        dict(algo) if algo else None,
    )

    return {
        "asset_id": tls["id"],
        "scan_id": tls["scan_id"],
        "domain": scan["target_domain"] if scan else None,
        "scan_status": scan["status"] if scan else None,
        "scan_created_at": scan["created_at"] if scan else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hostname": tls["hostname"],
        "port": tls["port"],
        "tls_version": tls["tls_version"],
        "cipher_suite": tls["cipher_suite"],
        "key_algorithm": tls["key_algorithm"],
        "signature_algorithm": tls["signature_algorithm"],
        "key_size": tls["key_size"],
        "certificate_expiry": tls["certificate_expiry"],
        "issuer": tls["issuer"],
        "hostname_mismatch": tls["hostname_mismatch"],
        "is_self_signed": tls["is_self_signed"],
        "is_expired": tls["is_expired"],
        "days_until_expiry": tls["days_until_expiry"],
        "hndl": dict(hndl) if hndl else None,
        "algorithm": dict(algo) if algo else None,
        "risk_score": qr_res["total_score"],
        "risk_label": qr_res["risk_label"],
        "composite_score": qr_res["composite_score"],
        "applied_floor": qr_res["applied_floor"],
        "hndl_multiplier": qr_res["hndl"]["multiplier"],
        "hndl_uplift": qr_res["hndl"]["uplift"],
        "quantum_safe_key_exchange": qr_res["quantum_safe_key_exchange"],
        "quantum_safe_signature": qr_res["quantum_safe_signature"],
        "score_components": qr_res["components"],
        # Same shared helper /asset/{id} uses, so the PDF and the dashboard
        # modal can never recommend different fixes for the same host.
        "recommendations": build_recommendations(qr_res["breakdown"], tls),
        "scoring_model": get_scoring_model(),
    }


# ---------------------------------------------------------------------------
# CycloneDX 1.6 cryptographic-asset BOM
# ---------------------------------------------------------------------------

def _oid_for(family: str) -> str:
    """Best-effort OID mapping; CycloneDX allows this to be omitted, but
    including it lets downstream CBOM tooling cross-reference known algos."""
    mapping = {
        "RSA": "1.2.840.113549.1.1.1",
        "ECDSA": "1.2.840.10045.4.3",
        "ED25519": "1.3.101.112",
        "X25519": "1.3.101.110",
        "ECDHE": "1.2.840.10045.2.1",
        "DHE": "1.2.840.113549.1.3.1",
    }
    for key, oid in mapping.items():
        if key in family.upper():
            return oid
    return None


def build_cyclonedx_bom(report: dict) -> dict:
    """
    Build a CycloneDX 1.6 BOM whose components are `cryptographic-asset`
    entries — one per distinct (host, role, algorithm) triple observed
    across the scan's algorithm analysis and TLS/certificate results.
    This is the standard machine-readable format for a Cryptographic
    Bill of Materials (CBOM), so the export can be fed directly into
    CycloneDX-compatible SBOM/CBOM tooling instead of only being
    human-readable. Unreachable targets (scan failures) are recorded as
    BOM-level properties so the document still accounts for every asset
    that was in scope, not only the ones that returned data.
    """
    domain = report["domain"] or "unknown-target"
    components = []
    seen = set()

    for a in report["algorithm_analysis"]:
        key_ex = a.get("key_exchange") or "Unknown"
        sig = a.get("signature") or "Unknown"
        enc = a.get("encryption") or "Unknown"
        hash_alg = a.get("hash") or "Unknown"
        hostname = a.get("hostname") or domain
        classification = a.get("classification") or {}

        family_for_role = {
            "key-exchange": classification.get("key_exchange_family", "unknown"),
            "signature": classification.get("signature_family", "unknown"),
            "encryption": classification.get("encryption_family", "unknown"),
            "hash": classification.get("hash_family", "unknown"),
        }

        for role, primitive, algo_name in (
            ("key-exchange", "key-agree", key_ex),
            ("signature", "signature", sig),
            ("encryption", "block-cipher", enc),
            ("hash", "hash", hash_alg),
        ):
            if not algo_name or algo_name == "Unknown":
                continue
            dedupe_key = (hostname, role, algo_name)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            components.append({
                "type": "cryptographic-asset",
                "name": f"{hostname} — {algo_name}",
                "bom-ref": f"crypto-asset/{hostname}/{role}/{algo_name}".replace(" ", "_"),
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": primitive,
                        "parameterSetIdentifier": algo_name,
                        "executionEnvironment": "software-plain-ram",
                        "implementationPlatform": "generic",
                        "cryptoFunctions": [role],
                        "nistQuantumSecurityLevel": 5 if _quantum_safe(algo_name) else 0,
                    },
                    "oid": _oid_for(algo_name),
                },
                "properties": [
                    {"name": "pqc:quantumSafe", "value": "true" if _quantum_safe(algo_name) else "false"},
                    {"name": "pqc:hostname", "value": hostname},
                    {"name": "pqc:algorithmFamily", "value": family_for_role.get(role, "unknown")},
                    {"name": "pqc:quantumRiskEstimate", "value": str(a.get("quantum_risk_estimate"))},
                ],
            })

    # Fold in TLS-level findings (cipher suite / cert key algorithm) not
    # already captured via algorithm_analysis, so the BOM matches the JSON
    # and PDF report 1:1 rather than being a partial view.
    qr_by_host = {q["hostname"]: q for q in report["quantum_risk"]}
    for t in report["tls_results"]:
        hostname = t.get("hostname") or domain
        qr = qr_by_host.get(hostname, {})
        cert_alg = t.get("key_algorithm") or "Unknown"
        key_size = t.get("key_size")
        dedupe_key = (hostname, "certificate", cert_alg, key_size)
        if cert_alg == "Unknown" or dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        components.append({
            "type": "cryptographic-asset",
            "name": f"{hostname}:{t.get('port')} — certificate ({cert_alg})",
            "bom-ref": f"crypto-asset/{hostname}/{t.get('port')}/certificate".replace(" ", "_"),
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": hostname,
                    "certificateFormat": "X.509",
                    "certificateExtension": "crt",
                },
            },
            "properties": [
                {"name": "pqc:keyAlgorithm", "value": cert_alg},
                {"name": "pqc:keySize", "value": str(key_size)},
                {"name": "pqc:tlsVersion", "value": t.get("tls_version") or "Unknown"},
                {"name": "pqc:certificateExpiry", "value": t.get("certificate_expiry") or "Unknown"},
                {"name": "pqc:riskLabel", "value": qr.get("risk_label", "Unknown")},
                {"name": "pqc:riskScore", "value": str(qr.get("risk_score", "Unknown"))},
            ],
        })

    metadata_properties = [
        {"name": "pqc:enterpriseRating", "value": str(report["summary"]["enterprise_rating"])},
        {"name": "pqc:postureTier", "value": report["summary"]["posture_tier"]},
        {"name": "pqc:assetsDiscovered", "value": str(report["summary"]["assets_discovered"])},
        {"name": "pqc:assetsScanned", "value": str(report["summary"]["assets_scanned"])},
        {"name": "pqc:assetsFailed", "value": str(report["summary"]["assets_failed"])},
        {"name": "pqc:vulnerableOrCriticalAssets", "value": str(report["summary"]["vulnerable_or_critical_assets"])},
    ]
    for f in report["scan_failures"]:
        metadata_properties.append({
            "name": "pqc:scanFailure",
            "value": f"{f.get('hostname')}: {f.get('failure_category')} — {f.get('failure_reason')} "
                     f"({f.get('attempt_count')} attempts)",
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:00000000-0000-4000-8000-{report['scan_id']:012d}",
        "version": 1,
        "metadata": {
            "timestamp": report["generated_at"],
            "tools": {
                "components": [
                    {"type": "application", "name": APP_NAME, "version": APP_VERSION}
                ]
            },
            "component": {
                "type": "application",
                "name": domain,
                "bom-ref": f"target/{domain}",
                "description": f"Scanned target — scan #{report['scan_id']}, status {report['status']}",
            },
            "properties": metadata_properties,
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# PDF report (built server-side with PyMuPDF — real selectable text and
# tables, not a screenshot of the rendered dashboard).
#
# Pages are landscape so wide tables (8-10 columns) have room to breathe,
# and every cell is truncated using the font's *actual* measured text
# width (fitz.get_text_length) rather than a guessed chars-per-point
# ratio — the guess is what caused neighbouring columns to visually
# overlap on long values (long signature algorithm names, full ISO
# timestamps) in the previous version.
# ---------------------------------------------------------------------------

PAGE_WIDTH, PAGE_HEIGHT = 842, 595  # A4 landscape, points
MARGIN = 36
FONT = "helv"
FONT_BOLD = "hebo"


def _fmt_date(iso_str: str) -> str:
    if not iso_str:
        return "—"
    try:
        return datetime.fromisoformat(iso_str).strftime("%Y-%m-%d")
    except ValueError:
        return iso_str[:10]


# PyMuPDF's base-14 fonts (helv/hebo) encode to Latin-1, which has no
# en-dash, em-dash or curly quotes — those glyphs are silently dropped, and
# a dropped en-dash took whole table cells ("850–1000") with it. Everything
# written to the PDF passes through this map first. Embedding a Unicode font
# would also work but would add a font file to the repo for no visual gain
# at these sizes.
_PDF_CHAR_MAP = {
    "–": "-", "—": "-", "−": "-",
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "…": "...", "×": "x", "≤": "<=", "≥": ">=",
    "→": "->", "·": "-", "•": "*", " ": " ",
}


def _pdf_text(value) -> str:
    """Render any value as PDF-safe Latin-1 text."""
    text = "" if value is None else str(value)
    for bad, good in _PDF_CHAR_MAP.items():
        text = text.replace(bad, good)
    return text.encode("latin-1", "replace").decode("latin-1")


def _truncate_to_width(fitz_mod, text: str, max_width: float, size: float, font: str) -> str:
    """Shorten `text` with a trailing ellipsis until it measures within
    max_width for the given font/size, using PyMuPDF's real glyph-width
    metrics instead of an approximate chars-per-point guess."""
    if fitz_mod.get_text_length(text, fontname=font, fontsize=size) <= max_width:
        return text
    ellipsis = "…"
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        candidate = text[:mid] + ellipsis
        if fitz_mod.get_text_length(candidate, fontname=font, fontsize=size) <= max_width:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo] + ellipsis if lo > 0 else ellipsis


def _new_pdf_writer(doc):
    """
    Shared low-level PyMuPDF page/text primitives — page-break handling,
    font selection, and the Latin-1 character substitution table — used by
    both the whole-scan report and the per-host remediation report, so
    that logic exists in exactly one place instead of two copies drifting
    apart. Returns (new_page, write, write_heading, write_table), all bound
    to `doc`.
    """
    import fitz  # PyMuPDF

    state = {"page": None, "y": MARGIN}

    def new_page():
        state["page"] = doc.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
        state["y"] = MARGIN

    def ensure_space(height: float):
        if state["page"] is None or state["y"] + height > PAGE_HEIGHT - MARGIN:
            new_page()

    def write(text: str, size=10, color=(0, 0, 0), gap=4, bold=False):
        ensure_space(size + gap)
        state["page"].insert_text(
            (MARGIN, state["y"] + size),
            _pdf_text(text),
            fontsize=size,
            fontname=FONT_BOLD if bold else FONT,
            color=color,
        )
        state["y"] += size + gap

    def write_heading(text: str, size=13):
        ensure_space(size + 16)
        state["y"] += 10
        write(text, size=size, bold=True, color=(0.66, 0, 0.14), gap=8)

    def write_table(headers, rows, col_widths, size=8, empty_message="No data recorded for this section."):
        usable_width = PAGE_WIDTH - 2 * MARGIN
        if sum(col_widths) > usable_width:
            scale = usable_width / sum(col_widths)
            col_widths = [w * scale for w in col_widths]
        cell_pad = 6

        def draw_row(cells, bold=False, color=(0, 0, 0)):
            ensure_space(size + 8)
            x = MARGIN
            for cell, w in zip(cells, col_widths):
                text = "-" if cell in (None, "") else _pdf_text(cell)
                font = FONT_BOLD if bold else FONT
                text = _truncate_to_width(fitz, text, w - cell_pad, size, font)
                state["page"].insert_text(
                    (x, state["y"] + size),
                    text,
                    fontsize=size,
                    fontname=font,
                    color=color,
                )
                x += w
            state["y"] += size + 8

        draw_row(headers, bold=True, color=(0.66, 0, 0.14))
        ensure_space(1)
        y_line = state["y"]
        state["page"].draw_line((MARGIN, y_line), (PAGE_WIDTH - MARGIN, y_line), color=(0.7, 0.7, 0.7), width=0.6)
        state["y"] += 3
        for row in rows:
            draw_row(row)
        if not rows:
            write(empty_message, size=size, color=(0.5, 0.5, 0.5))

    return new_page, write, write_heading, write_table


def build_pdf_report(report: dict) -> bytes:
    import fitz  # PyMuPDF

    doc = fitz.open()
    new_page, write, write_heading, write_table = _new_pdf_writer(doc)

    # ── Title ──
    new_page()
    write(APP_NAME, size=11, color=(0.4, 0.4, 0.4))
    write("Quantum Risk Scan Report", size=20, bold=True, color=(0.66, 0, 0.14), gap=14)
    write(f"Target domain: {report['domain']}", size=11)
    write(f"Scan ID: {report['scan_id']}    Status: {report['status']}", size=11)
    write(f"Scan started: {_fmt_date(report['created_at'])}    Report generated: {_fmt_date(report['generated_at'])}", size=11, gap=14)

    s = report["summary"]
    write_heading("Executive Summary")
    write(
        f"Assets discovered: {s['assets_discovered']}    |    Successfully scanned: {s['assets_scanned']}"
        f"    |    Unreachable: {s['assets_failed']}",
        size=10,
    )
    write(f"Average quantum risk score: {s['average_risk_score']}/100", size=10)
    write(f"Enterprise rating: {s['enterprise_rating']}/1000  (Posture tier: {s['posture_tier']})", size=10)
    write(f"Vulnerable or critical assets: {s['vulnerable_or_critical_assets']}", size=10)

    # ── Asset inventory ──
    write_heading("Asset Inventory")
    write_table(
        ["Hostname", "IP Address", "Discovery Method"],
        [[a.get("hostname"), a.get("ip_address"), a.get("discovery_method")] for a in report["assets"]],
        [320, 220, 220],
    )

    # ── TLS results ──
    write_heading("TLS Scan Results")
    write_table(
        ["Hostname", "Port", "TLS Ver", "Cipher Suite", "Key Alg", "Key Size", "Sig Alg", "Cert Expiry"],
        [
            [t.get("hostname"), t.get("port"), t.get("tls_version"), t.get("cipher_suite"),
             t.get("key_algorithm"), t.get("key_size"), t.get("signature_algorithm"), _fmt_date(t.get("certificate_expiry"))]
            for t in report["tls_results"]
        ],
        [150, 40, 55, 180, 90, 65, 160, 90],
        empty_message="No hosts completed a TLS handshake — see Scan Failures below.",
    )

    # ── Quantum risk ──
    # All ten raw component scores are printed, then the stages that turn
    # them into the total, so the number in the "Score" column can be
    # re-derived from the same page rather than taken on trust.
    write_heading("Quantum Risk Scoring — all 10 weighted components (raw 0-100, higher is worse)")
    write_table(
        ["Hostname", "Score", "Label", "KEX", "Sig", "Key", "PFS", "TLS", "Ciph", "Trust", "Mode", "Hash", "Life"],
        [
            [q.get("hostname"), q.get("risk_score"), q.get("risk_label"),
             q.get("key_exchange_score"), q.get("signature_score"), q.get("key_size_penalty"),
             q.get("forward_secrecy_score"), q.get("tls_score"), q.get("cipher_score"),
             q.get("certificate_trust_score"), q.get("cipher_mode_score"), q.get("hash_score"),
             q.get("certificate_validity_score")]
            for q in report["quantum_risk"]
        ],
        [145, 42, 118, 40, 34, 34, 34, 34, 38, 42, 38, 38, 34],
    )

    write_heading("Score Derivation per Asset", size=11)
    write_table(
        ["Hostname", "Composite", "Floor applied", "HNDL x", "Uplift", "PQC KEX", "PQC Sig", "Final"],
        [
            [q.get("hostname"), q.get("composite_score"), q.get("applied_floor") or "none",
             q.get("hndl_multiplier"), q.get("hndl_uplift"),
             "Yes" if q.get("quantum_safe_key_exchange") else "No",
             "Yes" if q.get("quantum_safe_signature") else "No",
             q.get("risk_score")]
            for q in report["quantum_risk"]
        ],
        [180, 70, 130, 60, 60, 60, 60, 50],
    )

    # ── HNDL ──
    write_heading("Harvest-Now, Decrypt-Later (HNDL) Results")
    write_table(
        ["Hostname", "Port", "Service Type", "Multiplier", "Risk Level"],
        [[h.get("hostname"), h.get("port"), h.get("service_type"), h.get("hndl_multiplier"), h.get("risk_level")]
         for h in report["hndl_results"]],
        [280, 60, 220, 100, 110],
    )

    # ── Algorithm analysis / CBOM ──
    write_heading("Cryptographic Bill of Materials (Algorithm Analysis)")
    write_table(
        ["Hostname", "Cipher Suite", "Key Exch", "Signature", "Encryption", "Hash", "Quantum-Safe", "Risk Est."],
        [
            [al.get("hostname"), al.get("cipher_suite"), al.get("key_exchange"), al.get("signature"),
             al.get("encryption"), al.get("hash"), "Yes" if al.get("quantum_safe") else "No",
             al.get("quantum_risk_estimate")]
            for al in report["algorithm_analysis"]
        ],
        [150, 170, 80, 90, 90, 70, 90, 70],
    )

    # ── Scan failures ──
    write_heading("Scan Failures — Unreachable Targets")
    write_table(
        ["Hostname", "Failure Category", "Reason", "Attempts", "First Recorded"],
        [
            [f.get("hostname"), f.get("failure_category"), f.get("failure_reason"),
             f.get("attempt_count"), _fmt_date(f.get("created_at"))]
            for f in report["scan_failures"]
        ],
        [220, 140, 260, 70, 110],
        empty_message="No failures — every discovered asset was reachable.",
    )

    # ── Scoring methodology ──
    # The model travels with the report so an exported PDF is self-contained:
    # a reader can audit any score above against the weights and thresholds
    # that produced it without access to the running system.
    model = report.get("scoring_model") or {}
    if model:
        new_page()
        write("Scoring Methodology", size=16, bold=True, color=(0.66, 0, 0.14), gap=10)
        write(
            f"Model v{model.get('model_version')} — {len(model.get('components', []))} weighted components, "
            f"score {model['score_range']['min']}-{model['score_range']['max']} "
            f"({model['score_range']['direction']}). Every input is measured from the TLS handshake "
            f"and certificate; no fixed or sample values are used.",
            size=9, color=(0.3, 0.3, 0.3), gap=10,
        )

        write_heading("Component Weights", size=11)
        write_table(
            ["Weight", "Component"],
            [[f"{c['weight_percent']}%", c["label"]] for c in model.get("components", [])],
            [80, 500],
        )
        write(f"Total weight: {model.get('weights_total')}", size=9, bold=True, gap=8)

        write_heading("Scoring Stages", size=11)
        write("1. Composite — weighted sum of the components above.", size=9)
        fm = model.get("floor_mapping", {})
        write(f"2. Floor gates — {fm.get('formula', '')}", size=9)
        write(f"   {fm.get('note', '')}", size=8, color=(0.4, 0.4, 0.4))
        for rule in model.get("floor_rules", []):
            write(f"   • Floor {rule['floor']} ({rule['name']}): {rule['trigger']}.", size=8)
            write(f"     {rule['rationale']}", size=8, color=(0.4, 0.4, 0.4))
        ha = model.get("hndl_amplification", {})
        write(f"3. HNDL amplification — {ha.get('formula', '')} "
              f"(sensitivity {ha.get('sensitivity')}, multiplier {ha.get('multiplier_range')}).", size=9)
        write(f"   {ha.get('note', '')}", size=8, color=(0.4, 0.4, 0.4))
        write(f"4. Clamp — bounded to {model['score_range']['min']}-{model['score_range']['max']}.", size=9, gap=8)

        write_heading("Risk Bands (per asset)", size=11)
        write_table(
            ["Range", "Label"],
            [[f"{b['min']}–{b['max']}", b["label"]] for b in model.get("risk_bands", [])],
            [90, 300],
        )

        write_heading("Posture Tiers (fleet)", size=11)
        write(f"{model.get('enterprise_rating', {}).get('formula', '')}", size=9, gap=6)
        write_table(
            ["Rating range", "Tier", "Max average risk"],
            [[f"{t['min_rating']}–{t['max_rating']}", t["tier"], t["max_avg_risk"]]
             for t in model.get("posture_tiers", [])],
            [120, 160, 140],
        )

    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()


def build_host_pdf_report(host: dict) -> bytes:
    """
    A single host's remediation report: identity, executive verdict, the
    full 10-component score derivation, crypto/certificate findings, HNDL
    exposure, and a prioritized remediation checklist — everything an
    auditor needs for one asset without wading through a whole-scan
    report. Built from `build_host_report_data(asset_id)`.
    """
    import fitz  # PyMuPDF

    doc = fitz.open()
    new_page, write, write_heading, write_table = _new_pdf_writer(doc)

    # ── Title ──
    new_page()
    write(APP_NAME, size=11, color=(0.4, 0.4, 0.4))
    write("Host Remediation Report", size=20, bold=True, color=(0.66, 0, 0.14), gap=14)
    write(f"Host: {host['hostname']}:{host['port']}", size=12, bold=True)
    if host.get("domain"):
        write(f"Parent domain: {host['domain']}    Scan #{host['scan_id']} ({host.get('scan_status') or 'unknown'})", size=10)
    write(
        f"Scan started: {_fmt_date(host.get('scan_created_at'))}    Report generated: {_fmt_date(host['generated_at'])}",
        size=10, gap=14,
    )

    # ── Executive verdict ──
    write_heading("Executive Verdict")
    write(f"Quantum risk score: {host['risk_score']}/100  —  {host['risk_label']}", size=13, bold=True)
    write(
        f"Composite (pre-floor) score: {host['composite_score']}    Floor applied: {host['applied_floor'] or 'none'}",
        size=9, color=(0.4, 0.4, 0.4),
    )
    write(
        f"HNDL multiplier: {host['hndl_multiplier']}x    HNDL uplift: +{host['hndl_uplift']}    "
        f"PQC key exchange: {'Yes' if host['quantum_safe_key_exchange'] else 'No'}    "
        f"PQC signature: {'Yes' if host['quantum_safe_signature'] else 'No'}",
        size=9, gap=10,
    )

    # ── Full component derivation, already sorted by weighted impact ──
    write_heading("Score Derivation — all 10 weighted components (raw 0-100, higher is worse)")
    write_table(
        ["Component", "Raw score", "Weight", "Weighted contribution"],
        [
            [c["label"], c["raw_score"], f"{c['weight'] * 100:.0f}%", round(c["weighted_contribution"], 2)]
            for c in host["score_components"]
        ],
        [280, 90, 80, 160],
    )

    # ── Crypto configuration ──
    write_heading("Cryptographic Configuration")
    algo = host.get("algorithm") or {}
    write_table(
        ["Field", "Value"],
        [
            ["TLS Version", host.get("tls_version")],
            ["Cipher Suite", host.get("cipher_suite")],
            ["Key Algorithm", host.get("key_algorithm")],
            ["Key Size", f"{host['key_size']} bits" if host.get("key_size") else None],
            ["Signature Algorithm", host.get("signature_algorithm")],
            ["Key Exchange (algorithm intelligence)", algo.get("key_exchange")],
            ["Hash Function", algo.get("hash")],
        ],
        [260, 380],
    )

    # ── Certificate validation ──
    write_heading("Certificate Validation")
    write_table(
        ["Field", "Value"],
        [
            ["Issuer", host.get("issuer")],
            ["Expiry", _fmt_date(host.get("certificate_expiry"))],
            ["Days until expiry", host.get("days_until_expiry")],
            ["Expired", "Yes" if host.get("is_expired") else "No"],
            ["Self-signed", "Yes" if host.get("is_self_signed") else "No"],
            ["Hostname mismatch", "Yes" if host.get("hostname_mismatch") else "No"],
        ],
        [260, 380],
    )

    # ── HNDL exposure ──
    write_heading("Harvest-Now, Decrypt-Later (HNDL) Exposure")
    hndl = host.get("hndl")
    write_table(
        ["Service Type", "Multiplier", "Risk Level"],
        [[hndl.get("service_type"), hndl.get("hndl_multiplier"), hndl.get("risk_level")]] if hndl else [],
        [300, 140, 200],
        empty_message="No HNDL service classification recorded for this host.",
    )

    # ── Remediation checklist — the core deliverable of this report ──
    write_heading("Remediation Checklist")
    for i, rec in enumerate(host["recommendations"], start=1):
        write(f"{i}. {rec}", size=10, gap=7)

    # ── Scoring methodology, same appendix as the whole-scan report ──
    model = host.get("scoring_model") or {}
    if model:
        new_page()
        write("Scoring Methodology", size=16, bold=True, color=(0.66, 0, 0.14), gap=10)
        write(
            f"Model v{model.get('model_version')} — {len(model.get('components', []))} weighted components, "
            f"score {model['score_range']['min']}-{model['score_range']['max']} "
            f"({model['score_range']['direction']}). Every input is measured from the TLS handshake "
            f"and certificate; no fixed or sample values are used.",
            size=9, color=(0.3, 0.3, 0.3), gap=10,
        )
        write_heading("Component Weights", size=11)
        write_table(
            ["Weight", "Component"],
            [[f"{c['weight_percent']}%", c["label"]] for c in model.get("components", [])],
            [80, 500],
        )
        write_heading("Risk Bands (per asset)", size=11)
        write_table(
            ["Range", "Label"],
            [[f"{b['min']}–{b['max']}", b["label"]] for b in model.get("risk_bands", [])],
            [90, 300],
        )

    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()
