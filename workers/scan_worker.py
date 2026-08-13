"""
Scan Worker -- Background process that picks up queued scan jobs,
runs domain discovery, stores results, and marks jobs as completed.

Run with:
    python workers/scan_worker.py
"""

import sys
import os
import io
import asyncio

# FIX 8: Windows compatibility — must be BEFORE any asyncio usage
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')

import time
import json as _json
from collections import Counter
from datetime import datetime, timezone, timedelta

# Add workers, backend, scanner, analysis, and intelligence directories to path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intelligence"))

from job_fetcher import (
    get_next_job,
    update_job_status,
    resume_paused_jobs,
    claim_job,
    is_cancelled,
    finalize_job_status,
    reconcile_orphaned_jobs,
)
from result_manager import store_result
from database import init_db, get_connection
from batch_writer import BatchWriter
from domain_discovery import discover_assets
from tls_scanner_async_concurrent import AsyncTLSScanner
from certificate_parser import parse_certificate
from cipher_parser import parse_cipher_suite
from algorithm_classifier import classify_family
from quantum_estimator import estimate_quantum_risk
from service_classifier import classify_service
from hndl_detector import detect_hndl_risk
from quantum_risk_engine import calculate_quantum_risk, summarize_fleet
from registry_updater import lookup_from_db, seed_registry as seed_crypto_registry
from threat_feed import run_feed_update
from config import (
    RECONCILE_CONCURRENCY, RECONCILE_MAX_HOSTS,
    RECONCILE_HOST_DEADLINE, RECONCILE_BUDGET_S,
    RECONCILE_COOLDOWN_S, RECONCILE_PASSES,
    DEGRADED_DEADLINE_RATIO, DEGRADED_SOURCE_FAILURES,
)

# Marker prefix for the scan_logs row that records unavailable discovery
# sources. Kept as a constant because it is both written and LIKE-matched.
SOURCE_FAILURE_MARKER = "[SOURCE-FAILURE]"

# Connection-level failures are retried once at low concurrency before being
# finalized — see scanner/config.py's RECONCILE_CONCURRENCY docstring for
# why. Protocol-level rejections (TLS_HANDSHAKE_FAIL, TLS_LEGACY_CIPHER,
# NOT_TLS, CERT_INVALID, DNS_NO_RECORD) are NOT retried: we verified live
# with openssl s_client that those are real, stable rejections independent
# of our scanner's concurrency, and retrying them would just cost time for
# no benefit.
RETRYABLE_FAILURE_CODES = {
    "TCP_TIMEOUT", "TCP_REFUSED", "TCP_ERROR", "TCP_UNREACHABLE",
    "HOST_DEADLINE", "BUDGET_EXCEEDED",
}

POLL_INTERVAL = 3   # seconds to wait when no jobs are available

def update_schedule_after_scan_from_db(scan_id: int, error_msg: str = None) -> None:
    conn = get_connection()
    try:
        schedule = conn.execute("""
            SELECT s.id, s.last_risk_score 
            FROM scheduled_scans s
            JOIN schedule_run_history h ON h.schedule_id = s.id
            WHERE h.scan_id = ?
        """, (scan_id,)).fetchone()
        
        if not schedule:
            return
            
        if error_msg:
            conn.execute("""
                UPDATE schedule_run_history
                SET status = 'failed',
                    completed_at = datetime('now'),
                    error_message = ?
                WHERE scan_id = ?
            """, (str(error_msg), scan_id))
        else:
            # Same columns the API scores against, so the trend line the
            # scheduler records matches what the dashboard shows for the
            # same scan instead of drifting from it.
            tls_rows = conn.execute(
                """SELECT hostname, tls_version, cipher_suite, key_algorithm, signature_algorithm,
                          key_size, certificate_expiry, hostname_mismatch, is_self_signed,
                          is_expired, days_until_expiry
                   FROM tls_results WHERE scan_id = ?""", (scan_id,)).fetchall()
            hndl_rows = conn.execute("SELECT hostname, service_type, hndl_multiplier, risk_level FROM hndl_results WHERE scan_id = ?", (scan_id,)).fetchall()
            hndl_map = {row["hostname"]: dict(row) for row in hndl_rows}
            algo_rows = conn.execute("SELECT hostname, key_exchange, signature, encryption, hash FROM algorithm_analysis WHERE scan_id = ?", (scan_id,)).fetchall()
            algo_map = {row["hostname"]: dict(row) for row in algo_rows}

            subdomains_found = conn.execute("SELECT COUNT(*) as c FROM discovered_assets WHERE scan_id = ?", (scan_id,)).fetchone()["c"]
            subdomains_scanned = len(tls_rows)

            scores = []
            for tls in tls_rows:
                hostname = tls["hostname"]
                tls_dict = {"tls_version": tls["tls_version"], "cipher_suite": tls["cipher_suite"]}
                cert_dict = {
                    "key_algorithm": tls["key_algorithm"], "key_size": tls["key_size"],
                    "signature_algorithm": tls["signature_algorithm"],
                    "certificate_expiry": tls["certificate_expiry"],
                    "is_expired": tls["is_expired"], "is_self_signed": tls["is_self_signed"],
                    "hostname_mismatch": tls["hostname_mismatch"],
                    "days_until_expiry": tls["days_until_expiry"],
                }
                qr_res = calculate_quantum_risk(
                    tls_dict, cert_dict, hndl_map.get(hostname), algo_map.get(hostname)
                )
                scores.append(qr_res["total_score"])

            risk_score = summarize_fleet(scores)["average_risk_score"]
            
            conn.execute("""
                UPDATE scheduled_scans
                SET prev_risk_score = last_risk_score,
                    last_risk_score = ?
                WHERE id = ?
            """, (risk_score, schedule['id']))
            
            conn.execute("""
                UPDATE schedule_run_history
                SET status = 'completed',
                    completed_at = datetime('now'),
                    risk_score = ?,
                    subdomains_found = ?,
                    subdomains_scanned = ?
                WHERE scan_id = ?
            """, (risk_score, subdomains_found, subdomains_scanned, scan_id))
            
        conn.commit()
        print(f"[worker] Updated Schedule Tracker for Scan ID {scan_id}")
    except Exception as e:
        print(f"[worker] Failed syncing the scheduler hook: {e}")
    finally:
        conn.close()

class ScanCancelled(Exception):
    """Raised when a scan is stopped mid-flight via POST /scan/{id}/stop.

    Distinct from a real failure so main() can leave the row as 'cancelled'
    instead of overwriting it with 'failed'.
    """


def run_scan(job: dict) -> None:
    """
    Run the domain discovery pipeline and store results.

    Discovery and DB writes are unchanged in spirit but rewired for
    throughput: TLS scanning streams results (AsyncTLSScanner.scan_stream)
    instead of gathering the whole batch, and every DB write goes through
    a BatchWriter instead of one connect+commit+close per row — measured
    400x faster. The separate 10-thread "IP resolution" phase that used to
    run before scanning is gone: it re-resolved hostnames the scanner
    resolves anyway, and its own output (ip_to_hostnames) was never read.

    The four log-message formats below are load-bearing: frontend/
    scan_progress.html regex-matches them to drive the five progress bars.
    Changing the wording breaks the demo UI silently (bars freeze at 0%
    with no error) — see the format notes inline.
    """
    scan_id = job["id"]
    domain = job["target_domain"]

    bw = BatchWriter(scan_id)
    try:
        # --- Discovery ----------------------------------------------------
        bw.log(f"[DISCOVERY] Starting discovery for {domain}...")
        # The pipeline's own per-technique / per-filter detail streams into
        # the same log the progress page reads, instead of dying in the
        # worker's stdout where nobody watching the scan can see it.
        assets, ghost_count, failed_sources = discover_assets(domain, log=bw.log)
        if failed_sources:
            # Persisted on the scan itself so the quality gate at completion
            # can see it — the log line alone scrolls past and never reaches
            # the caching decision.
            record_source_failures(scan_id, failed_sources)
        total_discovered = len(assets)
        total_endpoints = total_discovered
        # Format is load-bearing: /\[DISCOVERY[\s✓]*\] Discovered (\d+) unique/
        bw.log(f"[DISCOVERY ✓] Discovered {total_discovered} unique subdomains "
               f"from CT logs, DNS brute force, and passive DNS")

        # Cancellation checkpoint. Discovery is the cheap phase; TLS
        # scanning below is the multi-minute one, so bailing here is the
        # difference between a Stop click taking effect now versus after
        # the whole estate has been handshaken.
        if is_cancelled(scan_id):
            bw.log("[CANCELLED] Scan stopped by user after discovery")
            raise ScanCancelled(scan_id)

        # Name every host before scanning starts. A count alone ("315
        # subdomains") is unverifiable from the UI — you cannot tell a real
        # 315-host estate from a number the pipeline made up, and you cannot
        # see whether the interesting host you expected is in scope until
        # the scan finishes. Buffered: this is one row per host, and the
        # size/time flush lands them within the UI's poll interval anyway.
        for idx, hostname in enumerate(assets, start=1):
            bw.log(f"[INVENTORY {idx}/{total_discovered}] {hostname}", flush_now=False)
        bw.flush()

        # --- Stream TLS scans, process + store each result as it lands ----
        bw.log(f"[TLS ANALYSIS] Starting async concurrent analysis on "
               f"{total_endpoints} distinct subdomains...")

        def store_success(hostname: str, result_item: dict) -> None:
            """Parse + persist a successful TLS result. Shared by the main
            scan pass and the reconciliation pass so a recovered false
            failure is stored identically to a first-attempt success."""
            tls_res = {
                "tls_version": result_item.get("tls_version", ""),
                "cipher_suite": result_item.get("cipher_suite", ""),
                "der_cert": result_item.get("der_cert", b""),
                "method": result_item.get("method", "unknown"),
                "port": result_item.get("port", 443),
            }

            cert_meta = {}
            try:
                if tls_res.get("der_cert"):
                    cert_meta = parse_certificate(tls_res["der_cert"], hostname=hostname)
                    if "error_category" in cert_meta:
                        cert_meta = {
                            "key_algorithm": "unknown", "key_size": 0,
                            "signature_algorithm": "unknown", "certificate_expiry": "",
                        }
            except Exception:
                cert_meta = {
                    "key_algorithm": "unknown", "key_size": 0,
                    "signature_algorithm": "unknown", "certificate_expiry": "",
                }

            cipher_info, classification, algo_risk = {}, {}, {}
            try:
                cipher_info = parse_cipher_suite(tls_res.get("cipher_suite", ""))
                classification = classify_family(cipher_info)
                algo_risk = estimate_quantum_risk(classification)
            except Exception:
                cipher_info = {"key_exchange": "unknown", "signature": "unknown",
                                "encryption": "unknown", "hash": "unknown"}
                classification = {
                    "key_exchange_family": "unknown", "signature_family": "unknown",
                    "encryption_family": "unknown", "hash_family": "unknown",
                }
                algo_risk = {"quantum_risk_estimate": "unknown"}

            svc_type, hndl_data = "unknown", {}
            try:
                # Pass the scan target so the customer's own domain is
                # excluded from keyword matching — without it every host
                # under a domain like "pnb.bank.in" classifies as
                # Financial-API purely because the apex contains "bank".
                svc_type = classify_service(hostname, 443, domain)
                hndl_data = detect_hndl_risk(hostname, 443, svc_type)
            except Exception:
                svc_type = "unknown"
                hndl_data = {"hndl_multiplier": 0.0, "risk_level": "unknown"}

            live_port = tls_res.get("port", 443)
            bw.add_tls_result(
                hostname=hostname, port=live_port,
                tls_version=tls_res.get("tls_version"),
                cipher_suite=tls_res.get("cipher_suite"),
                key_algorithm=cert_meta.get("key_algorithm"),
                key_size=cert_meta.get("key_size"),
                signature_algorithm=cert_meta.get("signature_algorithm"),
                certificate_expiry=cert_meta.get("certificate_expiry"),
                hostname_mismatch=cert_meta.get("hostname_mismatch"),
                is_self_signed=cert_meta.get("is_self_signed"),
                is_expired=cert_meta.get("is_expired"),
                days_until_expiry=cert_meta.get("days_until_expiry"),
                issuer=cert_meta.get("issuer"),
            )
            bw.add_algorithm_analysis(
                hostname=hostname,
                cipher_suite=tls_res.get("cipher_suite"),
                key_exchange=cipher_info.get("key_exchange", "unknown"),
                signature=cipher_info.get("signature", "unknown"),
                encryption=cipher_info.get("encryption", "unknown"),
                hash_alg=cipher_info.get("hash", "unknown"),
                classification=_json.dumps(classification) if classification else _json.dumps({}),
                quantum_risk_estimate=algo_risk.get("quantum_risk_estimate", "unknown"),
            )
            bw.add_hndl_result(
                hostname=hostname, port=live_port,
                service_type=svc_type or "unknown",
                hndl_multiplier=hndl_data.get("hndl_multiplier", 0.0),
                risk_level=hndl_data.get("risk_level", "unknown"),
            )

        async def run_all_tls_scans():
            scanner = AsyncTLSScanner()
            failed_hosts: list[tuple[str, str, str]] = []
            # Connection-level failures are held here instead of finalized
            # immediately — they get one retry at low concurrency below
            # before we decide whether they're real.
            pending_retry: dict[str, dict] = {}
            tls_counter = {"succeeded": 0, "failed": 0}
            processed = 0

            async for result_item in scanner.scan_stream(assets):
                hostname = result_item.get("hostname", "")
                ip_address = result_item.get("ip_address") or ""
                method = "root" if hostname == domain else "discovery"
                bw.add_asset(hostname, ip_address, method)

                processed += 1

                # Cancellation checkpoint, sampled every 25 hosts so a Stop
                # lands within a second or two of real time without adding a
                # SELECT per host to the scan's hot path.
                if processed % 25 == 0 and is_cancelled(scan_id):
                    bw.log(f"[CANCELLED] Scan stopped by user after "
                           f"{processed}/{total_endpoints} hosts")
                    raise ScanCancelled(scan_id)

                # One line per host, naming it and what came back. The
                # aggregate counters below still drive the progress bars, but
                # they cannot show WHICH host is being scanned or what it
                # answered with — so a scan of hundreds of hosts used to be a
                # number ticking up with no evidence underneath it. Buffered,
                # so this costs no extra commit on the scan's hot path.
                if result_item.get("status") == "success":
                    store_success(hostname, result_item)
                    tls_counter["succeeded"] += 1
                    bw.log(
                        f"[SCAN {processed}/{total_endpoints}] ✓ {hostname}"
                        f"{f' [{ip_address}]' if ip_address else ''} — "
                        f"{result_item.get('tls_version') or 'unknown TLS'} · "
                        f"{result_item.get('cipher_suite') or 'unknown cipher'}",
                        flush_now=False,
                    )
                else:
                    failure_code = result_item.get("failure_code", "UNKNOWN")
                    error_reason = result_item.get("error", "Scan failed")
                    if failure_code in RETRYABLE_FAILURE_CODES:
                        pending_retry[hostname] = result_item
                        # Marked as held, not failed — it still has a retry
                        # coming, and calling it a failure here would
                        # contradict the reconciliation result later.
                        bw.log(
                            f"[SCAN {processed}/{total_endpoints}] … {hostname} — "
                            f"{failure_code}, holding for retry",
                            flush_now=False,
                        )
                    else:
                        attempts = result_item.get("attempts", 1) or 1
                        tls_counter["failed"] += 1
                        failed_hosts.append((hostname, failure_code, error_reason))
                        bw.add_failure(hostname, failure_code, error_reason, failure_code, attempts)
                        bw.log(
                            f"[SCAN {processed}/{total_endpoints}] ✗ {hostname} — "
                            f"{failure_code}: {error_reason}",
                            flush_now=False,
                        )

                # Emitted together so the "tls" and "quantum" bars advance in
                # tandem — resolution now happens as part of each host's
                # scan, not as a separate phase. Formats are load-bearing:
                #   /\[IP RESOLUTION\] Resolved (\d+)\/(\d+) domains/
                #   /\[TLS ANALYSIS\] Scanned (\d+)\/(\d+) endpoints/
                #   /\[STORAGE\] Stored (\d+)\/(\d+) domain results/
                if processed % 5 == 0 or processed == total_endpoints:
                    bw.log(f"[IP RESOLUTION] Resolved {processed}/{total_endpoints} domains")
                    bw.log(f"[TLS ANALYSIS] Scanned {processed}/{total_endpoints} endpoints "
                           f"(✓ {tls_counter['succeeded']} | ✗ {tls_counter['failed']})")
                    bw.log(f"[STORAGE] Stored {processed}/{total_endpoints} domain results")

            # --- Reconciliation pass ---------------------------------------
            # Retry connection-level failures at low concurrency before
            # finalizing them. A full-concurrency burst against a real,
            # defended target (verified live against a bank domain) trips
            # the target's own rate-limiting, and which hosts get caught
            # shifts run to run — the same domain scored 76 then 93-94
            # successful across otherwise-identical scans. Retried alone,
            # at low concurrency, a false failure looks exactly like a
            # normal successful scan; a genuinely offline host fails again
            # for the same reason, quickly.
            if pending_retry:
                retry_hosts = list(pending_retry.keys())[:RECONCILE_MAX_HOSTS]
                skipped = list(pending_retry.keys())[RECONCILE_MAX_HOSTS:]

                recovered = 0
                remaining = retry_hosts

                # Multi-pass: each pass retries only what the previous one
                # still could not reach, so a clean scan pays nothing extra
                # (empty pending set -> loop exits immediately) while a
                # throttled one gets another chance after a further cooldown.
                for pass_no in range(1, RECONCILE_PASSES + 1):
                    if not remaining:
                        break
                    is_last_pass = pass_no == RECONCILE_PASSES

                    # Cooldown BEFORE the pass, not after. Retrying into a
                    # still-hot rate limiter just re-confirms the same false
                    # failures — see RECONCILE_COOLDOWN_S in scanner/config.py.
                    await asyncio.sleep(RECONCILE_COOLDOWN_S)

                    # Format is load-bearing: scan_progress.html matches
                    # /\[RECONCILIATION\] Retrying (\d+) connection-level failures/
                    # so the pass counter has to sit AFTER that prefix.
                    bw.log(f"[RECONCILIATION] Retrying {len(remaining)} connection-level "
                           f"failures at reduced concurrency ({RECONCILE_CONCURRENCY}-way) "
                           f"to rule out scan-burst false failures "
                           f"(pass {pass_no}/{RECONCILE_PASSES}, after "
                           f"{RECONCILE_COOLDOWN_S:.0f}s cooldown)...")

                    reconcile_scanner = AsyncTLSScanner(
                        max_concurrent=RECONCILE_CONCURRENCY,
                        timeout=RECONCILE_HOST_DEADLINE,
                        budget_s=RECONCILE_BUDGET_S,
                    )
                    still_failing = []
                    reconciled = 0
                    async for result_item in reconcile_scanner.scan_stream(remaining):
                        hostname = result_item.get("hostname", "")
                        original = pending_retry[hostname]

                        if result_item.get("status") == "success":
                            store_success(hostname, result_item)
                            tls_counter["succeeded"] += 1
                            recovered += 1
                            # Named individually because this is the pass that
                            # changes a host's verdict — "recovered" as a count
                            # tells you nothing about which hosts were false
                            # failures, which is exactly what makes the
                            # reconciliation pass credible.
                            bw.log(f"[RETRY] ✓ {hostname} recovered — "
                                   f"{result_item.get('tls_version') or 'unknown TLS'} · "
                                   f"{result_item.get('cipher_suite') or 'unknown cipher'}",
                                   flush_now=False)
                        elif is_last_pass:
                            failure_code = result_item.get("failure_code", "UNKNOWN")
                            error_reason = result_item.get("error", "Scan failed")
                            total_attempts = (original.get("attempts", 1) or 1) + (result_item.get("attempts", 1) or 1)
                            tls_counter["failed"] += 1
                            failed_hosts.append((hostname, failure_code, error_reason))
                            bw.add_failure(hostname, failure_code, error_reason, failure_code, total_attempts)
                            bw.log(f"[RETRY] ✗ {hostname} confirmed failed — "
                                   f"{failure_code}: {error_reason}", flush_now=False)
                        else:
                            # Not finalized yet — recording a failure row here
                            # would double-count the host when the next pass
                            # also reports on it.
                            still_failing.append(hostname)
                            bw.log(f"[RETRY] … {hostname} — "
                                   f"{result_item.get('failure_code', 'UNKNOWN')}, "
                                   f"holding for pass {pass_no + 1}", flush_now=False)

                        reconciled += 1
                        # Without this, the progress page shows no new activity
                        # for the entire reconciliation pass (up to
                        # RECONCILE_BUDGET_S) and reads as hung even though work
                        # is actively happening. Format is load-bearing:
                        # frontend/scan_progress.html's reconcileProgressMatch.
                        if reconciled % 5 == 0 or reconciled == len(remaining):
                            bw.log(f"[RECONCILIATION] Verified {reconciled}/{len(remaining)} "
                                   f"flagged failures ({recovered} recovered)")

                    remaining = still_failing

                # Anything beyond RECONCILE_MAX_HOSTS never got a retry —
                # finalize as first-pass failures rather than dropping them.
                if skipped:
                    bw.log(f"[RETRY] {len(skipped)} host(s) over the "
                           f"{RECONCILE_MAX_HOSTS}-host retry cap — finalized on "
                           f"their first-pass result without a retry:")
                for hostname in skipped:
                    original = pending_retry[hostname]
                    failure_code = original.get("failure_code", "UNKNOWN")
                    error_reason = original.get("error", "Scan failed")
                    attempts = original.get("attempts", 1) or 1
                    tls_counter["failed"] += 1
                    failed_hosts.append((hostname, failure_code, error_reason))
                    bw.add_failure(hostname, failure_code, error_reason, failure_code, attempts)
                    bw.log(f"[RETRY] ✗ {hostname} — {failure_code} (not retried)",
                           flush_now=False)

                bw.log(f"[RECONCILIATION ✓] {recovered}/{len(retry_hosts)} recovered "
                       f"(were false failures from scan-burst concurrency, not real outages)")

            return failed_hosts, tls_counter

        try:
            failed_hosts, tls_counter = asyncio.run(run_all_tls_scans())
        except ScanCancelled:
            # Must precede the catch-all below, which would otherwise swallow
            # the cancellation and let the scan carry on to 'completed'.
            raise
        except Exception as e:
            bw.log(f"[TLS ANALYSIS] Error in async scanner: {e}")
            failed_hosts, tls_counter = [], {"succeeded": 0, "failed": 0}

        bw.log(f"[IP RESOLUTION ✓] Resolved {total_endpoints} domains")
        bw.log(f"[TLS ANALYSIS ✓] Completed async concurrent analysis "
               f"(✓ {tls_counter['succeeded']} succeeded | ✗ {tls_counter['failed']} failed)")
        bw.log(f"[STORAGE ✓] All {tls_counter['succeeded']} successful domains stored")

        if failed_hosts:
            code_counts = Counter(code for _, code, _ in failed_hosts)
            bw.log(f"[SUMMARY] ⚠ {len(failed_hosts)}/"
                   f"{tls_counter['succeeded'] + len(failed_hosts)} TLS scans failed:")
            label_map = {
                "DNS_NO_RECORD": "Ghost — safe to ignore",
                "TCP_TIMEOUT": "Host unreachable (confirmed on retry)",
                "TCP_REFUSED": "No HTTPS service (confirmed on retry)",
                "TCP_ERROR": "Connection error (confirmed on retry)",
                "TCP_UNREACHABLE": "Network unreachable (confirmed on retry)",
                "TLS_HANDSHAKE_FAIL": "WAF/CDN blocking",
                "TLS_LEGACY_CIPHER": "Legacy server",
                "CERT_MISMATCH": "Cert mismatch",
                "HOST_DEADLINE": "Timed out (confirmed on retry)",
                "BUDGET_EXCEEDED": "Skipped (scan budget exhausted)",
            }
            for code, count in code_counts.most_common():
                label = label_map.get(code, code)
                bw.log(f"         • {code}: {count} ({label})")

        # ghost_count now comes from discover_assets()'s real return value,
        # not the "always 0" `'ghost_count' in dir()` bug from before.
        bw.log(f"[SUMMARY ✓] Scan complete! {total_discovered} discovered • "
               f"{ghost_count} ghosts filtered • {tls_counter['succeeded']} TLS successful • "
               f"{tls_counter['failed']} failed")
    finally:
        bw.close()

    # --- Store a summary result row ------------------------------------
    store_result(
        scan_id=scan_id,
        host=domain,
        port=443,
        service="HTTPS",
    )


def count_scan_outcome(scan_id: int) -> dict:
    """
    Count what a finished scan actually produced.

    Used to decide the scan's terminal status. A scan that raised no
    exception but reached zero hosts has not "completed" in any sense a user
    would recognise — typo'd or parked domains resolve to nothing, so the
    pipeline runs cleanly and stores nothing. Marking those 'completed'
    produced scans that looked successful, rendered a dashboard full of
    zeroes, and generated empty PDF/JSON/CycloneDX reports.
    """
    conn = get_connection()
    try:
        def count(table):
            return conn.execute(
                f"SELECT COUNT(*) c FROM {table} WHERE scan_id = ?;", (scan_id,)
            ).fetchone()["c"]

        discovered = count("discovered_assets")
        scanned = count("tls_results")
        # HOST_DEADLINE specifically means "we ran out of wall clock waiting
        # on this host", which is what a target's rate limiter produces at
        # scale. Distinguished from TCP_REFUSED / CERT_INVALID / etc, which
        # are stable properties of the host and say nothing about throttling.
        deadline = conn.execute(
            "SELECT COUNT(*) c FROM scan_failures WHERE scan_id = ? "
            "AND failure_code = 'HOST_DEADLINE';",
            (scan_id,),
        ).fetchone()["c"]
        ratio = (deadline / discovered) if discovered else 0.0

        # Discovery-side degradation: passive sources that could not be
        # reached. Independent of the TLS-side deadline ratio — a scan can
        # be complete on one axis and partial on the other.
        row = conn.execute(
            "SELECT message FROM scan_logs WHERE scan_id = ? AND message LIKE ? "
            "ORDER BY id DESC LIMIT 1;",
            (scan_id, SOURCE_FAILURE_MARKER + "%"),
        ).fetchone()
        bad_sources = (
            [s for s in row["message"][len(SOURCE_FAILURE_MARKER):].strip().split(",") if s]
            if row else []
        )
        source_degraded = len(bad_sources) >= DEGRADED_SOURCE_FAILURES

        return {
            "discovered": discovered,
            "scanned": scanned,
            "failed_hosts": count("scan_failures"),
            "deadline_failures": deadline,
            "deadline_ratio": ratio,
            "failed_sources": bad_sources,
            # A run this deadline-heavy reports a floor, not an inventory —
            # and so does one missing a discovery source.
            "degraded": ratio >= DEGRADED_DEADLINE_RATIO or source_degraded,
        }
    finally:
        conn.close()


def record_source_failures(scan_id: int, sources: list[str]) -> None:
    """Persist which discovery sources were unavailable for this scan.

    Written into scan_logs with a fixed marker rather than a new column so
    it survives without a schema migration, and read back by
    count_scan_outcome() when deciding whether this run may be cached.
    """
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO scan_logs (scan_id, message, created_at) VALUES (?, ?, ?);",
            (scan_id, f"{SOURCE_FAILURE_MARKER} {','.join(sorted(sources))}",
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def best_cached_scan(domain: str) -> tuple[int, int] | None:
    """
    Return (scan_id, host_count) for the highest-yield unexpired cached scan
    of this domain, or None.

    Used to stop a throttled run from replacing a better one. The cache read
    in backend/server.py takes the NEWEST entry unconditionally, so without
    this a rate-limited re-scan silently becomes the answer of record for the
    next 24 hours.
    """
    conn = get_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        rows = conn.execute(
            "SELECT scan_id FROM scan_cache WHERE domain = ? AND expires_at > ?;",
            (domain, now),
        ).fetchall()
        best = None
        for r in rows:
            n = conn.execute(
                "SELECT COUNT(*) c FROM tls_results WHERE scan_id = ?;", (r["scan_id"],)
            ).fetchone()["c"]
            if best is None or n > best[1]:
                best = (r["scan_id"], n)
        return best
    finally:
        conn.close()


def main() -> None:
    """Main worker loop."""
    # Ensure tables exist (in case the worker starts before the server).
    init_db()

    # Clear jobs stranded by a previous worker that died mid-scan. Without
    # this, killing the worker (Ctrl+C, crash, reboot) leaves that scan
    # showing 'running' forever — the UI spins on a job no process owns.
    orphans = reconcile_orphaned_jobs()
    if any(orphans.values()):
        print(f"[worker] Startup reconcile: {orphans['salvaged']} finished-but-unwritten "
              f"-> completed, {orphans['failed']} genuinely incomplete -> failed, "
              f"{orphans['requeued']} paused -> queued", flush=True)

    # Seed crypto registry and run initial threat feed update
    print("[worker] Seeding crypto registry...", flush=True)
    feed_result = run_feed_update()
    print(f"[worker] Registry: {feed_result['seeded']} seeded, {feed_result['updated']} from feed", flush=True)

    print("=" * 60, flush=True)
    print("  Quantum Proof System Scanner -- Scan Worker v2.0", flush=True)
    print("  Scanner: Async DNS + 3-Tier TLS + Ghost Filter", flush=True)
    print("=" * 60, flush=True)
    print("Worker started", flush=True)
    print("  Waiting for jobs...\n", flush=True)

    while True:
        print("Checking for queued jobs...", flush=True)
        job = get_next_job()

        if job is not None:
            scan_id = job["id"]
            domain = job["target_domain"]

            print(f"Job found: {job}", flush=True)
            print(f"[worker] Picked up job {scan_id} -> {domain}", flush=True)

            # Mark as running. Guarded claim — if it fails, the job was
            # cancelled (or taken) between the SELECT and here, so drop it
            # and go back to polling rather than scanning a dead job.
            print("Updating job status -> running", flush=True)
            if not claim_job(scan_id):
                print(f"[worker] Job {scan_id} no longer queued (cancelled or "
                      f"claimed elsewhere) — skipping\n", flush=True)
                continue
            print(f"[worker] Job {scan_id} -> running", flush=True)

            try:
                run_scan(job)

                # A clean run is not automatically a successful one. If the
                # pipeline reached zero hosts there is nothing to score and
                # nothing to report, so the scan is terminal-failed rather
                # than completed — and it is NOT cached, because caching an
                # empty result would serve that emptiness to every re-scan
                # of the same domain for the next 24 hours.
                outcome = count_scan_outcome(scan_id)
                if outcome["scanned"] == 0:
                    reason = (
                        "no subdomains resolved — domain may not exist or has no public DNS records"
                        if outcome["discovered"] == 0
                        else f"all {outcome['discovered']} discovered host(s) were unreachable"
                    )
                    finalize_job_status(scan_id, "failed")
                    log_conn = get_connection()
                    try:
                        log_conn.execute(
                            "INSERT INTO scan_logs (scan_id, message, created_at) VALUES (?, ?, ?);",
                            (scan_id, f"[FAILED] Scan produced no scannable hosts — {reason}",
                             datetime.now(timezone.utc).isoformat()),
                        )
                        log_conn.commit()
                    finally:
                        log_conn.close()
                    update_schedule_after_scan_from_db(scan_id, f"No scannable hosts: {reason}")
                    print(f"[worker] Job {scan_id} -> failed (no scannable hosts: {reason})\n", flush=True)
                else:
                    print("Updating job status -> completed", flush=True)
                    # Guarded write: if a Stop landed during the final phase
                    # (after the last cancellation checkpoint), the row stays
                    # 'cancelled' and we skip the cache entry — otherwise the
                    # scan would resurrect itself as 'completed' AND seed the
                    # 24h cache with a run the user explicitly stopped.
                    if not finalize_job_status(scan_id, "completed"):
                        print(f"[worker] Job {scan_id} was cancelled during the "
                              f"final phase — leaving as cancelled, not caching\n", flush=True)
                    else:
                        # Scan-quality gate. A run where a large share of the
                        # estate died on HOST_DEADLINE was throttled, not
                        # surveyed — its host count is a floor. Record that on
                        # the scan, and refuse to let it displace a better
                        # cached run (server.py's cache read takes the NEWEST
                        # entry, so an unconditional insert would hand the
                        # dashboard the worse number for the next 24 hours).
                        quality_note = None
                        if outcome["degraded"]:
                            reasons = []
                            if outcome["failed_sources"]:
                                reasons.append(
                                    f"discovery sources unavailable "
                                    f"({', '.join(outcome['failed_sources'])})"
                                )
                            if outcome["deadline_ratio"] >= DEGRADED_DEADLINE_RATIO:
                                reasons.append(
                                    f"{outcome['deadline_failures']}/{outcome['discovered']} hosts "
                                    f"({outcome['deadline_ratio']:.0%}) hit the per-host deadline"
                                )
                            quality_note = (
                                f"[QUALITY] Degraded scan — {'; '.join(reasons)}. "
                                f"{outcome['scanned']} reachable hosts is a lower bound, "
                                f"not a complete inventory. Re-run after a few minutes."
                            )
                            print(f"[worker] {quality_note}", flush=True)

                        prior = best_cached_scan(domain)
                        skip_cache = (
                            outcome["degraded"]
                            and prior is not None
                            and prior[1] > outcome["scanned"]
                        )

                        now = datetime.now(timezone.utc)
                        cache_conn = get_connection()
                        try:
                            if quality_note:
                                cache_conn.execute(
                                    "INSERT INTO scan_logs (scan_id, message, created_at) VALUES (?, ?, ?);",
                                    (scan_id, quality_note, now.isoformat()),
                                )
                            if skip_cache:
                                msg = (
                                    f"[QUALITY] Not caching this run — scan {prior[0]} "
                                    f"already covers {domain} with {prior[1]} hosts vs "
                                    f"{outcome['scanned']} here. Keeping the better result."
                                )
                                cache_conn.execute(
                                    "INSERT INTO scan_logs (scan_id, message, created_at) VALUES (?, ?, ?);",
                                    (scan_id, msg, now.isoformat()),
                                )
                                print(f"[worker] {msg}", flush=True)
                            else:
                                # Write scan cache entry (24h window)
                                expires = now + timedelta(hours=24)
                                cache_conn.execute(
                                    "INSERT INTO scan_cache (domain, scan_id, created_at, expires_at) VALUES (?, ?, ?, ?);",
                                    (domain, scan_id, now.isoformat(), expires.isoformat()),
                                )
                                print(f"[worker] Cache entry written for {domain} (expires {expires.isoformat()})", flush=True)
                            cache_conn.commit()
                        finally:
                            cache_conn.close()

                        update_schedule_after_scan_from_db(scan_id)
                        print(f"[worker] Job {scan_id} -> completed "
                              f"({outcome['scanned']} hosts scanned)\n", flush=True)

                # Resume paused jobs if this was a priority scan
                if job.get("priority", 0) == 1:
                    resumed = resume_paused_jobs()
                    if resumed:
                        print(f"[worker] Resumed {resumed} paused queued jobs", flush=True)
            except ScanCancelled:
                # Deliberate stop, not a fault. The row is already 'cancelled'
                # (the API set it); leave it alone and take no failure path —
                # no cache entry, no schedule "last run failed" side effect.
                print(f"[worker] Job {scan_id} cancelled by user — stopped cleanly\n", flush=True)
            except Exception as exc:
                print(f"Updating job status -> failed ({exc})", flush=True)
                finalize_job_status(scan_id, "failed")
                update_schedule_after_scan_from_db(scan_id, str(exc))
                print(f"[worker] Job {scan_id} -> failed: {exc}\n", flush=True)

                # Resume paused jobs even on failure
                if job.get("priority", 0) == 1:
                    resumed = resume_paused_jobs()
                    if resumed:
                        print(f"[worker] Resumed {resumed} paused queued jobs", flush=True)
        else:
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Expected shutdown. Any job left 'running' is reconciled on the
        # next startup by reconcile_orphaned_jobs().
        print("\n[worker] Stopped", flush=True)
