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
import concurrent.futures
import json as _json
import threading
from collections import Counter

# Add workers, backend, scanner, analysis, and intelligence directories to path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intelligence"))

from job_fetcher import get_next_job, update_job_status, resume_paused_jobs
from result_manager import store_result, store_tls_result, store_hndl_result, store_algorithm_analysis, store_scan_failure
from database import init_db, get_connection
from domain_discovery import discover_assets, store_asset, resolve_ip
from tls_scanner_async_concurrent import AsyncTLSScanner
from certificate_parser import parse_certificate
from cipher_parser import parse_cipher_suite
from algorithm_classifier import classify_family
from quantum_estimator import estimate_quantum_risk
from service_classifier import classify_service
from hndl_detector import detect_hndl_risk
from quantum_risk_engine import calculate_quantum_risk
from registry_updater import lookup_from_db, seed_registry as seed_crypto_registry
from threat_feed import run_feed_update

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
            tls_rows = conn.execute("SELECT hostname, tls_version, cipher_suite, key_algorithm, signature_algorithm, key_size, certificate_expiry FROM tls_results WHERE scan_id = ?", (scan_id,)).fetchall()
            hndl_rows = conn.execute("SELECT hostname, risk_level FROM hndl_results WHERE scan_id = ?", (scan_id,)).fetchall()
            hndl_map = {row["hostname"]: row["risk_level"] for row in hndl_rows}
            
            subdomains_found = conn.execute("SELECT COUNT(*) as c FROM discovered_assets WHERE scan_id = ?", (scan_id,)).fetchone()["c"]
            subdomains_scanned = len(tls_rows)
            
            total_score = 0
            for tls in tls_rows:
                hndl_level = hndl_map.get(tls["hostname"], "")
                tls_dict = {"tls_version": tls["tls_version"], "cipher_suite": tls["cipher_suite"]}
                cert_dict = {
                    "key_algorithm": tls["key_algorithm"], "key_size": tls["key_size"],
                    "signature_algorithm": tls["signature_algorithm"], "certificate_expiry": tls["certificate_expiry"]
                }
                qr_res = calculate_quantum_risk(tls_dict, cert_dict, hndl_level)
                total_score += qr_res["total_score"]
                
            risk_score = round(total_score / subdomains_scanned) if subdomains_scanned > 0 else 0
            
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

def log_progress(scan_id: int, message: str) -> None:
    print(f"  [scan] {message}", flush=True)
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO scan_logs (scan_id, message) VALUES (?, ?);",
            (scan_id, message)
        )
        conn.commit()
    except Exception as e:
        pass
    finally:
        conn.close()

def run_scan(job: dict) -> None:
    """
    Run the domain discovery pipeline and store results.
    """
    scan_id = job["id"]
    domain = job["target_domain"]

    # --- Step 1: Discover assets -----------------------------------------
    log_progress(scan_id, f"[DISCOVERY] Starting discovery for {domain}...")
    assets = discover_assets(domain)
    total_discovered = len(assets)
    log_progress(scan_id, f"[DISCOVERY ✓] Discovered {total_discovered} unique subdomains from CT logs, DNS brute force, and passive DNS")

    total_live = total_discovered  # domain_discovery.py already ghost-filters

    # --- Step 2: Resolve IPs concurrently and store ----------------------
    ip_to_hostnames = {}
    resolve_lock = threading.Lock()
    resolve_counter = {"completed": 0}
    
    def resolve_and_store(hostname):
        ip = resolve_ip(hostname)
        method = "root" if hostname == domain else "discovery"
        store_asset(scan_id, hostname, ip, method)
        
        # Update progress counter
        with resolve_lock:
            resolve_counter["completed"] += 1
            if resolve_counter["completed"] % 10 == 0:
                log_progress(scan_id, f"[IP RESOLUTION] Resolved {resolve_counter['completed']}/{len(assets)} domains")
        
        return hostname, ip

    log_progress(scan_id, f"[IP RESOLUTION] Starting IP resolution for {len(assets)} domains...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(resolve_and_store, host): host for host in assets}
        for future in concurrent.futures.as_completed(futures):
            hostname, ip = future.result()
            # Group by IP to avoid redundant TLS scans
            if ip:
                ip_to_hostnames.setdefault(ip, []).append(hostname)
            else:
                ip_to_hostnames.setdefault(f"no_ip_{hostname}", []).append(hostname)

    log_progress(scan_id, f"[IP RESOLUTION ✓] Resolved {len(assets)} domains")

    # --- Step 3, 4, 5: Run TLS scans with async concurrent scanner -------
    total_endpoints = len(assets)
    log_progress(scan_id, f"[TLS ANALYSIS] Starting async concurrent analysis on {total_endpoints} distinct subdomains...")
    
    # Run async TLS scans
    async def run_all_tls_scans():
        scanner = AsyncTLSScanner(max_concurrent=50, timeout=12)
        raw_results = await scanner.scan_all_concurrent(assets)
        return raw_results
    
    # Execute async scanner
    try:
        tls_results_raw = asyncio.run(run_all_tls_scans())
    except Exception as e:
        log_progress(scan_id, f"[TLS ANALYSIS] Error in async scanner: {e}")
        tls_results_raw = []
    
    # Convert async results to compatible format and process
    results_map = {}
    failed_hosts = []
    tls_counter = {"succeeded": 0, "failed": 0}
    
    for result_item in tls_results_raw:
        hostname = result_item.get("hostname", "")
        
        if result_item.get("status") == "success":
            # Build compatible TLS result dict
            tls_res = {
                "tls_version": result_item.get("tls_version", ""),
                "cipher_suite": result_item.get("cipher_suite", ""),
                "der_cert": result_item.get("der_cert", b""),
                "method": result_item.get("method", "unknown"),
                "port": result_item.get("port", 443)
            }
            
            tls_counter["succeeded"] += 1
        else:
            # Failed result — extract structured failure code
            failure_code = result_item.get("failure_code", "UNKNOWN")
            error_reason = result_item.get("error", "Scan failed")
            tls_counter["failed"] += 1
            failed_hosts.append((hostname, failure_code, error_reason))
            continue

        # Continue processing: certificate, cipher, analysis
        cert_meta = {}
        try:
            if tls_res.get("der_cert"):
                cert_meta = parse_certificate(tls_res.get("der_cert"))
                if "error_category" in cert_meta:
                    cert_meta = {
                        "key_algorithm": "unknown",
                        "key_size": 0,
                        "signature_algorithm": "unknown",
                        "certificate_expiry": "",
                    }
        except Exception as e:
            cert_meta = {
                "key_algorithm": "unknown",
                "key_size": 0,
                "signature_algorithm": "unknown",
                "certificate_expiry": "",
            }
        
        cipher_info = {}
        classification = {}
        algo_risk = {}
        try:
            cipher_info = parse_cipher_suite(tls_res.get("cipher_suite", ""))
            classification = classify_family(cipher_info)
            algo_risk = estimate_quantum_risk(classification)
        except Exception as e:
            cipher_info = {"key_exchange": "unknown", "signature": "unknown", "encryption": "unknown", "hash": "unknown"}
            classification = {
                "key_exchange_family": "unknown",
                "signature_family": "unknown",
                "encryption_family": "unknown",
                "hash_family": "unknown",
            }
            algo_risk = {"quantum_risk_estimate": "unknown"}
        
        svc_type = "unknown"
        hndl_data = {}
        try:
            svc_type = classify_service(hostname, 443)
            hndl_data = detect_hndl_risk(hostname, 443, svc_type)
        except Exception as e:
            svc_type = "unknown"
            hndl_data = {"hndl_multiplier": 0.0, "risk_level": "unknown"}
        
        results_map[hostname] = (tls_res, cert_meta, cipher_info, classification, algo_risk, svc_type, hndl_data)
        
        # Log progress every 5 or at end
        completed = tls_counter["succeeded"] + tls_counter["failed"]
        if completed % 5 == 0 or completed == total_endpoints:
            log_progress(scan_id, f"[TLS ANALYSIS] Scanned {completed}/{total_endpoints} endpoints (✓ {tls_counter['succeeded']} | ✗ {tls_counter['failed']})")

    log_progress(scan_id, f"[TLS ANALYSIS ✓] Completed async concurrent analysis (✓ {tls_counter['succeeded']} succeeded | ✗ {tls_counter['failed']} failed)")

    # --- Step 6: Store per-hostname results ------------------------------
    storage_counter = {"completed": 0}
    log_progress(scan_id, f"[STORAGE] Storing results for {len(results_map)} successful subdomains...")
    
    for hostname, (tls_res, cert_meta, cipher_info, classification, algo_risk, svc_type, hndl_data) in results_map.items():
        try:
            live_port = tls_res.get("port", 443) if tls_res else 443
            store_tls_result(
                scan_id=scan_id,
                hostname=hostname,
                port=live_port,
                tls_version=tls_res.get("tls_version") if tls_res else None,
                cipher_suite=tls_res.get("cipher_suite") if tls_res else None,
                key_algorithm=cert_meta.get("key_algorithm") if cert_meta else None,
                key_size=cert_meta.get("key_size") if cert_meta else None,
                signature_algorithm=cert_meta.get("signature_algorithm") if cert_meta else None,
                certificate_expiry=cert_meta.get("certificate_expiry") if cert_meta else None,
            )
        except Exception as e:
            pass

        try:
            store_algorithm_analysis(
                scan_id=scan_id,
                hostname=hostname,
                cipher_suite=tls_res.get("cipher_suite") if tls_res else None,
                key_exchange=cipher_info.get("key_exchange", "unknown") if cipher_info else "unknown",
                signature=cipher_info.get("signature", "unknown") if cipher_info else "unknown",
                encryption=cipher_info.get("encryption", "unknown") if cipher_info else "unknown",
                hash_alg=cipher_info.get("hash", "unknown") if cipher_info else "unknown",
                classification=_json.dumps(classification) if classification else _json.dumps({}),
                quantum_risk_estimate=algo_risk.get("quantum_risk_estimate", "unknown") if algo_risk else "unknown",
            )
        except Exception as e:
            pass

        try:
            store_hndl_result(
                scan_id=scan_id,
                hostname=hostname,
                port=live_port,
                service_type=svc_type if svc_type else "unknown",
                hndl_multiplier=hndl_data.get("hndl_multiplier", 0.0) if hndl_data else 0.0,
                risk_level=hndl_data.get("risk_level", "unknown") if hndl_data else "unknown",
            )
        except Exception as e:
            pass
        
        storage_counter["completed"] += 1
        if storage_counter["completed"] % 25 == 0 or storage_counter["completed"] == len(results_map):
            log_progress(scan_id, f"[STORAGE] Stored {storage_counter['completed']}/{len(results_map)} domain results")
    
    log_progress(scan_id, f"[STORAGE ✓] All {len(results_map)} successful domains stored")
    
    # Store failure records with structured failure_code (FIX 7)
    for fail_hostname, failure_code, error_reason in failed_hosts:
        try:
            store_scan_failure(
                scan_id, fail_hostname, failure_code, error_reason,
                attempt_count=4, failure_code=failure_code
            )
        except Exception as e:
            log_progress(scan_id, f"Warning: Could not store failure record for {fail_hostname}: {e}")
    
    # Worker stats summary with failure code breakdown
    if failed_hosts:
        code_counts = Counter(code for _, code, _ in failed_hosts)
        log_progress(scan_id, f"[SUMMARY] ⚠ {len(failed_hosts)}/{tls_counter['succeeded'] + len(failed_hosts)} TLS scans failed:")
        for code, count in code_counts.most_common():
            # Map failure codes to user-friendly labels
            label_map = {
                "DNS_NO_RECORD": "Ghost — safe to ignore",
                "TCP_TIMEOUT": "Host unreachable",
                "TCP_REFUSED": "No HTTPS service",
                "TLS_HANDSHAKE_FAIL": "WAF/CDN blocking",
                "TLS_LEGACY_CIPHER": "Legacy server",
                "CERT_MISMATCH": "Cert mismatch",
            }
            label = label_map.get(code, code)
            log_progress(scan_id, f"         • {code}: {count} ({label})")
    
    log_progress(scan_id, f"[SUMMARY ✓] Scan complete! {total_discovered} discovered • {ghost_count if 'ghost_count' in dir() else 0} ghosts filtered • {tls_counter['succeeded']} TLS successful • {tls_counter['failed']} failed")

    # --- Step 7: Store a summary result row ------------------------------
    store_result(
        scan_id=scan_id,
        host=domain,
        port=443,
        service="HTTPS",
    )


def main() -> None:
    """Main worker loop."""
    # Ensure tables exist (in case the worker starts before the server).
    init_db()

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

            # Mark as running
            print("Updating job status -> running", flush=True)
            update_job_status(scan_id, "running")
            print(f"[worker] Job {scan_id} -> running", flush=True)

            try:
                run_scan(job)
                print("Updating job status -> completed", flush=True)
                update_job_status(scan_id, "completed")

                # Write scan cache entry (24h window)
                from datetime import datetime, timezone, timedelta
                now = datetime.now(timezone.utc)
                expires = now + timedelta(hours=24)
                cache_conn = get_connection()
                try:
                    cache_conn.execute(
                        "INSERT INTO scan_cache (domain, scan_id, created_at, expires_at) VALUES (?, ?, ?, ?);",
                        (domain, scan_id, now.isoformat(), expires.isoformat()),
                    )
                    cache_conn.commit()
                    print(f"[worker] Cache entry written for {domain} (expires {expires.isoformat()})", flush=True)
                finally:
                    cache_conn.close()

                update_schedule_after_scan_from_db(scan_id)
                print(f"[worker] Job {scan_id} -> completed\n", flush=True)

                # Resume paused jobs if this was a priority scan
                if job.get("priority", 0) == 1:
                    resumed = resume_paused_jobs()
                    if resumed:
                        print(f"[worker] Resumed {resumed} paused queued jobs", flush=True)
            except Exception as exc:
                print(f"Updating job status -> failed ({exc})", flush=True)
                update_job_status(scan_id, "failed")
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
    main()
