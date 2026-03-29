"""
Scan Worker -- Background process that picks up queued scan jobs,
runs domain discovery, stores results, and marks jobs as completed.

Run with:
    python workers/scan_worker.py
"""

import time
import sys
import os
import concurrent.futures
import json as _json

# Add workers, backend, scanner, analysis, and intelligence directories to path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intelligence"))

from job_fetcher import get_next_job, update_job_status
from result_manager import store_result, store_tls_result, store_hndl_result, store_algorithm_analysis
from database import init_db, get_connection
from domain_discovery import discover_assets, store_asset, resolve_ip
from tls_scanner import scan_tls
from certificate_parser import parse_certificate
from cipher_parser import parse_cipher_suite
from algorithm_classifier import classify_family
from quantum_estimator import estimate_quantum_risk
from service_classifier import classify_service
from hndl_detector import detect_hndl_risk
from registry_updater import lookup_from_db, seed_registry as seed_crypto_registry
from threat_feed import run_feed_update

POLL_INTERVAL = 3   # seconds to wait when no jobs are available

def log_progress(scan_id: int, message: str) -> None:
    print(f"  [scan] {message}")
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
    log_progress(scan_id, f"Starting discovery for {domain}...")
    assets = discover_assets(domain)
    log_progress(scan_id, f"Discovered {len(assets)} unique subdomains.")

    # --- Step 2: Resolve IPs concurrently and store ----------------------
    ip_to_hostnames = {}
    
    def resolve_and_store(hostname):
        ip = resolve_ip(hostname)
        method = "root" if hostname == domain else "discovery"
        store_asset(scan_id, hostname, ip, method)
        return hostname, ip

    log_progress(scan_id, "Resolving IP clusters concurrently...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(resolve_and_store, host): host for host in assets}
        for future in concurrent.futures.as_completed(futures):
            hostname, ip = future.result()
            # Group by IP to avoid redundant TLS scans
            if ip:
                ip_to_hostnames.setdefault(ip, []).append(hostname)
            else:
                ip_to_hostnames.setdefault(f"no_ip_{hostname}", []).append(hostname)

    unique_hostnames = [hosts[0] for ip, hosts in ip_to_hostnames.items()]
    log_progress(scan_id, f"Grouped assets into {len(unique_hostnames)} optimized endpoints based on redundant IPs.")

    # --- Step 3, 4, 5: Run TLS and Intelligence scans concurrently -------
    def process_hostname(representative_hostname):
        log_progress(scan_id, f"Running deep TLS Analysis & Quantum Risk scan for {representative_hostname}...")
        tls_res = scan_tls(representative_hostname)
        if not tls_res:
            log_progress(scan_id, f"TLS scan failed for {representative_hostname}")
            return representative_hostname, None, None, None, None, None, None, None
            
        cert_meta = parse_certificate(tls_res["der_cert"])
        
        cipher_info = parse_cipher_suite(tls_res.get("cipher_suite", ""))
        classification = classify_family(cipher_info)
        algo_risk = estimate_quantum_risk(classification)
        
        svc_type = classify_service(representative_hostname, 443)
        hndl_data = detect_hndl_risk(representative_hostname, 443, svc_type)
        
        return representative_hostname, tls_res, cert_meta, cipher_info, classification, algo_risk, svc_type, hndl_data

    results_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_hostname, host): host for host in unique_hostnames}
        for future in concurrent.futures.as_completed(futures):
            rep_host, tls_res, cert_meta, cipher_info, classification, algo_risk, svc_type, hndl_data = future.result()
            if tls_res:
                results_map[rep_host] = (tls_res, cert_meta, cipher_info, classification, algo_risk, svc_type, hndl_data)

    # --- Step 6: Store results for ALL assets based on their IP group ----
    log_progress(scan_id, "Applying classified intelligence engine results back to identical CDN host paths...")
    for ip, hosts in ip_to_hostnames.items():
        rep_host = hosts[0]
        if rep_host in results_map:
            tls_res, cert_meta, cipher_info, classification, algo_risk, svc_type, hndl_data = results_map[rep_host]
            
            # Apply results to all hostnames sharing this IP
            for hostname in hosts:
                store_tls_result(
                    scan_id=scan_id,
                    hostname=hostname,
                    port=443,
                    tls_version=tls_res["tls_version"],
                    cipher_suite=tls_res["cipher_suite"],
                    key_algorithm=cert_meta.get("key_algorithm"),
                    key_size=cert_meta.get("key_size"),
                    signature_algorithm=cert_meta.get("signature_algorithm"),
                    certificate_expiry=cert_meta.get("certificate_expiry"),
                )

                store_algorithm_analysis(
                    scan_id=scan_id,
                    hostname=hostname,
                    cipher_suite=tls_res.get("cipher_suite"),
                    key_exchange=cipher_info["key_exchange"],
                    signature=cipher_info["signature"],
                    encryption=cipher_info["encryption"],
                    hash_alg=cipher_info["hash"],
                    classification=_json.dumps(classification),
                    quantum_risk_estimate=algo_risk["quantum_risk_estimate"],
                )

                store_hndl_result(
                    scan_id=scan_id,
                    hostname=hostname,
                    port=443,
                    service_type=svc_type,
                    hndl_multiplier=hndl_data["hndl_multiplier"],
                    risk_level=hndl_data["risk_level"],
                )

    # --- Step 7: Store a summary result row ------------------------------
    store_result(
        scan_id=scan_id,
        host=domain,
        port=443,
        service="HTTPS",
    )
    log_progress(scan_id, f"Results strictly finalized and stored safely.")


def main() -> None:
    """Main worker loop."""
    # Ensure tables exist (in case the worker starts before the server).
    init_db()

    # Seed crypto registry and run initial threat feed update
    print("[worker] Seeding crypto registry...")
    feed_result = run_feed_update()
    print(f"[worker] Registry: {feed_result['seeded']} seeded, {feed_result['updated']} from feed")

    print("=" * 60)
    print("  Quantum Proof System Scanner -- Scan Worker")
    print("=" * 60)
    print("Worker started")
    print("  Waiting for jobs...\n")

    while True:
        print("Checking for queued jobs...")
        job = get_next_job()

        if job is not None:
            scan_id = job["id"]
            domain = job["target_domain"]

            print(f"Job found: {job}")
            print(f"[worker] Picked up job {scan_id} -> {domain}")

            # Mark as running
            print("Updating job status -> running")
            update_job_status(scan_id, "running")
            print(f"[worker] Job {scan_id} -> running")

            try:
                run_scan(job)
                print("Updating job status -> completed")
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
                    print(f"[worker] Cache entry written for {domain} (expires {expires.isoformat()})")
                finally:
                    cache_conn.close()

                print(f"[worker] Job {scan_id} -> completed\n")
            except Exception as exc:
                print(f"Updating job status -> failed ({exc})")
                update_job_status(scan_id, "failed")
                print(f"[worker] Job {scan_id} -> failed: {exc}\n")
        else:
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
