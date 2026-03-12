"""
Scan Worker -- Background process that picks up queued scan jobs,
runs domain discovery, stores results, and marks jobs as completed.

Run with:
    python workers/scan_worker.py
"""

import time
import sys
import os

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


def run_scan(job: dict) -> None:
    """
    Run the domain discovery pipeline and store results.
    """
    scan_id = job["id"]
    domain = job["target_domain"]

    # --- Step 1: Discover assets -----------------------------------------
    print(f"  [scan] Starting discovery for {domain}...")
    assets = discover_assets(domain)
    print(f"  [scan] Discovered {len(assets)} assets")

    # --- Step 2: Store each asset ----------------------------------------
    for hostname in assets:
        ip = resolve_ip(hostname)
        method = "root" if hostname == domain else "discovery"
        store_asset(scan_id, hostname, ip, method)

    # --- Step 3: Run TLS scans on all discovered assets ------------------
    for hostname in assets:
        print(f"  [scan] Running TLS scan for {hostname}...")
        tls_res = scan_tls(hostname)
        if tls_res:
            cert_meta = parse_certificate(tls_res["der_cert"])
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

            # --- Step 4: Algorithm Intelligence Analysis ---------------
            print(f"  [scan] Running Algorithm Intelligence for {hostname}...")
            cipher_info = parse_cipher_suite(tls_res.get("cipher_suite", ""))
            classification = classify_family(cipher_info)
            algo_risk = estimate_quantum_risk(classification)
            import json as _json
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

            # --- Step 5: HNDL Detection --------------------------------
            print(f"  [scan] Running HNDL detection for {hostname}...")
            svc_type = classify_service(hostname, 443)
            hndl_data = detect_hndl_risk(hostname, 443, svc_type)
            store_hndl_result(
                scan_id=scan_id,
                hostname=hostname,
                port=443,
                service_type=hndl_data["service_type"],
                hndl_multiplier=hndl_data["hndl_multiplier"],
                risk_level=hndl_data["risk_level"],
            )

        else:
            print(f"  [scan] TLS scan failed for {hostname}")

    # --- Step 7: Store a summary result row ------------------------------
    store_result(
        scan_id=scan_id,
        host=domain,
        port=443,
        service="HTTPS",
    )
    print(f"  [scan] Results stored for job {scan_id}")


def main() -> None:
    """Main worker loop."""
    # Ensure tables exist (in case the worker starts before the server).
    init_db()

    # Seed crypto registry and run initial threat feed update
    print("[worker] Seeding crypto registry...")
    feed_result = run_feed_update()
    print(f"[worker] Registry: {feed_result['seeded']} seeded, {feed_result['updated']} from feed")

    print("=" * 60)
    print("  Quantum Crypto Intelligence -- Scan Worker")
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
