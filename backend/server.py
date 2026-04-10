"""
Quantum Proof System Scanner — FastAPI Server
======================================================
Entry-point for the application.  Run with:

    python backend/server.py
"""

import os
import sys

# Ensure the backend package is on the path when running as a script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Header, UploadFile, File, Depends, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
from datetime import datetime, timezone
from upload_parser import parse_upload_for_urls
from dotenv import load_dotenv

ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(dotenv_path=ENV_PATH) # Load environments absolutely

from database import init_db, get_connection
from models import (
    ScanRequest, ScanResponse, ScanStatusResponse, AssetsResponse,
    TlsResultsResponse, TlsResultItem,
    QuantumRiskResponse, QuantumRiskResultItem,
    HndlResponse, HndlResultItem,
    AlgorithmAnalysisResponse, AlgorithmAnalysisItem,
    AssetDetailsResponse, AssetScoreBreakdown,
    ScanFailuresResponse, ScanFailureItem,
    DomainScanHistoryResponse, DomainScanHistoryItem, DomainsListResponse
)
from domain_parser import parse_domain
from job_manager import create_scan_job

# Intelligence modules
INTELLIGENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intelligence")
sys.path.insert(0, INTELLIGENCE_DIR)
from registry_updater import seed_registry, get_all_registry_entries

# Auth modules
AUTH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "auth")
sys.path.insert(0, AUTH_DIR)
from auth_routes import router as auth_router, get_current_user

# Analysis modules
ANALYSIS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis")
sys.path.insert(0, ANALYSIS_DIR)
from quantum_risk_engine import calculate_quantum_risk

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialize the database and seed crypto registry on startup."""
    init_db()
    seeded = seed_registry()
    if seeded:
        print(f"[startup] Seeded {seeded} algorithms into crypto_registry")
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Quantum Proof System Scanner",
    version="0.2.0",
    description="Analyze websites for quantum cryptographic risk and HNDL exposure.",
    lifespan=lifespan,
)

# Mount static JS components folder
components_dir = os.path.join(FRONTEND_DIR, "components")
os.makedirs(components_dir, exist_ok=True)
app.mount("/components", StaticFiles(directory=components_dir), name="components")

# Mount static CSS folder
css_dir = os.path.join(FRONTEND_DIR, "css")
os.makedirs(css_dir, exist_ok=True)
app.mount("/css", StaticFiles(directory=css_dir), name="css")

# Mount static JS scripts folder
js_dir = os.path.join(FRONTEND_DIR, "js")
os.makedirs(js_dir, exist_ok=True)
app.mount("/js", StaticFiles(directory=js_dir), name="js")

# Include auth router
app.include_router(auth_router)


# ---------------------------------------------------------------------------
# Frontend Page Routes
# ---------------------------------------------------------------------------
def no_cache_file(path: str):
    return FileResponse(path, headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    })

@app.get("/")
async def root():
    return no_cache_file(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/login")
async def login_page():
    return no_cache_file(os.path.join(FRONTEND_DIR, "login.html"))


@app.get("/scanner")
async def old_scanner_page():
    return RedirectResponse(url="/")


@app.get("/dashboard")
async def default_dashboard_page():
    return no_cache_file(os.path.join(FRONTEND_DIR, "dashboard.html"))


@app.get("/dashboard/{scan_id}")
async def dashboard_pagelet(scan_id: str):
    return no_cache_file(os.path.join(FRONTEND_DIR, "dashboard.html"))


@app.get("/user-dashboard")
async def user_dashboard_page():
    return no_cache_file(os.path.join(FRONTEND_DIR, "user_dashboard.html"))


@app.get("/scan-progress/{scan_id}")
async def scan_progress_page(scan_id: str):
    return no_cache_file(os.path.join(FRONTEND_DIR, "scan_progress.html"))

@app.get("/schedules")
async def schedules_page():
    return no_cache_file(os.path.join(FRONTEND_DIR, "schedules.html"))

@app.get("/api/config/agent-key")
async def get_agent_key(current_user: dict = Depends(get_current_user)):
    return {"key": os.environ.get("GEMINI_API_KEY", "")}


@app.post("/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    authorization: str = Header(None),
):
    """
    Submit a domain or URL for scanning.

    Always creates a new scan job (no caching).
    Every scan is timestamped and tracked for historical analysis.
    Optionally links the scan to a user if Authorization header is provided.
    """
    try:
        domain_info = parse_domain(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    domain = domain_info.host

    # Identify user (optional)
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        from jwt_handler import verify_token
        payload = verify_token(authorization.replace("Bearer ", ""))
        if payload:
            user_id = payload["sub"]

    # Always create a new scan (no caching)
    scan_id = create_scan_job(domain, domain_info.parent_domain)
    print(f"[scan] New scan job created: {scan_id} for domain {domain}")

    # Link new scan to user
    if user_id:
        _link_scan_to_user(user_id, scan_id, domain, "queued")

    return ScanResponse(scan_id=scan_id, status="queued")


def _link_scan_to_user(user_id: int, scan_id: int, domain: str, status: str):
    """Insert a user_scans record linking a scan to a user."""
    conn = get_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO user_scans (user_id, scan_id, domain, status, created_at) VALUES (?, ?, ?, ?, ?);",
            (user_id, scan_id, domain, status, now),
        )
        conn.commit()
    finally:
        conn.close()





@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: int):
    """
    Poll the current status of a scan job.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, target_domain, status FROM scans WHERE id = ?;",
            (scan_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=row["id"],
        domain=row["target_domain"],
        status=row["status"],
    )


@app.get("/domains", response_model=DomainsListResponse)
async def list_scanned_domains():
    """
    Return a list of all uniquely scanned domains.
    """
    conn = get_connection()
    try:
        # Get unique target domains from all scans
        rows = conn.execute(
            """
            SELECT DISTINCT target_domain 
            FROM scans 
            ORDER BY target_domain;
            """
        ).fetchall()
    finally:
        conn.close()

    domains = [row["target_domain"] for row in rows]
    return DomainsListResponse(total_domains=len(domains), domains=domains)


@app.get("/domain/{domain}/scans", response_model=DomainScanHistoryResponse)
async def get_domain_scan_history(domain: str):
    """
    Return all historical scans for a specific domain in chronological order.
    Includes summary stats for each scan (TLS count, failure count).
    """
    conn = get_connection()
    try:
        # Get all scans for this domain
        scan_rows = conn.execute(
            """
            SELECT id, target_domain, status, created_at 
            FROM scans 
            WHERE target_domain = ? 
            ORDER BY created_at DESC;
            """,
            (domain,),
        ).fetchall()
    finally:
        conn.close()

    if not scan_rows:
        raise HTTPException(status_code=404, detail=f"No scans found for domain {domain}")

    scans = []
    for scan_row in scan_rows:
        scan_id = scan_row["id"]
        
        # Count TLS results
        conn = get_connection()
        try:
            tls_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM tls_results WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()["cnt"]
            
            failure_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM scan_failures WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()["cnt"]
        finally:
            conn.close()
        
        scans.append(DomainScanHistoryItem(
            scan_id=scan_id,
            domain=scan_row["target_domain"],
            status=scan_row["status"],
            tls_count=tls_count,
            failure_count=failure_count,
            created_at=scan_row["created_at"],
        ))

    return DomainScanHistoryResponse(
        domain=domain,
        total_scans=len(scans),
        scans=scans,
    )


@app.get("/scan/{scan_id}/assets", response_model=AssetsResponse)
async def get_scan_assets(scan_id: int):
    """
    Return all discovered assets for a scan.
    """
    conn = get_connection()
    try:
        # Verify scan exists
        scan = conn.execute(
            "SELECT id FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        rows = conn.execute(
            "SELECT hostname FROM discovered_assets WHERE scan_id = ? ORDER BY hostname;",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    return AssetsResponse(
        scan_id=scan_id,
        assets=[row["hostname"] for row in rows],
    )


@app.get("/scan/{scan_id}/tls", response_model=TlsResultsResponse)
async def get_scan_tls(scan_id: int, exclude_failed: bool = Query(False, description="Exclude TLS scans with no cipher suite (failed scans)")):
    """
    Return all TLS scan results for a given scan.
    
    Parameters:
    - exclude_failed: If True, filters out subdomains where TLS handshake failed (tls_version is NULL)
    """
    conn = get_connection()
    try:
        # Verify scan exists
        scan = conn.execute(
            "SELECT id FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Build query based on exclude_failed flag
        if exclude_failed:
            query = """
            SELECT id, hostname, port, tls_version, cipher_suite,
                   key_algorithm, key_size, signature_algorithm, certificate_expiry
            FROM tls_results
            WHERE scan_id = ? AND tls_version IS NOT NULL AND tls_version != ''
            ORDER BY hostname;
            """
        else:
            query = """
            SELECT id, hostname, port, tls_version, cipher_suite,
                   key_algorithm, key_size, signature_algorithm, certificate_expiry
            FROM tls_results
            WHERE scan_id = ?
            ORDER BY hostname;
            """
        
        rows = conn.execute(query, (scan_id,)).fetchall()
    finally:
        conn.close()

    results = []
    for row in rows:
        results.append(TlsResultItem(
            id=row["id"],
            hostname=row["hostname"],
            port=row["port"],
            tls_version=row["tls_version"],
            cipher_suite=row["cipher_suite"],
            key_algorithm=row["key_algorithm"],
            key_size=row["key_size"],
            signature_algorithm=row["signature_algorithm"],
            certificate_expiry=row["certificate_expiry"],
        ))

    return TlsResultsResponse(scan_id=scan_id, results=results)


@app.get("/scan/{scan_id}/quantum-risk", response_model=QuantumRiskResponse)
async def get_scan_quantum_risk(scan_id: int):
    """
    Return dynamically calculated quantum risk assessment scores for all scanned assets.
    """
    conn = get_connection()
    try:
        # Verify scan exists
        scan = conn.execute(
            "SELECT id FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        tls_rows = conn.execute(
            """SELECT hostname, port, tls_version, cipher_suite, 
                      key_algorithm, signature_algorithm, key_size, certificate_expiry 
               FROM tls_results WHERE scan_id = ? ORDER BY hostname;""",
            (scan_id,)
        ).fetchall()

        hndl_rows = conn.execute(
            "SELECT hostname, risk_level FROM hndl_results WHERE scan_id = ?;",
            (scan_id,)
        ).fetchall()
        hndl_map = {row["hostname"]: row["risk_level"] for row in hndl_rows}

    finally:
        conn.close()

    results = []
    for tls in tls_rows:
        hostname = tls["hostname"]
        hndl_level = hndl_map.get(hostname, "")

        tls_result_dict = {
            "tls_version": tls["tls_version"],
            "cipher_suite": tls["cipher_suite"]
        }
        cert_meta_dict = {
            "key_algorithm": tls["key_algorithm"],
            "key_size": tls["key_size"],
            "signature_algorithm": tls["signature_algorithm"],
            "certificate_expiry": tls["certificate_expiry"]
        }

        qr_res = calculate_quantum_risk(tls_result_dict, cert_meta_dict, hndl_level)
        b = qr_res["breakdown"]
        
        results.append(QuantumRiskResultItem(
            hostname=hostname,
            port=tls["port"],
            risk_score=qr_res["total_score"],
            risk_label=qr_res["risk_label"],
            key_exchange_score=b["key_exchange"],
            signature_score=b["signature"],
            tls_score=b["tls_version"],
            key_size_penalty=b["key_size"],
            certificate_validity_score=b["certificate"],
            cipher_score=b["cipher"]
        ))

    return QuantumRiskResponse(scan_id=scan_id, results=results)


@app.get("/scan/{scan_id}/hndl", response_model=HndlResponse)
async def get_scan_hndl(scan_id: int):
    """
    Return HNDL (Harvest Now, Decrypt Later) detection results.
    """
    conn = get_connection()
    try:
        # Verify scan exists
        scan = conn.execute(
            "SELECT id FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        rows = conn.execute(
            """
            SELECT hostname, port, service_type, hndl_multiplier, risk_level
            FROM hndl_results
            WHERE scan_id = ?
            ORDER BY hndl_multiplier DESC;
            """,
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    targets = [
        HndlResultItem(
            hostname=row["hostname"],
            port=row["port"],
            service=row["service_type"],
            multiplier=row["hndl_multiplier"],
            risk=row["risk_level"],
        )
        for row in rows
    ]

    return HndlResponse(scan_id=scan_id, targets=targets)


@app.get("/scan/{scan_id}/algorithm-analysis", response_model=AlgorithmAnalysisResponse)
async def get_algorithm_analysis(scan_id: int):
    """
    Return algorithm intelligence analysis for all scanned assets.
    """
    conn = get_connection()
    try:
        scan = conn.execute(
            "SELECT id FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        rows = conn.execute(
            """
            SELECT hostname, cipher_suite, key_exchange, signature,
                   encryption, hash, classification, quantum_risk_estimate
            FROM algorithm_analysis
            WHERE scan_id = ?
            ORDER BY quantum_risk_estimate DESC;
            """,
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    results = []
    for row in rows:
        try:
            # Convert quantum_risk_estimate to int, defaulting to 0 if it's a string like "unknown"
            qr_estimate = row["quantum_risk_estimate"]
            if isinstance(qr_estimate, str):
                try:
                    qr_estimate = int(qr_estimate)
                except (ValueError, TypeError):
                    qr_estimate = 0
            
            item = AlgorithmAnalysisItem(
                hostname=row["hostname"],
                cipher_suite=row["cipher_suite"],
                key_exchange=row["key_exchange"],
                signature=row["signature"],
                encryption=row["encryption"],
                hash=row["hash"],
                classification=row["classification"],
                quantum_risk_estimate=qr_estimate,
            )
            results.append(item)
        except Exception as e:
            print(f"Error processing row {row['hostname']}: {e}")
            raise

    return AlgorithmAnalysisResponse(scan_id=scan_id, results=results)


@app.get("/scan/{scan_id}/failures", response_model=ScanFailuresResponse)
async def get_scan_failures(scan_id: int):
    """
    Return all domains that failed to scan with detailed failure reasons.
    Includes failure category and reason for easy triage and debugging.
    """
    conn = get_connection()
    try:
        # Verify scan exists
        scan = conn.execute(
            "SELECT id FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        rows = conn.execute(
            """
            SELECT id, hostname, failure_category, failure_reason, attempt_count, created_at
            FROM scan_failures
            WHERE scan_id = ?
            ORDER BY created_at DESC;
            """,
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    failures = [
        ScanFailureItem(
            id=row["id"],
            hostname=row["hostname"],
            failure_category=row["failure_category"],
            failure_reason=row["failure_reason"],
            attempt_count=row["attempt_count"],
            created_at=row["created_at"],
        )
        for row in rows
    ]

    return ScanFailuresResponse(scan_id=scan_id, total_failures=len(failures), failures=failures)


@app.get("/asset/{asset_id}", response_model=AssetDetailsResponse)
async def get_asset_details(asset_id: int):
    """
    Return a dynamically generated detailed drill-down for a specific asset.
    """
    conn = get_connection()
    try:
        # Get TLS info
        tls = conn.execute(
            """SELECT id, scan_id, hostname, port, tls_version, cipher_suite, 
                      key_algorithm, signature_algorithm, key_size, certificate_expiry 
               FROM tls_results WHERE id = ?;""",
            (asset_id,)
        ).fetchone()
        
        if not tls:
            raise HTTPException(status_code=404, detail="Asset not found")

        # Get HNDL info
        hndl = conn.execute(
            "SELECT risk_level FROM hndl_results WHERE scan_id = ? AND hostname = ?;",
            (tls["scan_id"], tls["hostname"])
        ).fetchone()

    finally:
        conn.close()

    tls_result_dict = {
        "tls_version": tls["tls_version"],
        "cipher_suite": tls["cipher_suite"]
    }
    cert_meta_dict = {
        "key_algorithm": tls["key_algorithm"],
        "key_size": tls["key_size"],
        "signature_algorithm": tls["signature_algorithm"],
        "certificate_expiry": tls["certificate_expiry"]
    }
    hndl_level = hndl["risk_level"] if hndl else "Unknown"
    
    qr_res = calculate_quantum_risk(tls_result_dict, cert_meta_dict, hndl_level)
    b = qr_res["breakdown"]

    score = qr_res["total_score"]
    breakdown = AssetScoreBreakdown(
        key_exchange=b["key_exchange"],
        signature=b["signature"],
        tls=b["tls_version"],
        key_size=b["key_size"],
        certificate=b["certificate"],
        cipher=b["cipher"],
    )

    return AssetDetailsResponse(
        asset_id=tls["id"],
        host=tls["hostname"],
        port=tls["port"],
        tls_version=tls["tls_version"],
        cipher_suite=tls["cipher_suite"],
        score=score,
        score_breakdown=breakdown,
        key_exchange_algorithm=tls["key_algorithm"],
        signature_algorithm=tls["signature_algorithm"],
        key_size=tls["key_size"],
        certificate_expiry=tls["certificate_expiry"],
        hndl_level=hndl["risk_level"] if hndl else "Unknown",
        pqc_recommendations=["ML-KEM", "ML-DSA", "SLH-DSA"]
    )



@app.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: int):
    """
    Aggregate all scan data into a single JSON report for export.
    """
    conn = get_connection()
    try:
        scan = conn.execute(
            "SELECT id, target_domain, status, created_at FROM scans WHERE id = ?;",
            (scan_id,),
        ).fetchone()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        assets = conn.execute(
            "SELECT hostname, ip_address, discovery_method FROM discovered_assets WHERE scan_id = ?;",
            (scan_id,),
        ).fetchall()

        tls = conn.execute(
            """SELECT hostname, port, tls_version, cipher_suite,
                      key_algorithm, key_size, signature_algorithm, certificate_expiry
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
    finally:
        conn.close()

    hndl_map = {row["hostname"]: row["risk_level"] for row in hndl}
    qr_list = []
    for t in tls:
        hostname = t["hostname"]
        tls_dict = {"tls_version": t["tls_version"], "cipher_suite": t["cipher_suite"]}
        cert_dict = {
            "key_algorithm": t["key_algorithm"],
            "key_size": t["key_size"],
            "signature_algorithm": t["signature_algorithm"],
            "certificate_expiry": t["certificate_expiry"]
        }
        h_level = hndl_map.get(hostname, "")
        risk_res = calculate_quantum_risk(tls_dict, cert_dict, h_level)
        b = risk_res["breakdown"]
        qr_list.append({
            "hostname": hostname,
            "port": t["port"],
            "risk_score": risk_res["total_score"],
            "risk_label": risk_res["risk_label"],
            "key_exchange_score": b["key_exchange"],
            "signature_score": b["signature"],
            "tls_score": b["tls_version"],
            "key_size_penalty": b["key_size"],
            "certificate_validity_score": b["certificate"],
            "cipher_score": b["cipher"]
        })

    return JSONResponse({
        "scan_id": scan["id"],
        "domain": scan["target_domain"],
        "status": scan["status"],
        "created_at": scan["created_at"],
        "assets": [dict(r) for r in assets],
        "tls_results": [dict(r) for r in tls],
        "quantum_risk": qr_list,
        "hndl_results": [dict(r) for r in hndl],
        "algorithm_analysis": [dict(r) for r in algo],
    })

@app.post("/scan/upload")
async def handle_document_upload(file: UploadFile = File(...)):
    """Accepts an image or PDF containing a QR/Barcode, decodes it, and returns the target URL."""
    contents = await file.read()
    urls = parse_upload_for_urls(file.filename, contents)
    if not urls:
        raise HTTPException(status_code=400, detail="No QR/Barcode found in document.")
    return JSONResponse({"url": urls[0]})

@app.get("/scan/{scan_id}/logs")
async def get_scan_logs(scan_id: int):
    """Retrieve the real-time execution logs for a specific scan job."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT message, created_at FROM scan_logs WHERE scan_id = ? ORDER BY id ASC;",
            (scan_id,),
        ).fetchall()
        return [{"message": r["message"], "created_at": r["created_at"]} for r in rows]
    finally:
        conn.close()

@app.get("/intelligence/registry")
async def get_intelligence_registry():
    """
    Return all known cryptographic algorithms from the threat intelligence registry.
    """
    entries = get_all_registry_entries()
    algorithms = [
        {
            "name": e["algorithm_name"],
            "family": e["algorithm_family"],
            "quantum_safe": bool(e["quantum_safe"]),
            "risk": e["risk_level"],
        }
        for e in entries
    ]
    return JSONResponse({"algorithms": algorithms})


@app.get("/cache/status/{domain}")
async def get_cache_status(domain: str):
    """
    Check if a domain has a valid cache entry.
    """
    from datetime import datetime, timezone
    conn = get_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        row = conn.execute(
            "SELECT scan_id, expires_at FROM scan_cache WHERE domain = ? AND expires_at > ? ORDER BY id DESC LIMIT 1;",
            (domain, now),
        ).fetchone()

        # Cleanup expired entries while we're here
        conn.execute("DELETE FROM scan_cache WHERE expires_at <= ?;", (now,))
        conn.commit()
    finally:
        conn.close()

    if row:
        return JSONResponse({
            "domain": domain,
            "cached": True,
            "scan_id": row["scan_id"],
            "expires_at": row["expires_at"],
        })
    return JSONResponse({
        "domain": domain,
        "cached": False,
        "scan_id": None,
        "expires_at": None,
    })


@app.get("/user/scans")
async def get_user_scans(authorization: str = Header(None)):
    """
    Return all scans linked to the authenticated user, dynamically calculating risk scores.
    """
    user = get_current_user(authorization)
    user_id = user["sub"]

    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT us.scan_id, us.domain, us.status, us.monitored, us.note, us.created_at,
                   s.status as scan_status
            FROM user_scans us
            LEFT JOIN scans s ON s.id = us.scan_id
            WHERE us.user_id = ?
            ORDER BY us.created_at DESC;
            """,
            (user_id,),
        ).fetchall()

        scans_out = []
        for r in rows:
            sid = r["scan_id"]
            scan_obj = {
                "scan_id": sid,
                "domain": r["domain"],
                "status": r["scan_status"] or r["status"],
                "monitored": bool(r["monitored"]),
                "note": r["note"] or "",
                "created_at": r["created_at"],
                "risk_score": 0
            }

            if scan_obj["status"] != "completed":
                scans_out.append(scan_obj)
                continue

            # Dynamically calculate the score for this scan across all its assets
            tls_rows = conn.execute(
                """SELECT hostname, tls_version, cipher_suite, 
                          key_algorithm, signature_algorithm, key_size, certificate_expiry 
                   FROM tls_results WHERE scan_id = ?;""",
                (sid,)
            ).fetchall()

            hndl_rows = conn.execute(
                "SELECT hostname, risk_level FROM hndl_results WHERE scan_id = ?;",
                (sid,)
            ).fetchall()
            hndl_map = {row["hostname"]: row["risk_level"] for row in hndl_rows}

            total_score = 0
            asset_count = 0

            for tls in tls_rows:
                hndl_level = hndl_map.get(tls["hostname"], "")
                tls_dict = {"tls_version": tls["tls_version"], "cipher_suite": tls["cipher_suite"]}
                cert_dict = {
                    "key_algorithm": tls["key_algorithm"], "key_size": tls["key_size"],
                    "signature_algorithm": tls["signature_algorithm"], "certificate_expiry": tls["certificate_expiry"]
                }
                
                qr_res = calculate_quantum_risk(tls_dict, cert_dict, hndl_level)
                total_score += qr_res["total_score"]
                asset_count += 1
            
            scan_obj["risk_score"] = round(total_score / asset_count) if asset_count > 0 else 0
            scans_out.append(scan_obj)

    finally:
        conn.close()

    return JSONResponse({"scans": scans_out})


@app.post("/monitor/domain")
async def toggle_monitor_domain(
    authorization: str = Header(None),
    domain: str = "",
    monitored: bool = True,
):
    """Toggle monitoring for a domain."""
    user = get_current_user(authorization)
    user_id = user["sub"]

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE user_scans SET monitored = ? WHERE user_id = ? AND domain = ?;",
            (1 if monitored else 0, user_id, domain),
        )
        conn.commit()
        updated = conn.execute(
            "SELECT COUNT(*) as cnt FROM user_scans WHERE user_id = ? AND domain = ? AND monitored = 1;",
            (user_id, domain),
        ).fetchone()
    finally:
        conn.close()

    return JSONResponse({
        "domain": domain,
        "monitored": bool(updated["cnt"]),
    })

class NoteUpdate(BaseModel):
    note: str

@app.post("/scan/{scan_id}/note")
async def update_scan_note(
    scan_id: int,
    request: NoteUpdate,
    authorization: str = Header(None)
):
    """Update a custom note for a specific scan."""
    user = get_current_user(authorization)
    user_id = user["sub"]

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE user_scans SET note = ? WHERE user_id = ? AND scan_id = ?;",
            (request.note, user_id, scan_id),
        )
        conn.commit()
    finally:
        conn.close()

    return JSONResponse({"status": "success"})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, authorization: str = Header(None)):
    """Delete a scan permanently."""
    user = get_current_user(authorization)
    user_id = user["sub"]

    conn = get_connection()
    try:
        scan = conn.execute(
            "SELECT id FROM user_scans WHERE scan_id = ? AND user_id = ?;",
            (scan_id, user_id),
        ).fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found or not owned by user")

        conn.execute("DELETE FROM algorithm_analysis WHERE scan_id = ?;", (scan_id,))
        conn.execute("DELETE FROM hndl_results WHERE scan_id = ?;", (scan_id,))
        conn.execute("DELETE FROM tls_results WHERE scan_id = ?;", (scan_id,))
        conn.execute("DELETE FROM discovered_assets WHERE scan_id = ?;", (scan_id,))
        conn.execute("DELETE FROM scan_results WHERE scan_id = ?;", (scan_id,))
        conn.execute("DELETE FROM user_scans WHERE scan_id = ?;", (scan_id,))
        conn.execute("DELETE FROM scan_cache WHERE scan_id = ?;", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))
        conn.commit()
    finally:
        conn.close()

    return JSONResponse({"status": "deleted", "scan_id": scan_id})

# ---------------------------------------------------------------------------
# Scheduling System Routes
# ---------------------------------------------------------------------------

from datetime import timedelta
from typing import Optional

def calculate_next_run(frequency: str, custom_hours: Optional[int] = None) -> datetime:
    now = datetime.now(timezone.utc)
    if frequency == 'daily':
        return now + timedelta(days=1)
    elif frequency == 'weekly':
        return now + timedelta(weeks=1)
    elif frequency == 'monthly':
        return now + timedelta(days=30)
    elif frequency == 'custom' and custom_hours:
        return now + timedelta(hours=custom_hours)
    return now + timedelta(days=1)

class ScheduleCreate(BaseModel):
    domain: str
    frequency: str
    custom_interval_hours: Optional[int] = None
    notify_on_change: bool = False
    start_immediately: bool = False

class ScheduleUpdate(BaseModel):
    frequency: str
    notify_on_change: bool = False
    custom_interval_hours: Optional[int] = None

@app.post("/api/schedules/create")
async def create_schedule(request: ScheduleCreate, authorization: str = Header(None)):
    user = get_current_user(authorization)
    user_id = user["sub"]
    
    try:
        domain_info = parse_domain(request.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
        
    domain = domain_info.host
    now = datetime.now(timezone.utc).isoformat()
    next_run = calculate_next_run(request.frequency, request.custom_interval_hours).isoformat()
    
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO scheduled_scans (domain, frequency, custom_interval_hours, created_by, created_at, next_run_at, notify_on_change)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (domain, request.frequency, request.custom_interval_hours, user_id, now, next_run, 1 if request.notify_on_change else 0)
        )
        schedule_id = cursor.lastrowid
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail="Schedule already exists or invalid parameters.")
    finally:
        conn.close()
        
    if request.start_immediately:
        try:
            # Reusing the run-now logic
            await run_schedule_now(schedule_id, authorization)
        except Exception:
            pass # Failing immediate trigger should not fail creation
            print(f"Failed to start scheduled scan immediately for {domain}")
            
    return {"schedule_id": schedule_id, "domain": domain, "frequency": request.frequency, "next_run_at": next_run, "message": "Schedule created successfully"}

@app.get("/api/schedules/list")
async def list_schedules(authorization: str = Header(None)):
    user = get_current_user(authorization)
    user_id = user["sub"]
    
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, domain, frequency, is_active, next_run_at, last_run_at, last_risk_score, prev_risk_score, run_count
            FROM scheduled_scans
            WHERE created_by = ?
            ORDER BY next_run_at ASC
            """,
            (user_id,)
        ).fetchall()
    finally:
        conn.close()
        
    schedules = []
    for row in rows:
        last_score = row["last_risk_score"]
        prev_score = row["prev_risk_score"]
        delta = None
        if last_score is not None and prev_score is not None:
             delta = round(last_score - prev_score, 2)
             
        schedules.append({
            "id": row["id"],
            "domain": row["domain"],
            "frequency": row["frequency"],
            "is_active": bool(row["is_active"]),
            "next_run_at": row["next_run_at"],
            "last_run_at": row["last_run_at"],
            "last_risk_score": last_score,
            "prev_risk_score": prev_score,
            "risk_delta": delta,
            "run_count": row["run_count"]
        })
        
    return {"schedules": schedules}

@app.patch("/api/schedules/{schedule_id}/pause")
async def pause_schedule(schedule_id: int, authorization: str = Header(None)):
    user = get_current_user(authorization)
    
    conn = get_connection()
    try:
        conn.execute("UPDATE scheduled_scans SET is_active = 0 WHERE id = ? AND created_by = ?", (schedule_id, user["sub"]))
        conn.commit()
    finally:
        conn.close()
    return {"message": "Schedule paused", "schedule_id": schedule_id}

@app.patch("/api/schedules/{schedule_id}/resume")
async def resume_schedule(schedule_id: int, authorization: str = Header(None)):
    user = get_current_user(authorization)
    
    conn = get_connection()
    try:
        row = conn.execute("SELECT frequency, custom_interval_hours FROM scheduled_scans WHERE id = ? AND created_by = ?", (schedule_id, user["sub"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")
            
        next_run = calculate_next_run(row["frequency"], row["custom_interval_hours"]).isoformat()
        conn.execute("UPDATE scheduled_scans SET is_active = 1, next_run_at = ? WHERE id = ?", (next_run, schedule_id))
        conn.commit()
    finally:
        conn.close()
        
    return {"message": "Schedule resumed", "schedule_id": schedule_id, "next_run_at": next_run}

@app.patch("/api/schedules/{schedule_id}/update")
async def update_schedule(schedule_id: int, request: ScheduleUpdate, authorization: str = Header(None)):
    user = get_current_user(authorization)
    
    next_run = calculate_next_run(request.frequency, request.custom_interval_hours).isoformat()
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE scheduled_scans SET frequency = ?, custom_interval_hours = ?, notify_on_change = ?, next_run_at = ? WHERE id = ? AND created_by = ?",
            (request.frequency, request.custom_interval_hours, 1 if request.notify_on_change else 0, next_run, schedule_id, user["sub"])
        )
        conn.commit()
    finally:
        conn.close()
        
    return {"message": "Schedule updated", "schedule_id": schedule_id, "next_run_at": next_run}

@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int, authorization: str = Header(None)):
    user = get_current_user(authorization)
    conn = get_connection()
    try:
        conn.execute("DELETE FROM scheduled_scans WHERE id = ? AND created_by = ?", (schedule_id, user["sub"]))
        conn.commit()
    finally:
        conn.close()
    return {"message": "Schedule deleted", "schedule_id": schedule_id}

@app.get("/api/schedules/{schedule_id}/history")
async def get_schedule_history(schedule_id: int, authorization: str = Header(None)):
    user = get_current_user(authorization)
    conn = get_connection()
    try:
        schedule = conn.execute("SELECT domain FROM scheduled_scans WHERE id = ? AND created_by = ?", (schedule_id, user["sub"])).fetchone()
        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")
            
        rows = conn.execute(
            """
            SELECT scan_id, triggered_at, completed_at, status, risk_score, subdomains_found, subdomains_scanned
            FROM schedule_run_history
            WHERE schedule_id = ?
            ORDER BY triggered_at DESC
            """,
            (schedule_id,)
        ).fetchall()
    finally:
        conn.close()
        
    history = []
    for r in rows:
        history.append({
            "run_id": r["scan_id"],
            "triggered_at": r["triggered_at"],
            "completed_at": r["completed_at"],
            "status": r["status"],
            "risk_score": r["risk_score"],
            "subdomains_found": r["subdomains_found"],
            "subdomains_scanned": r["subdomains_scanned"]
        })
        
    return {"schedule_id": schedule_id, "domain": schedule["domain"], "history": history}

@app.post("/api/schedules/{schedule_id}/run-now")
async def run_schedule_now(schedule_id: int, authorization: str = Header(None)):
    user = get_current_user(authorization)
    user_id = user["sub"]
    conn = get_connection()
    try:
        schedule = conn.execute("SELECT domain, id FROM scheduled_scans WHERE id = ? AND created_by = ?", (schedule_id, user_id)).fetchone()
        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")
        domain = schedule["domain"]
    finally:
        conn.close()
        
    # Queue the scan with "api" or "scheduler" source
    scan_id = create_scan_job(domain, domain)
    _link_scan_to_user(user_id, scan_id, domain, "queued")
    
    # Store immediate trigger in history tracking so it updates score
    conn = get_connection()
    try:
        conn.execute("UPDATE scans SET source = 'scheduler' WHERE id = ?", (scan_id,))
        conn.execute(
            "INSERT INTO schedule_run_history (schedule_id, scan_id, status, triggered_at) VALUES (?, ?, 'triggered', ?)",
            (schedule_id, scan_id, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    finally:
        conn.close()
        
    return {"message": "Scan triggered successfully", "scan_id": scan_id}


if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
