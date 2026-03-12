"""
Quantum Crypto Intelligence Platform — FastAPI Server
======================================================
Entry-point for the application.  Run with:

    python backend/server.py
"""

import os
import sys

# Ensure the backend package is on the path when running as a script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from datetime import datetime, timezone

from database import init_db, get_connection
from models import (
    ScanRequest, ScanResponse, ScanStatusResponse, AssetsResponse,
    TlsResultsResponse, TlsResultItem,
    QuantumRiskResponse, QuantumRiskResultItem,
    HndlResponse, HndlResultItem,
    AlgorithmAnalysisResponse, AlgorithmAnalysisItem,
    AssetDetailsResponse, AssetScoreBreakdown
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
    title="Quantum Crypto Intelligence Platform",
    version="0.2.0",
    description="Analyze websites for quantum cryptographic risk and HNDL exposure.",
    lifespan=lifespan,
)

# Mount static JS components folder
components_dir = os.path.join(FRONTEND_DIR, "components")
os.makedirs(components_dir, exist_ok=True)
app.mount("/components", StaticFiles(directory=components_dir), name="components")

# Include auth router
app.include_router(auth_router)


# ---------------------------------------------------------------------------
# Frontend Page Routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def serve_frontend():
    """Serve the login page by default."""
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"), media_type="text/html")

@app.get("/scanner", include_in_schema=False)
async def serve_scanner():
    """Serve the scanner landing page."""
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"), media_type="text/html")


@app.get("/scan-progress/{scan_id}", include_in_schema=False)
async def serve_scan_progress(scan_id: int):
    """Serve the scan progress page."""
    return FileResponse(os.path.join(FRONTEND_DIR, "scan_progress.html"), media_type="text/html")


@app.get("/dashboard/{scan_id}", include_in_schema=False)
async def serve_dashboard(scan_id: int):
    """Serve the results dashboard page."""
    return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"), media_type="text/html")


@app.get("/login", include_in_schema=False)
async def serve_login():
    """Serve the login/register page."""
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"), media_type="text/html")


@app.get("/user-dashboard", include_in_schema=False)
async def serve_user_dashboard():
    """Serve the user dashboard page."""
    return FileResponse(os.path.join(FRONTEND_DIR, "user_dashboard.html"), media_type="text/html")


@app.post("/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    force: bool = Query(False),
    authorization: str = Header(None),
):
    """
    Submit a domain or URL for scanning.

    If a cached result exists (within 24h) and ``force`` is False,
    return the cached scan_id with status ``cached``.
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

    # Check cache (unless force=true)
    if not force:
        conn = get_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cached = conn.execute(
                "SELECT scan_id FROM scan_cache WHERE domain = ? AND expires_at > ? ORDER BY id DESC LIMIT 1;",
                (domain, now),
            ).fetchone()
        finally:
            conn.close()

        if cached:
            print(f"Cache hit for {domain} -> scan_id {cached['scan_id']}")
            
            # Link cached scan to user
            if user_id:
                _link_scan_to_user(user_id, cached["scan_id"], domain, "cached")
            return ScanResponse(scan_id=cached["scan_id"], status="cached")

    scan_id = create_scan_job(domain, domain_info.parent_domain)
    print("New scan job created:", scan_id)

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
async def get_scan_tls(scan_id: int):
    """
    Return all TLS scan results for a given scan.
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
            SELECT id, hostname, port, tls_version, cipher_suite,
                   key_algorithm, key_size, signature_algorithm, certificate_expiry
            FROM tls_results
            WHERE scan_id = ?
            ORDER BY hostname;
            """,
            (scan_id,),
        ).fetchall()
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

    results = [
        AlgorithmAnalysisItem(
            hostname=row["hostname"],
            cipher_suite=row["cipher_suite"],
            key_exchange=row["key_exchange"],
            signature=row["signature"],
            encryption=row["encryption"],
            hash=row["hash"],
            classification=row["classification"],
            quantum_risk_estimate=row["quantum_risk_estimate"],
        )
        for row in rows
    ]

    return AlgorithmAnalysisResponse(scan_id=scan_id, results=results)


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
            SELECT us.scan_id, us.domain, us.status, us.monitored, us.created_at,
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


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
