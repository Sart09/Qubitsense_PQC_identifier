"""
Quantum Proof System Scanner — FastAPI Server
======================================================
Entry-point for the application.  Run with:

    python backend/server.py
"""

import os
import re
import sys

# Ensure the backend package is on the path when running as a script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Header, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx
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
    AssetDetailsResponse, AssetScoreBreakdown, ScoreComponent,
    ScanFailuresResponse, ScanFailureItem,
    DomainScanHistoryResponse, DomainScanHistoryItem, DomainsListResponse,
    AgentChatRequest,
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
from auth_routes import router as auth_router, get_current_user, seed_bootstrap_admin
from admin_routes import router as admin_router

# Analysis modules
ANALYSIS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis")
sys.path.insert(0, ANALYSIS_DIR)
from quantum_risk_engine import (
    calculate_quantum_risk, summarize_fleet, get_scoring_model,
)
from remediation import build_recommendations
from report_export import (
    build_report_data, build_cyclonedx_bom, build_pdf_report,
    build_host_report_data, build_host_pdf_report,
)
from analytics import (
    load_user_fleet, build_overview, build_history, build_domain_leaderboard,
    build_domain_trend, build_risky_assets, build_crypto_rollup,
)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialize the database, seed the crypto registry, and ensure the
    bootstrap admin account exists — all idempotent, so the app is fully
    demoable immediately after a fresh clone with zero manual setup."""
    init_db()
    seeded = seed_registry()
    if seeded:
        print(f"[startup] Seeded {seeded} algorithms into crypto_registry")
    if seed_bootstrap_admin():
        print("[startup] Seeded bootstrap admin account (nick@gmail.com)")
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

# Include auth + admin routers
app.include_router(auth_router)
app.include_router(admin_router)


# ---------------------------------------------------------------------------
# Scoring input helpers
#
# Every endpoint that scores an asset builds the engine's input dicts
# through these two helpers, so all of them feed the model the same fields.
# Previously each call site assembled its own dict inline and they had
# drifted apart — the same host could score differently depending on which
# endpoint you asked, because some sites omitted the certificate trust
# columns. _row_get tolerates rows selected without the newer columns.
# ---------------------------------------------------------------------------

def _row_get(row, key, default=None):
    """Safe accessor for sqlite3.Row, which raises on absent columns."""
    try:
        return row[key]
    except (IndexError, KeyError):
        return default


def _tls_dict(row) -> dict:
    """Handshake facts consumed by the scoring engine."""
    return {
        "tls_version": _row_get(row, "tls_version"),
        "cipher_suite": _row_get(row, "cipher_suite"),
    }


def _cert_dict(row) -> dict:
    """Certificate facts consumed by the scoring engine, including the
    validation flags that carry the certificate-trust component."""
    def _flag(name):
        value = _row_get(row, name)
        return None if value is None else bool(value)

    return {
        "key_algorithm": _row_get(row, "key_algorithm"),
        "key_size": _row_get(row, "key_size"),
        "signature_algorithm": _row_get(row, "signature_algorithm"),
        "certificate_expiry": _row_get(row, "certificate_expiry"),
        "is_expired": _flag("is_expired"),
        "is_self_signed": _flag("is_self_signed"),
        "hostname_mismatch": _flag("hostname_mismatch"),
        "days_until_expiry": _row_get(row, "days_until_expiry"),
    }


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


@app.get("/analytics")
async def analytics_page():
    return no_cache_file(os.path.join(FRONTEND_DIR, "analytics.html"))


@app.get("/home")
async def home_page():
    """
    The signed-in landing page: a card grid of every domain the user has
    scanned, each opening that domain's scan history.

    This is what the sidebar's Home item points at. It is deliberately NOT
    index.html — that page is the anonymous entry point and its whole body
    is a "start a new scan" form, so sending a returning user there on Home
    dropped them into a new scan instead of showing them their estate.
    """
    return no_cache_file(os.path.join(FRONTEND_DIR, "user_dashboard.html"))


@app.get("/user-dashboard")
async def user_dashboard_page():
    """Legacy path for the domain inventory — now served at /home."""
    return RedirectResponse(url="/home")


@app.get("/scan-progress/{scan_id}")
async def scan_progress_page(scan_id: str):
    return no_cache_file(os.path.join(FRONTEND_DIR, "scan_progress.html"))


@app.get("/admin")
async def admin_page():
    """Admin console — the page itself loads for anyone, but every data
    call it makes is rejected server-side (admin_routes.py's require_admin)
    unless the caller is an active admin, so there is no real access
    control gap here even before the page's own client-side gate runs."""
    return no_cache_file(os.path.join(FRONTEND_DIR, "admin.html"))


@app.get("/security")
async def security_page():
    return no_cache_file(os.path.join(FRONTEND_DIR, "security.html"))

@app.get("/schedules")
async def schedules_page():
    return no_cache_file(os.path.join(FRONTEND_DIR, "schedules.html"))

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


@app.post("/api/agent/chat")
async def agent_chat(request: AgentChatRequest):
    """
    Server-side proxy to Groq for the "Qubit" assistant.

    The API key lives only here and is never sent to the browser. The
    previous version of this integration (/api/config/agent-key, Gemini)
    returned the raw key to any authenticated client, which then called
    Google directly from the browser — a real key-exposure bug, documented
    and now fixed rather than repeated with a different provider.

    No auth required: Qubit is meant to answer questions for anonymous
    visitors too, matching the rest of the platform ("Skip login and
    proceed to scanner" — the core product needs no account either).
    """
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="AI assistant is not configured (missing GROQ_API_KEY in .env).",
        )

    # Bound cost/latency against an unauthenticated endpoint: cap how much
    # history is forwarded and the total payload size, rather than trusting
    # an anonymous client indefinitely.
    messages = request.messages[-20:]
    total_chars = len(request.system) + sum(len(m.content) for m in messages)
    if total_chars > 24000:
        raise HTTPException(status_code=413, detail="Message too long.")

    payload = {
        "model": os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        "messages": (
            [{"role": "system", "content": request.system}]
            + [{"role": m.role, "content": m.content} for m in messages]
        ),
        "temperature": 0.4,
        "max_tokens": 700,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.post(
                GROQ_API_URL,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=payload,
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach the AI provider: {exc}")

    if res.status_code != 200:
        detail = res.text[:300]
        try:
            detail = res.json().get("error", {}).get("message", detail)
        except Exception:
            pass
        raise HTTPException(status_code=502, detail=f"AI provider error ({res.status_code}): {detail}")

    data = res.json()
    try:
        reply = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise HTTPException(status_code=502, detail="Unexpected response shape from AI provider.")

    return {"reply": reply}


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


@app.post("/scan/priority", response_model=ScanResponse)
async def start_priority_scan(
    request: ScanRequest,
    authorization: str = Header(None),
):
    """
    Submit a PRIORITY scan that jumps the queue.
    Pauses all currently queued jobs, runs this scan first,
    then resumes paused jobs automatically after completion.
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

    # Pause all currently queued jobs (set status = 'paused')
    conn = get_connection()
    try:
        paused_count = conn.execute(
            "UPDATE scans SET status = 'paused' WHERE status = 'queued';"
        ).rowcount
        conn.commit()
    finally:
        conn.close()

    print(f"[scan/priority] Paused {paused_count} queued jobs")

    # Create a priority scan job (priority=1 ensures it's picked first)
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO scans (target_domain, parent_domain, status, priority, created_at)
            VALUES (?, ?, 'queued', 1, ?);
            """,
            (domain, domain_info.parent_domain, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        scan_id = cursor.lastrowid
    finally:
        conn.close()

    print(f"[scan/priority] Created priority scan job {scan_id} for {domain}")

    # Link to user
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





@app.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: int):
    """
    Stop a running, queued, or paused scan by setting its status to 'cancelled'.
    Also resumes any paused jobs so they can proceed.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, status FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        if row["status"] in ("completed", "failed", "cancelled"):
            raise HTTPException(status_code=400, detail=f"Scan already {row['status']}")

        conn.execute(
            "UPDATE scans SET status = 'cancelled' WHERE id = ?;", (scan_id,)
        )
        # Resume any jobs that were paused for a priority scan
        resumed = conn.execute(
            "UPDATE scans SET status = 'queued' WHERE status = 'paused';"
        ).rowcount
        conn.commit()
        print(f"[scan/stop] Cancelled scan {scan_id}, resumed {resumed} paused jobs")
    finally:
        conn.close()

    return JSONResponse({"scan_id": scan_id, "status": "cancelled", "resumed_jobs": resumed})


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

        # Build query based on exclude_failed flag. LEFT JOIN discovered_assets
        # for the real resolved IP — the Asset Inventory table used to
        # synthesize a fake 10.x.x.x address from the hostname string length;
        # this is the actual IP the scanner connected to.
        base_select = """
            SELECT t.id, t.hostname, t.port, t.tls_version, t.cipher_suite,
                   t.key_algorithm, t.key_size, t.signature_algorithm, t.certificate_expiry,
                   t.hostname_mismatch, t.is_self_signed, t.is_expired,
                   t.days_until_expiry, t.issuer, d.ip_address
            FROM tls_results t
            LEFT JOIN discovered_assets d
                   ON d.scan_id = t.scan_id AND d.hostname = t.hostname
            WHERE t.scan_id = ?
        """
        if exclude_failed:
            query = base_select + " AND t.tls_version IS NOT NULL AND t.tls_version != '' ORDER BY t.hostname;"
        else:
            query = base_select + " ORDER BY t.hostname;"

        rows = conn.execute(query, (scan_id,)).fetchall()
    finally:
        conn.close()

    results = []
    for row in rows:
        results.append(TlsResultItem(
            id=row["id"],
            hostname=row["hostname"],
            port=row["port"],
            ip_address=row["ip_address"],
            tls_version=row["tls_version"],
            cipher_suite=row["cipher_suite"],
            key_algorithm=row["key_algorithm"],
            key_size=row["key_size"],
            signature_algorithm=row["signature_algorithm"],
            certificate_expiry=row["certificate_expiry"],
            hostname_mismatch=bool(row["hostname_mismatch"]) if row["hostname_mismatch"] is not None else None,
            is_self_signed=bool(row["is_self_signed"]) if row["is_self_signed"] is not None else None,
            is_expired=bool(row["is_expired"]) if row["is_expired"] is not None else None,
            days_until_expiry=row["days_until_expiry"],
            issuer=row["issuer"],
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

        # Certificate validation flags and the pre-parsed cipher components
        # are selected here because the v2 scoring model weighs them
        # (certificate trust, cipher mode, hash strength). Leaving them out
        # made four of the ten components fall back to their "unknown"
        # defaults on data the scanner had already collected.
        tls_rows = conn.execute(
            """SELECT hostname, port, tls_version, cipher_suite,
                      key_algorithm, signature_algorithm, key_size, certificate_expiry,
                      hostname_mismatch, is_self_signed, is_expired, days_until_expiry
               FROM tls_results WHERE scan_id = ? ORDER BY hostname;""",
            (scan_id,)
        ).fetchall()

        hndl_rows = conn.execute(
            "SELECT hostname, service_type, hndl_multiplier, risk_level FROM hndl_results WHERE scan_id = ?;",
            (scan_id,)
        ).fetchall()
        hndl_map = {row["hostname"]: dict(row) for row in hndl_rows}

        algo_rows = conn.execute(
            "SELECT hostname, key_exchange, signature, encryption, hash FROM algorithm_analysis WHERE scan_id = ?;",
            (scan_id,)
        ).fetchall()
        algo_map = {row["hostname"]: dict(row) for row in algo_rows}

    finally:
        conn.close()

    results = []
    for tls in tls_rows:
        hostname = tls["hostname"]
        qr_res = calculate_quantum_risk(
            _tls_dict(tls), _cert_dict(tls),
            hndl_map.get(hostname), algo_map.get(hostname),
        )
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
            cipher_score=b["cipher"],
            forward_secrecy_score=b["forward_secrecy"],
            cipher_mode_score=b["cipher_mode"],
            hash_score=b["hash"],
            certificate_trust_score=b["certificate_trust"],
            composite_score=qr_res["composite_score"],
            applied_floor=qr_res["applied_floor"],
            hndl_multiplier=qr_res["hndl"]["multiplier"],
            hndl_uplift=qr_res["hndl"]["uplift"],
            quantum_safe_key_exchange=qr_res["quantum_safe_key_exchange"],
            quantum_safe_signature=qr_res["quantum_safe_signature"],
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
                      key_algorithm, signature_algorithm, key_size, certificate_expiry,
                      hostname_mismatch, is_self_signed, is_expired, days_until_expiry, issuer
               FROM tls_results WHERE id = ?;""",
            (asset_id,)
        ).fetchone()
        
        if not tls:
            raise HTTPException(status_code=404, detail="Asset not found")

        # Get HNDL info — the numeric multiplier drives the amplification
        # stage, so it is selected alongside the coarse risk level.
        hndl = conn.execute(
            """SELECT service_type, hndl_multiplier, risk_level FROM hndl_results
               WHERE scan_id = ? AND hostname = ?;""",
            (tls["scan_id"], tls["hostname"])
        ).fetchone()

        algo = conn.execute(
            """SELECT key_exchange, signature, encryption, hash FROM algorithm_analysis
               WHERE scan_id = ? AND hostname = ?;""",
            (tls["scan_id"], tls["hostname"])
        ).fetchone()

    finally:
        conn.close()

    qr_res = calculate_quantum_risk(
        _tls_dict(tls), _cert_dict(tls),
        dict(hndl) if hndl else None,
        dict(algo) if algo else None,
    )
    b = qr_res["breakdown"]

    score = qr_res["total_score"]
    breakdown = AssetScoreBreakdown(
        key_exchange=b["key_exchange"],
        signature=b["signature"],
        tls=b["tls_version"],
        key_size=b["key_size"],
        certificate=b["certificate"],
        cipher=b["cipher"],
        forward_secrecy=b["forward_secrecy"],
        cipher_mode=b["cipher_mode"],
        hash=b["hash"],
        certificate_trust=b["certificate_trust"],
    )

    # Recommendations driven by which components are actually elevated for
    # THIS asset, not a fixed list shown identically for every asset
    # regardless of its real weaknesses. Shared with the per-host
    # remediation PDF (report_export.py) so the two can never disagree.
    recommendations = build_recommendations(b, tls)

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
        pqc_recommendations=recommendations,
        hostname_mismatch=bool(tls["hostname_mismatch"]) if tls["hostname_mismatch"] is not None else None,
        is_self_signed=bool(tls["is_self_signed"]) if tls["is_self_signed"] is not None else None,
        is_expired=bool(tls["is_expired"]) if tls["is_expired"] is not None else None,
        days_until_expiry=tls["days_until_expiry"],
        issuer=tls["issuer"],
        score_components=[ScoreComponent(**c) for c in qr_res["components"]],
        composite_score=qr_res["composite_score"],
        applied_floor=qr_res["applied_floor"],
        hndl_multiplier=qr_res["hndl"]["multiplier"],
        hndl_uplift=qr_res["hndl"]["uplift"],
        risk_label=qr_res["risk_label"],
    )



def _report_or_409(scan_id: int) -> dict:
    """
    Load a scan's report data, refusing to produce a report for a scan that
    scanned nothing.

    A zero-host scan used to export a fully-formed PDF/JSON/CycloneDX
    document whose every table was empty and whose rating was 0/1000 —
    indistinguishable, to anyone reading the file, from a real estate with
    catastrophic posture. Refusing with an explanation is the honest
    outcome; 409 (not 404) because the scan exists, it just has nothing to
    report.
    """
    report = build_report_data(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if report["summary"]["assets_scanned"] == 0:
        discovered = report["summary"]["assets_discovered"]
        detail = (
            f"Scan #{scan_id} of '{report['domain']}' scanned 0 hosts, so there is nothing to report. "
            + (
                "No subdomains resolved — the domain may not exist or has no public DNS records."
                if discovered == 0
                else f"All {discovered} discovered host(s) were unreachable — see the scan's failure list."
            )
        )
        raise HTTPException(status_code=409, detail=detail)
    return report


@app.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: int):
    """
    Aggregate all scan data into a single JSON report for export.
    """
    return JSONResponse(_report_or_409(scan_id))


@app.get("/scan/{scan_id}/report/cyclonedx")
async def get_scan_report_cyclonedx(scan_id: int):
    """
    Export the scan's full findings as a CycloneDX 1.6 cryptographic-asset
    BOM (CBOM), for use with CycloneDX-compatible SBOM/CBOM tooling.
    """
    bom = build_cyclonedx_bom(_report_or_409(scan_id))
    return JSONResponse(
        bom,
        headers={"Content-Disposition": f'attachment; filename="quantum-scan-{scan_id}-cyclonedx.json"'},
    )


@app.get("/scan/{scan_id}/report/pdf")
async def get_scan_report_pdf(scan_id: int):
    """
    Export the scan's full findings as a printable PDF, built server-side
    from the same data as the JSON report — every table on the dashboard,
    not a screenshot of the page.
    """
    pdf_bytes = build_pdf_report(_report_or_409(scan_id))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="quantum-scan-{scan_id}.pdf"'},
    )


@app.get("/asset/{asset_id}/report/pdf")
async def get_asset_report_pdf(asset_id: int):
    """
    Export a single host's remediation findings as a standalone, printable
    PDF: full 10-component score derivation, crypto/certificate findings,
    HNDL exposure, and a prioritized remediation checklist — everything an
    auditor needs for one asset without downloading the whole-scan report.
    Same recommendation logic as GET /asset/{id} (analysis/remediation.py),
    so the JSON view and this PDF never disagree.
    """
    host = build_host_report_data(asset_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    pdf_bytes = build_host_pdf_report(host)
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "_", host["hostname"])
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_host}-remediation-{asset_id}.pdf"'},
    )


@app.post("/scan/upload")
async def handle_document_upload(file: UploadFile = File(...)):
    """Accepts an image or PDF containing a QR/Barcode, decodes it, and returns the target URL."""
    contents = await file.read()
    urls = parse_upload_for_urls(file.filename, contents)
    if not urls:
        raise HTTPException(status_code=400, detail="No QR/Barcode found in document.")
    return JSONResponse({"url": urls[0]})

@app.get("/scan/{scan_id}/logs")
async def get_scan_logs(scan_id: int, after_id: int = 0):
    """
    Retrieve the real-time execution logs for a specific scan job.

    after_id makes this a tail: the progress page passes the highest id it
    has already rendered and gets back only what is new. The scan now logs
    every discovered host and every host result, so a large estate produces
    thousands of rows — re-sending the whole history every 2 seconds (what
    the page used to do) grew the poll response without bound over the life
    of the scan, on exactly the scans that take longest.

    Omitting after_id returns the full history, so a reload still rebuilds
    the whole trace and any existing caller keeps working.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, message, created_at FROM scan_logs "
            "WHERE scan_id = ? AND id > ? ORDER BY id ASC;",
            (scan_id, after_id),
        ).fetchall()
        return [
            {"id": r["id"], "message": r["message"], "created_at": r["created_at"]}
            for r in rows
        ]
    finally:
        conn.close()

@app.get("/scoring-model")
async def get_risk_scoring_model():
    """
    Return the complete quantum risk scoring model: every component and its
    weight, the HNDL amplification formula, the floor rules, the risk bands
    and the posture tiers.

    Exposed as an endpoint so the methodology is independently verifiable —
    the same constants that produce every score in the platform are served
    here verbatim, which lets a reviewer confirm the weights sum to 1.0 and
    that no score is hardcoded.
    """
    model = get_scoring_model()
    return JSONResponse(model)


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


# ---------------------------------------------------------------------------
# Cross-scan analytics (authenticated — scoped to the caller's own scans)
#
# All six endpoints share one loader, load_user_fleet(), which fetches and
# scores the user's whole estate in a fixed number of queries. Scoring runs
# through the same engine the per-scan dashboard uses, so the analytics page
# and a scan's own dashboard can never report different numbers for the same
# host.
# ---------------------------------------------------------------------------

@app.get("/analytics/overview")
async def analytics_overview(authorization: str = Header(None)):
    """Fleet-level headline posture across every scan the user owns."""
    user = get_current_user(authorization)
    fleet = load_user_fleet(user["sub"])
    return JSONResponse(build_overview(fleet))


@app.get("/analytics/history")
async def analytics_history(authorization: str = Header(None)):
    """
    Every scan the user owns, newest first, with per-scan posture.
    Replaces the data behind the retired My Scans page.
    """
    user = get_current_user(authorization)
    fleet = load_user_fleet(user["sub"])
    return JSONResponse(build_history(fleet))


@app.get("/analytics/domains")
async def analytics_domains(authorization: str = Header(None)):
    """Per-domain posture leaderboard, worst first."""
    user = get_current_user(authorization)
    fleet = load_user_fleet(user["sub"])
    return JSONResponse(build_domain_leaderboard(fleet))


@app.get("/analytics/domains/{domain}/trend")
async def analytics_domain_trend(domain: str, authorization: str = Header(None)):
    """Posture movement across repeat scans of one domain."""
    user = get_current_user(authorization)
    fleet = load_user_fleet(user["sub"])
    if not any(s["domain"] == domain for s in fleet["scans"]):
        raise HTTPException(status_code=404, detail=f"No scans of {domain} found for this account")
    return JSONResponse(build_domain_trend(fleet, domain))


@app.get("/analytics/assets/risky")
async def analytics_risky_assets(limit: int = 25, authorization: str = Header(None)):
    """Riskiest individual hosts across the user's whole estate."""
    user = get_current_user(authorization)
    fleet = load_user_fleet(user["sub"])
    return JSONResponse(build_risky_assets(fleet, max(1, min(200, limit))))


@app.get("/analytics/crypto")
async def analytics_crypto(authorization: str = Header(None)):
    """Fleet-wide algorithm inventory and where the weakest links cluster."""
    user = get_current_user(authorization)
    fleet = load_user_fleet(user["sub"])
    return JSONResponse(build_crypto_rollup(fleet))


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

            # Dynamically calculate the score for this scan across all its
            # assets, using the same columns and the same fleet aggregation
            # as the dashboard so a scan's score is identical wherever it
            # is displayed.
            tls_rows = conn.execute(
                """SELECT hostname, tls_version, cipher_suite,
                          key_algorithm, signature_algorithm, key_size, certificate_expiry,
                          hostname_mismatch, is_self_signed, is_expired, days_until_expiry
                   FROM tls_results WHERE scan_id = ?;""",
                (sid,)
            ).fetchall()

            hndl_rows = conn.execute(
                "SELECT hostname, service_type, hndl_multiplier, risk_level FROM hndl_results WHERE scan_id = ?;",
                (sid,)
            ).fetchall()
            hndl_map = {row["hostname"]: dict(row) for row in hndl_rows}

            algo_rows = conn.execute(
                "SELECT hostname, key_exchange, signature, encryption, hash FROM algorithm_analysis WHERE scan_id = ?;",
                (sid,)
            ).fetchall()
            algo_map = {row["hostname"]: dict(row) for row in algo_rows}

            scores = [
                calculate_quantum_risk(
                    _tls_dict(tls), _cert_dict(tls),
                    hndl_map.get(tls["hostname"]), algo_map.get(tls["hostname"]),
                )["total_score"]
                for tls in tls_rows
            ]
            fleet = summarize_fleet(scores)
            scan_obj["risk_score"] = fleet["average_risk_score"]
            scan_obj["enterprise_rating"] = fleet["enterprise_rating"]
            scan_obj["posture_tier"] = fleet["posture_tier"]
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
# Scan deletion
# ---------------------------------------------------------------------------

# Every table that carries a scan_id. Enumerated explicitly because SQLite
# runs with foreign_keys=OFF here, so the schema's ON DELETE clauses never
# fire — nothing cascades on its own. Missing a table from this list leaves
# orphan rows keyed to a scan that no longer exists, which is how
# schedule_run_history was silently accumulating them before.
SCAN_CHILD_TABLES = (
    "algorithm_analysis",
    "hndl_results",
    "tls_results",
    "discovered_assets",
    "scan_results",
    "scan_failures",
    "scan_logs",
    "scan_cache",
    "schedule_run_history",
)


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, authorization: str = Header(None)):
    """
    Permanently delete a scan and every record derived from it.

    Removes the scan from all of the caller's views at once: history,
    analytics, domain leaderboards, trends, the domain's scan list, the
    24-hour result cache, and any scheduler run history that referenced it.

    A scan still queued or running is refused rather than deleted: the
    worker holds the id and would keep writing result rows after the delete,
    recreating exactly the orphans this endpoint exists to avoid. Stop it
    first via POST /scan/{id}/stop.
    """
    user = get_current_user(authorization)
    user_id = user["sub"]

    conn = get_connection()
    try:
        owned = conn.execute(
            "SELECT id FROM user_scans WHERE scan_id = ? AND user_id = ?;",
            (scan_id, user_id),
        ).fetchone()
        if not owned:
            raise HTTPException(status_code=404, detail="Scan not found or not owned by user")

        scan = conn.execute(
            "SELECT id, target_domain, status FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        if scan and scan["status"] in ("queued", "running", "paused"):
            raise HTTPException(
                status_code=409,
                detail=f"Scan #{scan_id} is '{scan['status']}'. Stop it first, then delete.",
            )

        # Drop only this user's ownership link.
        conn.execute(
            "DELETE FROM user_scans WHERE scan_id = ? AND user_id = ?;", (scan_id, user_id)
        )

        # The scan's own data is shared, so it is only destroyed once no
        # other account still links to it. With one owner per scan this is
        # always true today, but deleting another user's data as a side
        # effect is not a behaviour to leave lying around.
        remaining = conn.execute(
            "SELECT COUNT(*) c FROM user_scans WHERE scan_id = ?;", (scan_id,)
        ).fetchone()["c"]

        if remaining == 0:
            for table in SCAN_CHILD_TABLES:
                conn.execute(f"DELETE FROM {table} WHERE scan_id = ?;", (scan_id,))
            # scheduled_scans points at its most recent scan by id. That is a
            # reference, not owned data, so the schedule survives — but the
            # pointer has to be cleared or it dangles at a deleted row.
            conn.execute(
                "UPDATE scheduled_scans SET last_scan_id = NULL WHERE last_scan_id = ?;",
                (scan_id,),
            )
            conn.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))

        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return JSONResponse({
        "status": "deleted",
        "scan_id": scan_id,
        "domain": scan["target_domain"] if scan else None,
        "fully_removed": remaining == 0,
    })

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
