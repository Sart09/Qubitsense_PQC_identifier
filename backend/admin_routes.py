"""
Admin console API — read visibility into every user's data plus role and
account-status control. Mounted as a sub-router on the main FastAPI app.

Privilege model, deliberately scoped: admin gets READ access to every
user's profile, scans, and login activity, plus the ability to
promote/demote roles and activate/deactivate accounts. It does NOT get a
bypass of the existing owner-scoped DELETE /scan/{id} (server.py) — that
endpoint's entire design is "only the owner may delete," and reusing it
for admin-on-behalf-of-another-user deletion would quietly widen what
that check means everywhere else it's read. Every number this module
returns comes from a real SQL read (users, scans, user_scans,
login_audit) — nothing here is fabricated or sampled.
"""

import os
import sys
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# analytics.py imports quantum_risk_engine, which lives in analysis/ — this
# module doesn't rely on server.py having already put that on sys.path
# (import order in server.py is not something this file should depend on).
ANALYSIS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis")
sys.path.insert(0, ANALYSIS_DIR)

from database import get_connection
from analytics import (
    load_user_fleet, build_overview, build_history, build_domain_leaderboard,
    build_domain_trend, build_risky_assets, build_crypto_rollup,
)

AUTH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "auth")
sys.path.insert(0, AUTH_DIR)
from auth_routes import get_current_user

router = APIRouter(prefix="/admin", tags=["Admin"])


# ---- Request models --------------------------------------------------------

class RoleUpdateRequest(BaseModel):
    role: str  # "admin" | "user"

class StatusUpdateRequest(BaseModel):
    is_active: bool


# ---- Access control ---------------------------------------------------------

def require_admin(authorization: str = Header(None)) -> dict:
    """Every /admin/* route depends on this alone. Reuses get_current_user,
    which already rejects a missing/expired token or a deactivated
    account, then adds the role check on top."""
    current = get_current_user(authorization)
    conn = get_connection()
    try:
        row = conn.execute("SELECT role FROM users WHERE id = ?;", (int(current["sub"]),)).fetchone()
    finally:
        conn.close()
    if row is None or row["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current


def _active_admin_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) c FROM users WHERE role = 'admin' AND is_active = 1;").fetchone()["c"]


# ---- User directory ---------------------------------------------------------

@router.get("/users")
async def list_users(_: dict = Depends(require_admin)):
    """Every account in the system, with a real scan count per user."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT u.id, u.email, u.role, u.is_active, u.mfa_enabled, u.created_at,
                   u.last_login_at, u.supabase_uid,
                   (SELECT COUNT(*) FROM user_scans us WHERE us.user_id = u.id) AS scan_count
            FROM users u
            ORDER BY u.created_at DESC;
            """
        ).fetchall()
    finally:
        conn.close()
    return {
        "total_users": len(rows),
        "users": [
            {
                "id": r["id"], "email": r["email"], "role": r["role"],
                "is_active": bool(r["is_active"]), "mfa_enabled": bool(r["mfa_enabled"]),
                "created_at": r["created_at"], "last_login_at": r["last_login_at"],
                "supabase_linked": r["supabase_uid"] is not None,
                "scan_count": r["scan_count"],
            }
            for r in rows
        ],
    }


@router.get("/users/{user_id}")
async def get_user_detail(user_id: int, _: dict = Depends(require_admin)):
    """One user's profile, every scan they own, and their real login/MFA
    activity trail — the drill-down behind "see all users' activity"."""
    conn = get_connection()
    try:
        user = conn.execute(
            """SELECT id, email, role, is_active, mfa_enabled, created_at, last_login_at, supabase_uid
               FROM users WHERE id = ?;""",
            (user_id,),
        ).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        scans = conn.execute(
            """SELECT s.id, s.target_domain, s.status, s.created_at
               FROM user_scans us JOIN scans s ON s.id = us.scan_id
               WHERE us.user_id = ? ORDER BY s.created_at DESC;""",
            (user_id,),
        ).fetchall()

        activity = conn.execute(
            """SELECT event, ip_address, user_agent, created_at
               FROM login_audit WHERE user_id = ? ORDER BY created_at DESC LIMIT 200;""",
            (user_id,),
        ).fetchall()
    finally:
        conn.close()

    return {
        "id": user["id"], "email": user["email"], "role": user["role"],
        "is_active": bool(user["is_active"]), "mfa_enabled": bool(user["mfa_enabled"]),
        "created_at": user["created_at"], "last_login_at": user["last_login_at"],
        "supabase_linked": user["supabase_uid"] is not None,
        "scans": [dict(s) for s in scans],
        "activity": [dict(a) for a in activity],
    }


@router.patch("/users/{user_id}/role")
async def update_user_role(user_id: int, body: RoleUpdateRequest, _: dict = Depends(require_admin)):
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")

    conn = get_connection()
    try:
        target = conn.execute("SELECT id, role FROM users WHERE id = ?;", (user_id,)).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")
        if target["role"] == "admin" and body.role != "admin" and _active_admin_count(conn) <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the last remaining admin")
        conn.execute("UPDATE users SET role = ? WHERE id = ?;", (body.role, user_id))
        conn.commit()
    finally:
        conn.close()
    return {"id": user_id, "role": body.role}


@router.patch("/users/{user_id}/status")
async def update_user_status(user_id: int, body: StatusUpdateRequest, _: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        target = conn.execute("SELECT id, role FROM users WHERE id = ?;", (user_id,)).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")
        if target["role"] == "admin" and not body.is_active and _active_admin_count(conn) <= 1:
            raise HTTPException(status_code=409, detail="Cannot deactivate the last remaining admin")
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?;", (1 if body.is_active else 0, user_id))
        conn.commit()
    finally:
        conn.close()
    return {"id": user_id, "is_active": body.is_active}


# ---- Fleet-wide activity & stats --------------------------------------------

@router.get("/activity")
async def admin_activity(limit: int = 50, _: dict = Depends(require_admin)):
    """Real, paginated feed merging login/MFA events with scan creation
    across every user — newest first. Nothing here is sampled or invented."""
    limit = max(1, min(200, limit))
    conn = get_connection()
    try:
        logins = conn.execute(
            """SELECT 'login' AS kind, email, event, ip_address, created_at
               FROM login_audit ORDER BY created_at DESC LIMIT ?;""",
            (limit,),
        ).fetchall()
        scans = conn.execute(
            """
            SELECT 'scan' AS kind, u.email AS email, s.status AS event, s.created_at AS created_at,
                   s.id AS scan_id, s.target_domain AS domain
            FROM scans s
            LEFT JOIN user_scans us ON us.scan_id = s.id
            LEFT JOIN users u ON u.id = us.user_id
            ORDER BY s.created_at DESC LIMIT ?;
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    events = [dict(r) for r in logins] + [dict(r) for r in scans]
    events.sort(key=lambda e: e["created_at"] or "", reverse=True)
    return {"events": events[:limit]}


@router.get("/stats")
async def admin_stats(_: dict = Depends(require_admin)):
    """Fleet totals — every value a real SQL aggregate over the same
    tables the rest of the app reads, computed in Python-ISO time
    boundaries rather than mixing SQLite's datetime() formatting with
    the app's stored ISO-8601 timestamps."""
    now = datetime.now(timezone.utc)
    today_start = now.date().isoformat()
    week_ago = (now - timedelta(days=7)).isoformat()

    conn = get_connection()
    try:
        total_users = conn.execute("SELECT COUNT(*) c FROM users;").fetchone()["c"]
        total_scans = conn.execute("SELECT COUNT(*) c FROM scans;").fetchone()["c"]
        admin_count = conn.execute("SELECT COUNT(*) c FROM users WHERE role = 'admin';").fetchone()["c"]
        mfa_users = conn.execute("SELECT COUNT(*) c FROM users WHERE mfa_enabled = 1;").fetchone()["c"]
        scans_today = conn.execute(
            "SELECT COUNT(*) c FROM scans WHERE created_at >= ?;", (today_start,)
        ).fetchone()["c"]
        active_7d = conn.execute(
            """SELECT COUNT(DISTINCT user_id) c FROM login_audit
               WHERE event IN ('login_success', 'mfa_verified') AND created_at >= ?;""",
            (week_ago,),
        ).fetchone()["c"]
    finally:
        conn.close()

    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "admin_count": admin_count,
        "mfa_adoption_rate": round(mfa_users / total_users * 100, 1) if total_users else 0.0,
        "active_users_7d": active_7d,
        "scans_today": scans_today,
    }


# ---- Fleet-wide analytics — reuses analytics.py's builders unmodified ------
# Same functions the regular /analytics/* routes use, just fed a fleet that
# is either unfiltered (?user_id omitted) or targeted at one user
# (?user_id=<id>) instead of always scoped to the caller. No aggregation
# logic is duplicated — load_user_fleet(None) is the one place this widens.

@router.get("/analytics/overview")
async def admin_analytics_overview(user_id: int | None = None, _: dict = Depends(require_admin)):
    return build_overview(load_user_fleet(user_id))

@router.get("/analytics/history")
async def admin_analytics_history(user_id: int | None = None, _: dict = Depends(require_admin)):
    return build_history(load_user_fleet(user_id))

@router.get("/analytics/domains")
async def admin_analytics_domains(user_id: int | None = None, _: dict = Depends(require_admin)):
    return build_domain_leaderboard(load_user_fleet(user_id))

@router.get("/analytics/domains/{domain}/trend")
async def admin_analytics_domain_trend(domain: str, user_id: int | None = None, _: dict = Depends(require_admin)):
    fleet = load_user_fleet(user_id)
    if not any(s["domain"] == domain for s in fleet["scans"]):
        raise HTTPException(status_code=404, detail=f"No scans of {domain} found")
    return build_domain_trend(fleet, domain)

@router.get("/analytics/assets/risky")
async def admin_analytics_risky(limit: int = 25, user_id: int | None = None, _: dict = Depends(require_admin)):
    return build_risky_assets(load_user_fleet(user_id), max(1, min(200, limit)))

@router.get("/analytics/crypto")
async def admin_analytics_crypto(user_id: int | None = None, _: dict = Depends(require_admin)):
    return build_crypto_rollup(load_user_fleet(user_id))
