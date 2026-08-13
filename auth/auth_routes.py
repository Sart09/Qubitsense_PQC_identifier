"""
Authentication API routes — register, login, MFA, and user-related
endpoints. Mounted as a sub-router on the main FastAPI app.

Identity backend: local bcrypt by default; automatically starts routing
password verification through Supabase Auth (see supabase_client.py) once
SUPABASE_URL/SUPABASE_ANON_KEY are set, per-user, based on whether that
user has a supabase_uid on file — never a blanket switch, so a Supabase
outage can't flip every user onto a code path that hasn't been exercised
for them. Either way, this module issues its own JWT (jwt_handler.py,
unchanged) as the app's session token, so nothing downstream of login
needs to know or care which identity backend authenticated the password.

MFA (auth/mfa.py, TOTP) is a second factor enforced by this module alone,
independent of the identity backend. A logged-in-but-not-yet-2FA'd state
is represented by an opaque, DB-backed challenge token (mfa_challenges
table) — deliberately NOT a JWT, because jwt_handler.verify_token only
checks signature+expiry, not token purpose, and get_current_user accepts
any JWT it validates at every protected route in the app. A JWT minted for
"password OK, MFA pending" would be a fully valid, MFA-bypassing session
token the instant it existed.
"""

import os
import secrets
import sys

# Ensure auth modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel

from password_utils import hash_password, verify_password
from jwt_handler import create_access_token, verify_token
import mfa
import supabase_client

# Use the backend database helper
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
from database import get_connection

router = APIRouter(prefix="/auth", tags=["Authentication"])

MFA_CHALLENGE_TTL_MINUTES = 5
MFA_MAX_ATTEMPTS = 5


# ---- Request / Response Models -------------------------------------------

class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    token: str
    email: str
    user_id: int
    role: str = "user"
    mfa_enabled: bool = False

class MfaVerifyRequest(BaseModel):
    challenge_token: str
    code: str

class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_png_base64: str

class MfaActivateRequest(BaseModel):
    code: str

class MfaDisableRequest(BaseModel):
    password: str


# ---- Small helpers ---------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _now_iso() -> str:
    return _now().isoformat()

def _admin_emails() -> set[str]:
    raw = os.getenv("ADMIN_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}

def _write_login_audit(user_id: int | None, email: str, event: str, request: Request | None = None) -> None:
    conn = get_connection()
    try:
        ip = request.client.host if request is not None and request.client else None
        ua = request.headers.get("user-agent") if request is not None else None
        conn.execute(
            """INSERT INTO login_audit (user_id, email, event, ip_address, user_agent, created_at)
               VALUES (?, ?, ?, ?, ?, ?);""",
            (user_id, email, event, ip, ua, _now_iso()),
        )
        conn.commit()
    finally:
        conn.close()

def _mark_login_success(user_id: int) -> None:
    conn = get_connection()
    try:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?;", (_now_iso(), user_id))
        conn.commit()
    finally:
        conn.close()


def seed_bootstrap_admin() -> bool:
    """
    Idempotently ensure the bootstrap admin account exists with
    role='admin' — called from server.py's startup lifespan so it's
    demoable with zero manual setup. Runs on every startup but only ever
    INSERTs once: an existing row's password is never touched, so a judge
    changing the seeded password mid-demo isn't silently reverted on the
    next restart. Returns True if a new row was created.
    """
    email = "nick@gmail.com"
    password = "Hero44@55"

    conn = get_connection()
    try:
        existing = conn.execute("SELECT id, role FROM users WHERE email = ?;", (email,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users (email, password_hash, created_at, role) VALUES (?, ?, ?, 'admin');",
                (email, hash_password(password), _now_iso()),
            )
            conn.commit()
            return True
        if existing["role"] != "admin":
            conn.execute("UPDATE users SET role = 'admin' WHERE id = ?;", (existing["id"],))
            conn.commit()
        return False
    finally:
        conn.close()


# ---- Helper: Extract user from token ------------------------------------

def get_current_user(authorization: str = Header(None)) -> dict:
    """
    Extract and verify the current user from the Authorization header.

    Raises HTTPException 401 if token is missing or invalid, 403 if the
    account has been deactivated. The deactivation check lives here — the
    single choke point every protected route already passes through —
    rather than only at login, so an admin's "deactivate user" action
    takes effect immediately instead of waiting out the token's 24h life.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = authorization.replace("Bearer ", "")
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    conn = get_connection()
    try:
        row = conn.execute("SELECT is_active FROM users WHERE id = ?;", (int(payload["sub"]),)).fetchone()
    finally:
        conn.close()
    if row is not None and not row["is_active"]:
        raise HTTPException(status_code=403, detail="This account has been deactivated")

    return payload


# ---- Routes --------------------------------------------------------------

@router.post("/register", response_model=TokenResponse)
async def register(body: RegisterRequest):
    """Register a new user (mirrored into Supabase Auth if configured) and
    return an access token. MFA is opt-in afterward via /auth/mfa/enroll."""
    email = body.email.strip().lower()
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    conn = get_connection()
    try:
        existing = conn.execute("SELECT id FROM users WHERE email = ?;", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        supabase_uid = None
        if supabase_client.is_configured():
            sb_user = await supabase_client.create_user(email, body.password)
            if sb_user:
                supabase_uid = sb_user.get("id")

        role = "admin" if email in _admin_emails() else "user"
        pw_hash = hash_password(body.password)
        cursor = conn.execute(
            """INSERT INTO users (email, password_hash, created_at, role, supabase_uid)
               VALUES (?, ?, ?, ?, ?);""",
            (email, pw_hash, _now_iso(), role, supabase_uid),
        )
        conn.commit()
        user_id = cursor.lastrowid
    finally:
        conn.close()

    _write_login_audit(user_id, email, "register")
    token = create_access_token(user_id, email)
    return TokenResponse(token=token, email=email, user_id=user_id, role=role, mfa_enabled=False)


@router.post("/login")
async def login(body: LoginRequest, request: Request):
    """
    Authenticate a user and return an access token — or, if the account has
    MFA enabled, a short-lived challenge token instead (see
    POST /auth/mfa/verify to complete login).
    """
    email = body.email.strip().lower()

    conn = get_connection()
    try:
        user = conn.execute(
            """SELECT id, email, password_hash, role, is_active, mfa_enabled,
                      mfa_secret, supabase_uid
               FROM users WHERE email = ?;""",
            (email,),
        ).fetchone()
        # Opportunistic cleanup of stale challenges — same "delete expired
        # rows in passing" idiom the codebase already uses for scan_cache.
        conn.execute("DELETE FROM mfa_challenges WHERE expires_at < ?;", (_now_iso(),))
        conn.commit()
    finally:
        conn.close()

    if user is None:
        _write_login_audit(None, email, "login_failed_unknown_email", request)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user["is_active"]:
        _write_login_audit(user["id"], email, "login_blocked_inactive", request)
        raise HTTPException(status_code=403, detail="This account has been deactivated")

    # Route by whether THIS user has a Supabase identity, not by whether
    # Supabase is configured at all — an outage or a not-yet-migrated user
    # must never flip onto an auth path that hasn't been exercised for them.
    verified = False
    if user["supabase_uid"] and supabase_client.is_configured():
        sb_result = await supabase_client.password_login(email, body.password)
        verified = sb_result is not None
        if not verified:
            # Could be a genuinely wrong password, or Supabase being
            # unreachable — either way, the local mirror hash is the
            # honest fallback rather than hard-failing the login.
            verified = verify_password(body.password, user["password_hash"])
    else:
        verified = verify_password(body.password, user["password_hash"])

    if not verified:
        _write_login_audit(user["id"], email, "login_failed_bad_password", request)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user["mfa_enabled"]:
        challenge_token = secrets.token_urlsafe(32)
        expires_at = (_now() + timedelta(minutes=MFA_CHALLENGE_TTL_MINUTES)).isoformat()
        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO mfa_challenges (token, user_id, expires_at, attempt_count, created_at)
                   VALUES (?, ?, ?, 0, ?);""",
                (challenge_token, user["id"], expires_at, _now_iso()),
            )
            conn.commit()
        finally:
            conn.close()
        _write_login_audit(user["id"], email, "password_verified_mfa_pending", request)
        return {"mfa_required": True, "challenge_token": challenge_token}

    _mark_login_success(user["id"])
    _write_login_audit(user["id"], email, "login_success", request)
    token = create_access_token(user["id"], user["email"])
    return TokenResponse(
        token=token, email=user["email"], user_id=user["id"],
        role=user["role"], mfa_enabled=bool(user["mfa_enabled"]),
    )


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify(body: MfaVerifyRequest, request: Request):
    """Complete a login that returned mfa_required by submitting the
    6-digit authenticator code alongside the challenge token it issued."""
    conn = get_connection()
    try:
        challenge = conn.execute(
            "SELECT token, user_id, expires_at, attempt_count FROM mfa_challenges WHERE token = ?;",
            (body.challenge_token,),
        ).fetchone()
        if challenge is None:
            raise HTTPException(status_code=401, detail="Invalid or expired verification request — please log in again")

        if datetime.fromisoformat(challenge["expires_at"]) < _now():
            conn.execute("DELETE FROM mfa_challenges WHERE token = ?;", (body.challenge_token,))
            conn.commit()
            raise HTTPException(status_code=401, detail="Verification window expired — please log in again")

        if challenge["attempt_count"] >= MFA_MAX_ATTEMPTS:
            conn.execute("DELETE FROM mfa_challenges WHERE token = ?;", (body.challenge_token,))
            conn.commit()
            raise HTTPException(status_code=429, detail="Too many incorrect attempts — please log in again")

        user = conn.execute(
            "SELECT id, email, role, mfa_enabled, mfa_secret FROM users WHERE id = ?;",
            (challenge["user_id"],),
        ).fetchone()
        if user is None or not user["mfa_enabled"]:
            conn.execute("DELETE FROM mfa_challenges WHERE token = ?;", (body.challenge_token,))
            conn.commit()
            raise HTTPException(status_code=401, detail="MFA is not active for this account")

        if not mfa.verify_code(user["mfa_secret"], body.code):
            conn.execute(
                "UPDATE mfa_challenges SET attempt_count = attempt_count + 1 WHERE token = ?;",
                (body.challenge_token,),
            )
            conn.commit()
            _write_login_audit(user["id"], user["email"], "mfa_failed", request)
            raise HTTPException(status_code=401, detail="Invalid authentication code")

        conn.execute("DELETE FROM mfa_challenges WHERE token = ?;", (body.challenge_token,))
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?;", (_now_iso(), user["id"]))
        conn.commit()
    finally:
        conn.close()

    _write_login_audit(user["id"], user["email"], "mfa_verified", request)
    token = create_access_token(user["id"], user["email"])
    return TokenResponse(token=token, email=user["email"], user_id=user["id"], role=user["role"], mfa_enabled=True)


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(authorization: str = Header(None)):
    """Start MFA enrollment: generates a pending secret + QR code. The
    account isn't protected yet — call /auth/mfa/activate with one correct
    code first, so a mistyped/mis-scanned secret can never lock a user out."""
    current = get_current_user(authorization)
    user_id = int(current["sub"])

    secret = mfa.generate_secret()
    conn = get_connection()
    try:
        row = conn.execute("SELECT email, mfa_enabled FROM users WHERE id = ?;", (user_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")
        if row["mfa_enabled"]:
            raise HTTPException(status_code=409, detail="MFA is already enabled on this account")
        conn.execute("UPDATE users SET mfa_pending_secret = ? WHERE id = ?;", (secret, user_id))
        conn.commit()
        email = row["email"]
    finally:
        conn.close()

    return MfaEnrollResponse(
        secret=secret,
        otpauth_uri=mfa.provisioning_uri(secret, email),
        qr_png_base64=mfa.provisioning_qr_png_base64(secret, email),
    )


@router.post("/mfa/activate")
async def mfa_activate(body: MfaActivateRequest, authorization: str = Header(None)):
    """Confirm enrollment with one valid code from the authenticator app —
    only then does the account actually require MFA at login."""
    current = get_current_user(authorization)
    user_id = int(current["sub"])

    conn = get_connection()
    try:
        row = conn.execute("SELECT email, mfa_pending_secret FROM users WHERE id = ?;", (user_id,)).fetchone()
        if row is None or not row["mfa_pending_secret"]:
            raise HTTPException(status_code=400, detail="No pending MFA enrollment — call /auth/mfa/enroll first")
        if not mfa.verify_code(row["mfa_pending_secret"], body.code):
            raise HTTPException(status_code=401, detail="Invalid authentication code")
        conn.execute(
            """UPDATE users SET mfa_enabled = 1, mfa_secret = mfa_pending_secret, mfa_pending_secret = NULL
               WHERE id = ?;""",
            (user_id,),
        )
        conn.commit()
        email = row["email"]
    finally:
        conn.close()

    _write_login_audit(user_id, email, "mfa_enabled")
    return {"mfa_enabled": True}


@router.post("/mfa/disable")
async def mfa_disable(body: MfaDisableRequest, authorization: str = Header(None)):
    """Turn MFA back off — requires the current password as proof of
    presence, since this removes a security control."""
    current = get_current_user(authorization)
    user_id = int(current["sub"])

    conn = get_connection()
    try:
        row = conn.execute("SELECT email, password_hash FROM users WHERE id = ?;", (user_id,)).fetchone()
        if row is None or not verify_password(body.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Incorrect password")
        conn.execute(
            "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_pending_secret = NULL WHERE id = ?;",
            (user_id,),
        )
        conn.commit()
        email = row["email"]
    finally:
        conn.close()

    _write_login_audit(user_id, email, "mfa_disabled")
    return {"mfa_enabled": False}


@router.get("/me")
async def get_me(authorization: str = Header(None)):
    """Return the current user's info, including role and MFA status, from
    their JWT token plus the local user row it identifies."""
    current = get_current_user(authorization)
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT role, mfa_enabled FROM users WHERE id = ?;", (int(current["sub"]),)
        ).fetchone()
    finally:
        conn.close()
    return {
        "user_id": int(current["sub"]),
        "email": current["email"],
        "role": row["role"] if row else "user",
        "mfa_enabled": bool(row["mfa_enabled"]) if row else False,
    }
