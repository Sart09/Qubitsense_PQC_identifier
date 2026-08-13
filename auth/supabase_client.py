"""
Supabase Auth client — thin REST wrapper over httpx, no Supabase SDK
dependency (matches how backend/server.py already talks to Groq: raw
httpx calls, not a vendor SDK).

Every function is inert when SUPABASE_URL / SUPABASE_ANON_KEY /
SUPABASE_SERVICE_ROLE_KEY are unset, so the app runs entirely on local
bcrypt auth (unchanged) until a free Supabase project is created and its
keys are pasted into .env — see .env.example. No other code change is
needed to activate it at that point; auth_routes.py calls into this module
unconditionally and branches on is_configured()/the result it gets back.
"""

import os

import httpx

TIMEOUT = httpx.Timeout(5.0)


def _config() -> tuple[str, str, str]:
    url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    anon_key = os.getenv("SUPABASE_ANON_KEY", "").strip()
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    return url, anon_key, service_key


def is_configured() -> bool:
    """True once a project URL and anon key are present — the minimum
    needed to verify a login. Registration additionally needs the
    service-role key, checked separately in create_user()."""
    url, anon_key, _ = _config()
    return bool(url and anon_key)


async def create_user(email: str, password: str) -> dict | None:
    """
    Create a user directly in Supabase Auth via the Admin API.

    email_confirm is always sent as True: this app has no email delivery,
    so without it every subsequent password-grant login would fail with
    "email not confirmed" the moment a real project is connected — a
    feature that would look wired up but silently never work.

    Returns the created Supabase user dict (its "id" is the UUID to mirror
    locally as users.supabase_uid) on success, or None if Supabase isn't
    configured for admin operations or the call fails — callers treat None
    as "continue with local-only registration," never as a fatal error.
    """
    url, _, service_key = _config()
    if not url or not service_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                f"{url}/auth/v1/admin/users",
                headers={
                    "apikey": service_key,
                    "Authorization": f"Bearer {service_key}",
                    "Content-Type": "application/json",
                },
                json={"email": email, "password": password, "email_confirm": True},
            )
        if resp.status_code in (200, 201):
            return resp.json()
        return None
    except httpx.HTTPError:
        return None


async def password_login(email: str, password: str) -> dict | None:
    """
    Verify a password against Supabase Auth's password grant.

    Returns the token response dict on success (its "user" field carries
    the Supabase identity), or None on invalid credentials, missing
    config, or a network/timeout error. auth_routes.py falls back to the
    local bcrypt hash whenever this returns None, so a dropped connection
    mid-demo degrades to local verification rather than hanging or 500ing.
    """
    url, anon_key, _ = _config()
    if not url or not anon_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                f"{url}/auth/v1/token",
                params={"grant_type": "password"},
                headers={"apikey": anon_key, "Content-Type": "application/json"},
                json={"email": email, "password": password},
            )
        if resp.status_code == 200:
            return resp.json()
        return None
    except httpx.HTTPError:
        return None
