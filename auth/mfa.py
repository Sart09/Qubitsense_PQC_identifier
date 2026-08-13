"""
TOTP multi-factor authentication.

This is our own implementation (pyotp + qrcode), not delegated to
Supabase's native MFA — it works today, with zero external configuration,
regardless of whether Supabase Auth is connected. It layers on top of
whichever identity backend verified the password (see auth_routes.py),
so the second factor never depends on the first factor's provider.
"""

import base64
import io

import pyotp
import qrcode

ISSUER = "PNB Qubitsense"


def generate_secret() -> str:
    """A fresh base32 TOTP secret, stored as users.mfa_pending_secret until
    the enrollment is confirmed with one correct code (see /auth/mfa/activate)."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str) -> str:
    """The otpauth:// URI an authenticator app decodes from the QR code."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def provisioning_qr_png_base64(secret: str, email: str) -> str:
    """Base64-encoded PNG QR code of the provisioning URI, for the frontend
    to render directly as <img src="data:image/png;base64,...">."""
    img = qrcode.make(provisioning_uri(secret, email))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def verify_code(secret: str | None, code: str | None) -> bool:
    """valid_window=1 tolerates the code from one 30s step before/after the
    current one, covering ordinary clock drift without weakening the
    6-digit code's effective validity window past ~90s."""
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False
