"""
JWT handler — create and verify JSON Web Tokens.
"""

import jwt
import os
from datetime import datetime, timezone, timedelta

# Secret key — in production, use a secure environment variable
SECRET_KEY = os.getenv("JWT_SECRET", "quantum-crypto-platform-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24


def create_access_token(user_id: int, email: str) -> str:
    """
    Create a JWT access token.

    Parameters
    ----------
    user_id : int
        The user's database ID.
    email : str
        The user's email address.

    Returns
    -------
    str
        Encoded JWT token string.
    """
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Verify and decode a JWT token.

    Returns
    -------
    dict or None
        Decoded payload with ``sub`` (user_id) and ``email``,
        or None if the token is invalid/expired.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
