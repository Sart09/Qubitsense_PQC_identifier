"""
Authentication API routes — register, login, and user-related endpoints.
Mounted as a sub-router on the main FastAPI app.
"""

import os
import sys

# Ensure auth modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, EmailStr

from password_utils import hash_password, verify_password
from jwt_handler import create_access_token, verify_token

# Use the backend database helper
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
from database import get_connection

router = APIRouter(prefix="/auth", tags=["Authentication"])


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


# ---- Helper: Extract user from token ------------------------------------

def get_current_user(authorization: str = Header(None)) -> dict:
    """
    Extract and verify the current user from the Authorization header.

    Raises HTTPException 401 if token is missing or invalid.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = authorization.replace("Bearer ", "")
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return payload


# ---- Routes --------------------------------------------------------------

@router.post("/register", response_model=TokenResponse)
async def register(request: RegisterRequest):
    """Register a new user and return an access token."""
    email = request.email.strip().lower()
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?;", (email,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        pw_hash = hash_password(request.password)
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?);",
            (email, pw_hash, now),
        )
        conn.commit()
        user_id = cursor.lastrowid
    finally:
        conn.close()

    token = create_access_token(user_id, email)
    return TokenResponse(token=token, email=email, user_id=user_id)


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Authenticate a user and return an access token."""
    email = request.email.strip().lower()

    conn = get_connection()
    try:
        user = conn.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?;",
            (email,),
        ).fetchone()
    finally:
        conn.close()

    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user["id"], user["email"])
    return TokenResponse(token=token, email=user["email"], user_id=user["id"])


@router.get("/me")
async def get_me(authorization: str = Header(None)):
    """Return the current user's info from their JWT token."""
    user = get_current_user(authorization)
    return {"user_id": int(user["sub"]), "email": user["email"]}
