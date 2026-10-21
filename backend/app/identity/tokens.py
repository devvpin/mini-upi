"""
identity.tokens — JWT access tokens and hashed rotating refresh tokens.

Crypto concept: Ephemeral bearer tokens with cryptographic signing (JWT HMAC-SHA256)
and rotating refresh tokens hashed at rest (SHA-256). Token family revocation on replay
detects and neutralises stolen refresh tokens.

Threat mitigated: Token theft window limitation (15 min access token) and detection of
replayed refresh tokens.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.core.config import get_settings
from app.core.errors import auth_failed


def create_access_token(
    user_id: uuid.UUID,
    college_id: str,
    role: str,
    *,
    ttl_minutes: int | None = None,
) -> str:
    """Create a signed JWT access token with 15-minute TTL."""
    settings = get_settings()
    ttl = ttl_minutes if ttl_minutes is not None else settings.token_ttl_minutes
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "college_id": college_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl)).timestamp()),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT access token.
    Raises auth_failed if invalid, expired, or wrong type.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            options={"require": ["exp", "sub", "role"]},
        )
        if payload.get("type") != "access":
            raise auth_failed("Invalid token type.")
        return payload
    except jwt.ExpiredSignatureError:
        raise auth_failed("Token has expired.") from None
    except jwt.InvalidTokenError:
        raise auth_failed("Invalid token.") from None


def hash_token(raw_token: str) -> str:
    """Hash a refresh token using SHA-256 for safe storage at rest."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_raw_refresh_token() -> str:
    """Generate a high-entropy cryptographically secure refresh token string."""
    return secrets.token_urlsafe(48)
