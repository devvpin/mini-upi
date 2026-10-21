"""
identity.service — High-level authentication and user credential management.

Crypto concept: Timing equalisation via dummy hashing; token rotation with replay
detection (family revocation); account lockout preventing online brute-force.
Threat mitigated: Timing enumeration, credential brute-forcing, token reuse attacks.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import account_locked, auth_failed
from app.crypto.kdf import hash_secret, needs_rehash, verify_dummy, verify_secret
from app.identity.models import User, UserStatus
from app.identity.repository import (
    create_refresh_token,
    get_refresh_token_by_hash,
    get_user_by_college_id,
    record_login_failure,
    reset_login_failures,
    revoke_refresh_token,
    revoke_token_family,
    update_user_password,
)
from app.identity.tokens import (
    create_access_token,
    generate_raw_refresh_token,
    hash_token,
)


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


async def authenticate_user(
    session: AsyncSession,
    college_id: str,
    password: str,
) -> tuple[User, str, str]:
    """
    Authenticate a user with college ID and password.
    Timing equalised: unknown user runs verify_dummy() so execution time matches
    known user verification.
    """
    settings = get_settings()
    pepper = settings.pepper
    user = await get_user_by_college_id(session, college_id)

    if user is None:
        verify_dummy(pepper)
        raise auth_failed()

    now = datetime.now(UTC)
    user_locked = _to_utc(user.locked_until)

    # Check if locked out due to prior failed attempts
    if user_locked is not None and user_locked > now:
        # Still run verification to keep timing equalized
        verify_secret(password, user.password_hash, pepper)
        raise account_locked("Account is temporarily locked. Please try again later.")

    if user.status != UserStatus.ACTIVE:
        verify_dummy(pepper)
        raise auth_failed()

    is_valid = verify_secret(password, user.password_hash, pepper)

    if not is_valid:
        await record_login_failure(session, user, max_attempts=5, lock_minutes=15)
        await session.commit()
        raise auth_failed()

    # Successful authentication
    await reset_login_failures(session, user)

    # Transparent rehash if hash parameters were upgraded
    if needs_rehash(user.password_hash):
        new_hash = hash_secret(password, pepper)
        user.password_hash = new_hash

    # Generate session tokens
    access_token = create_access_token(
        user_id=user.id,
        college_id=user.college_id,
        role=user.role if isinstance(user.role, str) else user.role.value,
    )
    raw_refresh = generate_raw_refresh_token()
    family_id = uuid.uuid4()
    refresh_expires = now + timedelta(days=30)

    await create_refresh_token(
        session=session,
        user_id=user.id,
        token_hash=hash_token(raw_refresh),
        family_id=family_id,
        expires_at=refresh_expires,
    )
    await session.commit()

    return user, access_token, raw_refresh


async def rotate_session(
    session: AsyncSession,
    raw_refresh_token: str,
) -> tuple[str, str]:
    """
    Rotate a refresh token.
    If the presented token was ALREADY revoked, this indicates a replay/theft attack:
    we immediately revoke the entire family.
    """
    token_hash = hash_token(raw_refresh_token)
    token = await get_refresh_token_by_hash(session, token_hash)

    if token is None:
        raise auth_failed("Invalid session token.")

    # Replay detection: token already revoked!
    if token.revoked_at is not None:
        await revoke_token_family(session, token.family_id)
        await session.commit()
        raise auth_failed("Session token revoked due to suspected replay.")

    now = datetime.now(UTC)
    token_expires = _to_utc(token.expires_at)
    if token_expires is not None and token_expires < now:
        await revoke_refresh_token(session, token)
        await session.commit()
        raise auth_failed("Session token expired.")

    if token.user.status != UserStatus.ACTIVE:
        raise auth_failed("Account is not active.")

    # Revoke current token and issue replacement within same family
    await revoke_refresh_token(session, token)
    new_raw_refresh = generate_raw_refresh_token()
    refresh_expires = now + timedelta(days=30)

    await create_refresh_token(
        session=session,
        user_id=token.user_id,
        token_hash=hash_token(new_raw_refresh),
        family_id=token.family_id,
        expires_at=refresh_expires,
        device_id=token.device_id,
    )

    new_access = create_access_token(
        user_id=token.user_id,
        college_id=token.user.college_id,
        role=token.user.role if isinstance(token.user.role, str) else token.user.role.value,
    )
    await session.commit()

    return new_access, new_raw_refresh


async def logout_session(
    session: AsyncSession,
    raw_refresh_token: str | None,
) -> None:
    """Revoke refresh token on explicit logout."""
    if raw_refresh_token:
        token_hash = hash_token(raw_refresh_token)
        token = await get_refresh_token_by_hash(session, token_hash)
        if token and token.revoked_at is None:
            await revoke_refresh_token(session, token)
            await session.commit()


async def change_password(
    session: AsyncSession,
    user: User,
    current_password: str,
    new_password: str,
) -> None:
    """Change user password after verifying existing password."""
    settings = get_settings()
    pepper = settings.pepper
    if not verify_secret(current_password, user.password_hash, pepper):
        raise auth_failed("Current password is incorrect.")

    new_hash = hash_secret(new_password, pepper)
    await update_user_password(session, user, new_hash)
    await session.commit()
