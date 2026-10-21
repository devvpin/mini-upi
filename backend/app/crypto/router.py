"""
crypto.router — Cryptographic endpoints for device binding, MPIN management, and PKI.

Crypto concept: Device-bound credentials, hardware-rooted authentication,
Argon2id MPIN verification with rate-limiting and audit trail.
Threat mitigated: Token theft from web clients, brute-force PIN guessing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.crypto.chain import append_audit_entry
from app.crypto.kdf import hash_secret, verify_dummy, verify_secret
from app.crypto.server_key import get_server_key_payload
from app.crypto.signing import jwk_to_public_key
from app.identity.deps import get_current_user
from app.identity.models import Device, MpinCredential, RefreshToken, User

router = APIRouter(tags=["crypto"])


class DeviceRegisterRequest(BaseModel):
    public_key_jwk: dict[str, Any]
    label: str | None = Field(default=None, max_length=128)


class DeviceResponse(BaseModel):
    id: uuid.UUID
    label: str | None
    status: str
    public_key_jwk: dict[str, Any]
    created_at: datetime
    revoked_at: datetime | None


class MpinSetRequest(BaseModel):
    mpin: str = Field(..., pattern=r"^\d{6}$", description="6-digit numeric MPIN")


class MpinVerifyRequest(BaseModel):
    mpin: str = Field(..., pattern=r"^\d{6}$", description="6-digit numeric MPIN")


@router.get("/crypto/server-key")
async def get_server_key() -> dict[str, Any]:
    """
    Public server cryptographic parameters and CA-signed static ECDH certificate.
    Clients use this key to perform app-layer envelope encryption.
    """
    return get_server_key_payload()


@router.post(
    "/devices/register",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_device(
    payload: DeviceRegisterRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DeviceResponse:
    """
    Register a client device public key (ECDSA P-256 JWK).
    Verifies that the JWK is mathematically valid and on the secp256r1 curve.
    """
    try:
        # Validate that JWK is structurally and mathematically sound
        jwk_to_public_key(payload.public_key_jwk)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid EC P-256 public key JWK: {e}",
        ) from e

    device = Device(
        user_id=current_user.id,
        public_key_jwk=payload.public_key_jwk,
        label=payload.label,
        status="active",
    )
    session.add(device)
    await session.flush()

    settings = get_settings()
    await append_audit_entry(
        session=session,
        event_type="DEVICE_REGISTERED",
        payload={
            "user_id": str(current_user.id),
            "device_id": str(device.id),
            "label": device.label,
        },
        audit_hmac_key=settings.audit_hmac_key.encode("utf-8"),
        actor_user_id=current_user.id,
    )
    await session.commit()

    return DeviceResponse(
        id=device.id,
        label=device.label,
        status=device.status,
        public_key_jwk=device.public_key_jwk,
        created_at=device.created_at,
        revoked_at=device.revoked_at,
    )


@router.get("/devices", response_model=list[DeviceResponse])
async def list_devices(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[DeviceResponse]:
    """List all registered devices for the authenticated user."""
    stmt = (
        select(Device)
        .where(Device.user_id == current_user.id)
        .order_by(Device.created_at.desc())
    )
    result = await session.execute(stmt)
    devices = result.scalars().all()
    return [
        DeviceResponse(
            id=d.id,
            label=d.label,
            status=d.status,
            public_key_jwk=d.public_key_jwk,
            created_at=d.created_at,
            revoked_at=d.revoked_at,
        )
        for d in devices
    ]


@router.delete("/devices/{device_id}")
async def revoke_device(
    device_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """
    Revoke a registered device. Also revokes all refresh tokens bound to it.
    """
    stmt = select(Device).where(
        Device.id == device_id, Device.user_id == current_user.id
    )
    device = (await session.execute(stmt)).scalar_one_or_none()
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    now = datetime.now(UTC)
    device.status = "revoked"
    device.revoked_at = now

    # Revoke bound refresh tokens
    token_stmt = select(RefreshToken).where(RefreshToken.device_id == device_id)
    tokens = (await session.execute(token_stmt)).scalars().all()
    for token in tokens:
        if token.revoked_at is None:
            token.revoked_at = now

    settings = get_settings()
    await append_audit_entry(
        session=session,
        event_type="DEVICE_REVOKED",
        payload={
            "user_id": str(current_user.id),
            "device_id": str(device.id),
        },
        audit_hmac_key=settings.audit_hmac_key.encode("utf-8"),
        actor_user_id=current_user.id,
    )
    await session.commit()

    return {"status": "revoked"}


@router.post("/mpin/set")
async def set_mpin(
    payload: MpinSetRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """
    Configure a 6-digit MPIN for high-security transaction authorization.
    Stored using Argon2id with server-side pepper pre-hash.
    """
    settings = get_settings()
    if settings.app_env == "test":
        mpin_hash = hash_secret(
            payload.mpin, settings.pepper, time_cost=1, memory_cost=1024
        )
    else:
        mpin_hash = hash_secret(payload.mpin, settings.pepper)

    stmt = select(MpinCredential).where(MpinCredential.user_id == current_user.id)
    cred = (await session.execute(stmt)).scalar_one_or_none()
    if cred is None:
        cred = MpinCredential(
            user_id=current_user.id,
            mpin_hash=mpin_hash,
            failed_count=0,
            locked_until=None,
        )
        session.add(cred)
    else:
        cred.mpin_hash = mpin_hash
        cred.failed_count = 0
        cred.locked_until = None

    await append_audit_entry(
        session=session,
        event_type="MPIN_SET",
        payload={"user_id": str(current_user.id)},
        audit_hmac_key=settings.audit_hmac_key.encode("utf-8"),
        actor_user_id=current_user.id,
    )
    await session.commit()

    return {"status": "mpin_configured"}


@router.post("/mpin/verify")
async def verify_mpin(
    payload: MpinVerifyRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Verify MPIN with timing equalization and rate-limiting lockout:
    - 3 consecutive failures locks the MPIN for 15 minutes.
    - Subsequent lockouts apply exponential back-off.
    - Every failure is recorded in the immutable audit trail.
    """
    settings = get_settings()
    now = datetime.now(UTC)

    stmt = select(MpinCredential).where(MpinCredential.user_id == current_user.id)
    cred = (await session.execute(stmt)).scalar_one_or_none()

    if cred is None:
        # Timing equalisation dummy verification
        verify_dummy(settings.pepper)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MPIN not configured for this user",
        )

    # Check lockout
    if cred.locked_until is not None:
        locked_until_utc = cred.locked_until
        if locked_until_utc.tzinfo is None:
            locked_until_utc = locked_until_utc.replace(tzinfo=UTC)
        else:
            locked_until_utc = locked_until_utc.astimezone(UTC)

        if now < locked_until_utc:
            remaining_sec = int((locked_until_utc - now).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"MPIN is locked. Please wait {remaining_sec} seconds before retrying.",
            )

    # Verify MPIN
    is_valid = verify_secret(
        payload.mpin, cred.mpin_hash, settings.pepper
    )

    if not is_valid:
        cred.failed_count += 1
        audit_event = "MPIN_FAILED"

        # Lockout after 3 failures
        if cred.failed_count >= 3:
            multiplier = 2 ** min(cred.failed_count - 3, 4)
            lock_duration = timedelta(minutes=15 * multiplier)
            cred.locked_until = now + lock_duration
            audit_event = "MPIN_LOCKED"

        await append_audit_entry(
            session=session,
            event_type=audit_event,
            payload={
                "user_id": str(current_user.id),
                "failed_count": cred.failed_count,
                "locked": cred.locked_until is not None,
            },
            audit_hmac_key=settings.audit_hmac_key.encode("utf-8"),
            actor_user_id=current_user.id,
        )
        await session.commit()

        if cred.locked_until is not None:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="MPIN locked due to 3 consecutive failed attempts. Try again in 15 minutes.",
            )

        remaining_attempts = 3 - cred.failed_count
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Incorrect MPIN. {remaining_attempts} attempts remaining before lockout.",
        )

    # Success: reset failed counters
    cred.failed_count = 0
    cred.locked_until = None
    await session.commit()

    return {"status": "ok", "message": "MPIN verified successfully"}
