"""
crypto.nonce — Anti-replay protection and timestamp window validation.

Crypto concept: Challenge-response / Nonce table and time-bounded acceptance window.
Threat mitigated: Request replay attacks, delayed packet injection.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto.models import UsedNonce


def validate_timestamp(
    ts: int | float | str | datetime,
    window_seconds: int = 60,
    now: datetime | None = None,
) -> tuple[bool, str | None]:
    """
    Validate that timestamp is within acceptance window: |now - ts| <= window_seconds.
    """
    current_time = now or datetime.now(UTC)
    current_epoch = current_time.timestamp()

    if isinstance(ts, (int, float)):
        ts_epoch = float(ts)
        # If timestamp is in milliseconds (e.g. from JS Date.now()), convert to seconds
        if ts_epoch > 1e11:
            ts_epoch /= 1000.0
    elif isinstance(ts, str):
        try:
            # Check if string is float/int
            ts_epoch = float(ts)
            if ts_epoch > 1e11:
                ts_epoch /= 1000.0
        except ValueError:
            # Try ISO format
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            ts_epoch = dt.timestamp()
    elif isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        ts_epoch = ts.timestamp()
    else:
        return False, "Invalid timestamp type"

    delta = abs(current_epoch - ts_epoch)
    if delta > window_seconds:
        return (
            False,
            f"Timestamp outside acceptance window (skew={delta:.1f}s, allowed={window_seconds}s)",
        )

    return True, None


async def check_and_record_nonce(
    session: AsyncSession,
    nonce: str,
    user_id: uuid.UUID,
    window_seconds: int = 60,
) -> tuple[bool, str | None]:
    """
    Atomically verify that nonce has not been used, and record it into used_nonces.

    Returns:
        (is_valid: bool, error_reason: str | None)
    """
    if not nonce or not nonce.strip():
        return False, "Nonce cannot be empty"

    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=window_seconds)

    # Check existence
    stmt = select(UsedNonce).where(UsedNonce.nonce == nonce)
    existing = (await session.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        return False, "Replay attack detected: nonce already consumed"

    used = UsedNonce(nonce=nonce, user_id=user_id, expires_at=expires_at)
    session.add(used)
    try:
        await session.flush()
    except IntegrityError:
        return False, "Replay attack detected: duplicate nonce"

    return True, None
