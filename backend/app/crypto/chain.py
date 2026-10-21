"""
crypto.chain — Tamper-evident hash-chained audit ledger.

Crypto concept: Merkle-style sequential hash chain with HMAC authentication.
Threat mitigated: Log truncation, history rewriting, selective omission, silent edits.

Each entry binds strictly to the previous entry:
    entry_hash = SHA256(prev_hash || canonical(payload) || created_at_iso)
    entry_hmac = HMAC(K_audit, entry_hash)
Genesis block:
    prev_hash = 32 zero bytes
"""

from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto.canonical import canonical_json
from app.crypto.models import AuditLog

GENESIS_PREV_HASH = b"\x00" * 32


def _to_iso(dt: datetime) -> str:
    """Format datetime into consistent UTC ISO-8601 string."""
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return dt.isoformat()


def compute_entry_hash(
    prev_hash: bytes,
    payload: Any,
    created_at_iso: str,
) -> bytes:
    """
    Compute SHA-256 hash: SHA256(prev_hash || canonical(payload) || created_at_iso).
    """
    data = prev_hash + canonical_json(payload) + created_at_iso.encode("utf-8")
    return sha256(data).digest()


def compute_entry_hmac(
    audit_key: bytes,
    entry_hash: bytes,
) -> bytes:
    """
    Compute HMAC-SHA256 authentication tag over entry hash.
    """
    return hmac.new(audit_key, entry_hash, sha256).digest()


async def append_audit_entry(
    session: AsyncSession,
    event_type: str,
    payload: dict[str, Any],
    audit_hmac_key: bytes,
    actor_user_id: uuid.UUID | None = None,
    txn_id: uuid.UUID | None = None,
) -> AuditLog:
    """
    Append an entry to the audit hash chain.
    """
    # Fetch the last entry in the chain
    stmt = select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)
    result = await session.execute(stmt)
    last_entry = result.scalar_one_or_none()

    prev_hash = last_entry.entry_hash if last_entry is not None else GENESIS_PREV_HASH
    now = datetime.now(UTC)
    now_iso = _to_iso(now)

    entry_hash = compute_entry_hash(prev_hash, payload, now_iso)
    entry_hmac = compute_entry_hmac(audit_hmac_key, entry_hash)

    log_entry = AuditLog(
        event_type=event_type,
        txn_id=txn_id,
        actor_user_id=actor_user_id,
        payload_json=payload,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        entry_hmac=entry_hmac,
        created_at=now,
    )
    session.add(log_entry)
    await session.flush()
    return log_entry


async def verify_audit_chain(
    session: AsyncSession,
    audit_hmac_key: bytes,
) -> dict[str, Any]:
    """
    Walk and verify the integrity of the audit hash chain from genesis to head.

    Returns:
        {
            "ok": bool,
            "head_hash": str | None,
            "checked": int,
            "first_bad_seq": int | None,
            "error": str | None,
        }
    """
    stmt = select(AuditLog).order_by(AuditLog.seq.asc())
    result = await session.execute(stmt)
    entries = list(result.scalars().all())

    if not entries:
        return {
            "ok": True,
            "head_hash": GENESIS_PREV_HASH.hex(),
            "checked": 0,
            "first_bad_seq": None,
            "error": None,
        }

    expected_prev_hash = GENESIS_PREV_HASH
    checked_count = 0

    for entry in entries:
        checked_count += 1
        seq = entry.seq

        # 1. Verify linkage to previous entry
        if entry.prev_hash != expected_prev_hash:
            return {
                "ok": False,
                "head_hash": None,
                "checked": checked_count,
                "first_bad_seq": seq,
                "error": (
                    f"Chain link broken at seq={seq}: expected prev_hash "
                    f"{expected_prev_hash.hex()[:16]}, got {entry.prev_hash.hex()[:16]}"
                ),
            }

        # 2. Recalculate entry hash
        entry_iso = _to_iso(entry.created_at)
        recalculated_hash = compute_entry_hash(
            entry.prev_hash, entry.payload_json, entry_iso
        )
        if entry.entry_hash != recalculated_hash:
            return {
                "ok": False,
                "head_hash": None,
                "checked": checked_count,
                "first_bad_seq": seq,
                "error": f"Hash integrity failure at seq={seq}: payload or metadata modified",
            }

        # 3. Recalculate HMAC
        recalculated_hmac = compute_entry_hmac(audit_hmac_key, entry.entry_hash)
        if not hmac.compare_digest(entry.entry_hmac, recalculated_hmac):
            return {
                "ok": False,
                "head_hash": None,
                "checked": checked_count,
                "first_bad_seq": seq,
                "error": f"HMAC authentication failure at seq={seq}: entry signature invalid",
            }

        expected_prev_hash = entry.entry_hash

    return {
        "ok": True,
        "head_hash": entries[-1].entry_hash.hex(),
        "checked": checked_count,
        "first_bad_seq": None,
        "error": None,
    }
