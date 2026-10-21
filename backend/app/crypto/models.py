"""
crypto.models — SQLAlchemy models for audit log hash chain, nonces, and certificates.

Crypto concept: Immutable hash-chained audit ledger, replay nonce tracking, and PKI cert store.
Threat mitigated: Log tampering, replay attacks, untrusted service keys.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.identity.models import Base


class UsedNonce(Base):
    """
    Tracks nonces used in transaction / request signing to prevent replay attacks.
    Nonces expire after the timestamp acceptance window (e.g., 60 seconds).
    """

    __tablename__ = "used_nonces"

    nonce: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class AuditLog(Base):
    """
    Hash-chained tamper-evident audit ledger.
    Every entry binds to the preceding entry hash:
        entry_hash = SHA256(prev_hash || canonical(payload_json) || created_at_iso)
        entry_hmac = HMAC(K_audit, entry_hash)
    """

    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    txn_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True
    )
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    entry_hmac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PkiCertificate(Base):
    """
    X.509 certificates issued by Mini-CA for core actors (PSP, Switch, Bank).
    """

    __tablename__ = "pki_certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    not_before: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    not_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
