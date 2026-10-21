"""
bank.models — SQLAlchemy models for banking accounts, wallets, VPAs, and the double-entry ledger.

Crypto concept: Immutable double-entry financial ledger enforcing conservation of money.
Threat mitigated: Double-spending, balance manipulation, arithmetic overflow, race conditions.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.identity.models import Base, User


class AccountStatus(enum.StrEnum):
    ACTIVE = "active"
    FROZEN = "frozen"


class TxnStatus(enum.StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


class TxnKind(enum.StrEnum):
    PAY = "PAY"
    COLLECT_SETTLE = "COLLECT_SETTLE"
    TOPUP = "TOPUP"


class LedgerDirection(enum.StrEnum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class CollectStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"
    EXPIRED = "expired"


class BankAccount(Base):
    __tablename__ = "bank_accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), unique=True, nullable=True
    )
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[AccountStatus] = mapped_column(
        String(32), default=AccountStatus.ACTIVE, nullable=False
    )

    user: Mapped[User | None] = relationship("User")
    wallet: Mapped[Wallet | None] = relationship(
        "Wallet", back_populates="account", uselist=False, cascade="all, delete-orphan"
    )
    vpas: Mapped[list[Vpa]] = relationship(
        "Vpa", back_populates="account", cascade="all, delete-orphan"
    )


class Wallet(Base):
    __tablename__ = "wallets"

    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("bank_accounts.id"), primary_key=True
    )
    balance_paise: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    account: Mapped[BankAccount] = relationship("BankAccount", back_populates="wallet")


class Vpa(Base):
    __tablename__ = "vpas"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("bank_accounts.id"), nullable=False
    )
    handle: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    account: Mapped[BankAccount] = relationship("BankAccount", back_populates="vpas")


class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        CheckConstraint("amount_paise > 0", name="chk_txn_amount_positive"),
        CheckConstraint("payer_account_id <> payee_account_id", name="chk_distinct_parties"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    kind: Mapped[TxnKind] = mapped_column(String(32), nullable=False)
    payer_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("bank_accounts.id"), nullable=False, index=True
    )
    payee_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("bank_accounts.id"), nullable=False, index=True
    )
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[TxnStatus] = mapped_column(
        String(32), default=TxnStatus.PENDING, nullable=False
    )
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    receipt_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    receipt_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    payer_account: Mapped[BankAccount] = relationship(
        "BankAccount", foreign_keys=[payer_account_id]
    )
    payee_account: Mapped[BankAccount] = relationship(
        "BankAccount", foreign_keys=[payee_account_id]
    )
    ledger_entries: Mapped[list[LedgerEntry]] = relationship(
        "LedgerEntry", back_populates="transaction"
    )


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    __table_args__ = (
        CheckConstraint("amount_paise > 0", name="chk_ledger_amount_positive"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    txn_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("transactions.id"), nullable=False
    )
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("bank_accounts.id"), nullable=False, index=True
    )
    direction: Mapped[LedgerDirection] = mapped_column(String(16), nullable=False)
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    balance_after_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    transaction: Mapped[Transaction] = relationship(
        "Transaction", back_populates="ledger_entries"
    )
    account: Mapped[BankAccount] = relationship("BankAccount")


class CollectRequest(Base):
    __tablename__ = "collect_requests"
    __table_args__ = (
        CheckConstraint("amount_paise > 0", name="chk_collect_amount_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    requester_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("bank_accounts.id"), nullable=False
    )
    payer_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("bank_accounts.id"), nullable=False
    )
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CollectStatus] = mapped_column(
        String(32), default=CollectStatus.PENDING, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    requester_account: Mapped[BankAccount] = relationship(
        "BankAccount", foreign_keys=[requester_account_id]
    )
    payer_account: Mapped[BankAccount] = relationship(
        "BankAccount", foreign_keys=[payer_account_id]
    )
