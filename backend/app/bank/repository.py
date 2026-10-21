"""
bank.repository — Database access layer for accounts, wallets, VPAs, and transactions.

Crypto concept: Strict isolation of financial state; deadlock prevention via deterministic
resource ordering; row-level locking for atomicity.
Threat mitigated: Race conditions, deadlocks, unauthorized balance modification.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.bank.models import (
    AccountStatus,
    BankAccount,
    Transaction,
    Vpa,
    Wallet,
)
from app.identity.models import User

TREASURY_ACCOUNT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


async def get_or_create_treasury(session: AsyncSession) -> BankAccount:
    """Ensure the system TREASURY account and wallet exist."""
    stmt = select(BankAccount).where(BankAccount.id == TREASURY_ACCOUNT_ID)
    res = await session.execute(stmt)
    account = res.scalar_one_or_none()

    if account is None:
        account = BankAccount(
            id=TREASURY_ACCOUNT_ID,
            user_id=None,
            is_system=True,
            status=AccountStatus.ACTIVE,
        )
        session.add(account)
        await session.flush()

        wallet = Wallet(account_id=account.id, balance_paise=0)
        session.add(wallet)
        await session.flush()

    return account


async def get_account_by_user_id(
    session: AsyncSession, user_id: uuid.UUID
) -> BankAccount | None:
    """Get the active bank account for a user."""
    stmt = (
        select(BankAccount)
        .options(
            selectinload(BankAccount.wallet),
            selectinload(BankAccount.vpas),
            selectinload(BankAccount.user),
        )
        .where(BankAccount.user_id == user_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def get_or_create_account_for_user(
    session: AsyncSession,
    user: User,
    vpa_suffix: str = "gcet",
    initial_balance: int = 0,
) -> tuple[BankAccount, Vpa]:
    """
    Get or create a bank account, wallet, and primary VPA for a user.
    """
    account = await get_account_by_user_id(session, user.id)
    if account is not None and account.vpas:
        return account, account.vpas[0]

    if account is None:
        account = BankAccount(
            user_id=user.id,
            is_system=False,
            status=AccountStatus.ACTIVE,
        )
        session.add(account)
        await session.flush()

        wallet = Wallet(account_id=account.id, balance_paise=initial_balance)
        session.add(wallet)
        await session.flush()

    handle = f"{user.college_id.lower()}@{vpa_suffix.lower()}"
    vpa = Vpa(
        account_id=account.id,
        handle=handle,
        is_primary=True,
    )
    session.add(vpa)
    await session.flush()

    # Re-query with relations loaded
    account = await get_account_by_user_id(session, user.id)
    assert account is not None
    return account, vpa


async def get_vpa_by_handle(session: AsyncSession, handle: str) -> Vpa | None:
    """Look up a VPA handle with account and user eager loaded."""
    stmt = (
        select(Vpa)
        .options(
            selectinload(Vpa.account).selectinload(BankAccount.user),
            selectinload(Vpa.account).selectinload(BankAccount.wallet),
        )
        .where(Vpa.handle == handle.strip().lower())
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def get_wallet_by_account_id(
    session: AsyncSession, account_id: uuid.UUID
) -> Wallet | None:
    stmt = select(Wallet).where(Wallet.account_id == account_id)
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def lock_wallets_ordered(
    session: AsyncSession,
    account_id_1: uuid.UUID,
    account_id_2: uuid.UUID,
) -> tuple[Wallet, Wallet]:
    """
    Lock two wallets with SELECT ... FOR UPDATE ordered by account UUID.
    Guarantees deadlock-free execution under high concurrency.
    Returns (wallet_1, wallet_2) in the requested order.
    """
    if account_id_1 == account_id_2:
        raise ValueError("Cannot transfer to the same account.")

    # Determine deterministic acquisition order
    first_id, second_id = (
        (account_id_1, account_id_2)
        if account_id_1 < account_id_2
        else (account_id_2, account_id_1)
    )

    # Acquire first lock
    stmt_first = (
        select(Wallet)
        .options(selectinload(Wallet.account))
        .where(Wallet.account_id == first_id)
        .with_for_update()
    )
    res_first = await session.execute(stmt_first)
    w_first = res_first.scalar_one_or_none()

    # Acquire second lock
    stmt_second = (
        select(Wallet)
        .options(selectinload(Wallet.account))
        .where(Wallet.account_id == second_id)
        .with_for_update()
    )
    res_second = await session.execute(stmt_second)
    w_second = res_second.scalar_one_or_none()

    if w_first is None or w_second is None:
        raise ValueError("One or both wallets not found.")

    if account_id_1 == first_id:
        return w_first, w_second
    return w_second, w_first


async def get_transaction_by_id(
    session: AsyncSession, txn_id: uuid.UUID
) -> Transaction | None:
    stmt = (
        select(Transaction)
        .options(
            selectinload(Transaction.ledger_entries),
            selectinload(Transaction.payer_account).selectinload(BankAccount.user),
            selectinload(Transaction.payer_account).selectinload(BankAccount.vpas),
            selectinload(Transaction.payee_account).selectinload(BankAccount.user),
            selectinload(Transaction.payee_account).selectinload(BankAccount.vpas),
        )
        .where(Transaction.id == txn_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def list_transactions_for_account(
    session: AsyncSession,
    account_id: uuid.UUID,
    limit: int = 20,
    cursor_created_at: datetime | None = None,
) -> list[Transaction]:
    """Cursor-paginated transactions where account was payer or payee."""
    stmt = (
        select(Transaction)
        .options(
            selectinload(Transaction.payer_account).selectinload(BankAccount.user),
            selectinload(Transaction.payer_account).selectinload(BankAccount.vpas),
            selectinload(Transaction.payee_account).selectinload(BankAccount.user),
            selectinload(Transaction.payee_account).selectinload(BankAccount.vpas),
            selectinload(Transaction.ledger_entries),
        )
        .where(
            (Transaction.payer_account_id == account_id)
            | (Transaction.payee_account_id == account_id)
        )
    )
    if cursor_created_at is not None:
        stmt = stmt.where(Transaction.created_at < cursor_created_at)

    stmt = stmt.order_by(desc(Transaction.created_at)).limit(limit)
    res = await session.execute(stmt)
    return list(res.scalars().all())
