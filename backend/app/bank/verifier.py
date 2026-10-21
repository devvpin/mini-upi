"""
bank.verifier — Comprehensive ledger integrity and invariant verification.

Crypto concept: Mathematical proof of double-entry integrity (zero-sum invariant)
and deterministic replay of financial history.
Threat mitigated: Silent corruption, balance forgery, undetected ledger tampering.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.bank.models import (
    BankAccount,
    LedgerDirection,
    LedgerEntry,
    Transaction,
    TxnStatus,
    Wallet,
)


@dataclass
class LedgerVerificationReport:
    ok: bool
    total_wallets: int
    sum_wallet_balances_paise: int
    zero_sum_verified: bool
    total_transactions: int
    balanced_entries_verified: bool
    history_replay_verified: bool
    errors: list[str]


async def verify_ledger(session: AsyncSession) -> LedgerVerificationReport:
    """
    Verify all key financial invariants:
    1. Global zero-sum invariant: sum(all wallet balances) == 0
    2. Double-entry parity: each transaction has equal DEBIT and CREDIT entries
    3. Replay consistency: ledger entries for every account reconstruct current balance
    """
    errors: list[str] = []

    # 1. Global Zero-Sum Invariant
    sum_stmt = select(func.coalesce(func.sum(Wallet.balance_paise), 0))
    sum_res = await session.execute(sum_stmt)
    total_balance_paise = int(sum_res.scalar() or 0)

    count_stmt = select(func.count(Wallet.account_id))
    count_res = await session.execute(count_stmt)
    wallet_count = int(count_res.scalar() or 0)

    zero_sum_ok = (total_balance_paise == 0)
    if not zero_sum_ok:
        errors.append(
            f"Zero-sum invariant broken: total wallet balance sum is "
            f"{total_balance_paise} paise (expected 0)."
        )

    # 2. Double-Entry Parity for all successful transactions
    txn_stmt = select(Transaction).where(Transaction.status == TxnStatus.SUCCESS)
    txn_res = await session.execute(txn_stmt)
    transactions = list(txn_res.scalars().all())

    balanced_ok = True
    for txn in transactions:
        entries_stmt = select(LedgerEntry).where(LedgerEntry.txn_id == txn.id)
        entries_res = await session.execute(entries_stmt)
        entries = list(entries_res.scalars().all())

        debits = [e for e in entries if e.direction == LedgerDirection.DEBIT]
        credits = [e for e in entries if e.direction == LedgerDirection.CREDIT]

        if len(debits) != 1 or len(credits) != 1:
            balanced_ok = False
            errors.append(
                f"Transaction {txn.id} has {len(debits)} debits "
                f"and {len(credits)} credits (expected 1 each)."
            )
            continue

        if (
            debits[0].amount_paise != txn.amount_paise
            or credits[0].amount_paise != txn.amount_paise
        ):
            balanced_ok = False
            errors.append(
                f"Transaction {txn.id} entry amount mismatch: expected {txn.amount_paise}, "
                f"got debit={debits[0].amount_paise}, credit={credits[0].amount_paise}."
            )

    # 3. History Replay per Account
    replay_ok = True
    accounts_stmt = select(BankAccount)
    accounts_res = await session.execute(accounts_stmt)
    accounts = list(accounts_res.scalars().all())

    for acc in accounts:
        wallet_stmt = select(Wallet).where(Wallet.account_id == acc.id)
        wallet_res = await session.execute(wallet_stmt)
        wallet = wallet_res.scalar_one_or_none()
        current_balance = wallet.balance_paise if wallet else 0

        entries_stmt = (
            select(LedgerEntry)
            .where(LedgerEntry.account_id == acc.id)
            .order_by(LedgerEntry.id.asc())
        )
        entries_res = await session.execute(entries_stmt)
        acc_entries = list(entries_res.scalars().all())

        recomputed_balance = 0
        for entry in acc_entries:
            if entry.direction == LedgerDirection.CREDIT:
                recomputed_balance += entry.amount_paise
            elif entry.direction == LedgerDirection.DEBIT:
                recomputed_balance -= entry.amount_paise

            if recomputed_balance != entry.balance_after_paise:
                replay_ok = False
                errors.append(
                    f"Account {acc.id} ledger entry {entry.id} invalid balance_after: "
                    f"recorded {entry.balance_after_paise}, recomputed {recomputed_balance}."
                )

        if recomputed_balance != current_balance:
            replay_ok = False
            errors.append(
                f"Account {acc.id} balance drift: wallet shows {current_balance}, "
                f"recomputed from history is {recomputed_balance}."
            )

    is_overall_ok = zero_sum_ok and balanced_ok and replay_ok and len(errors) == 0

    return LedgerVerificationReport(
        ok=is_overall_ok,
        total_wallets=wallet_count,
        sum_wallet_balances_paise=total_balance_paise,
        zero_sum_verified=zero_sum_ok,
        total_transactions=len(transactions),
        balanced_entries_verified=balanced_ok,
        history_replay_verified=replay_ok,
        errors=errors,
    )
