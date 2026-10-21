"""
bank.ledger — Double-entry financial ledger service and balance transfers.

Crypto concept: Provable conservation of virtual money; balanced double-entry
(every debit equals a credit); zero-sum invariant across the economy.
Threat mitigated: Money creation from thin air, double-spending, race-condition overdrafts.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.bank.models import (
    AccountStatus,
    LedgerDirection,
    LedgerEntry,
    Transaction,
    TxnKind,
    TxnStatus,
)
from app.bank.repository import (
    get_transaction_by_id,
    lock_wallets_ordered,
)
from app.core.errors import (
    AppError,
    account_frozen,
    insufficient_funds,
)


async def post_transfer(
    session: AsyncSession,
    txn_id: uuid.UUID,
    from_account_id: uuid.UUID,
    to_account_id: uuid.UUID,
    amount_paise: int,
    note: str | None = None,
    kind: TxnKind = TxnKind.PAY,
    receipt_json: dict[str, Any] | None = None,
    receipt_signature: str | None = None,
) -> Transaction:
    """
    Atomically transfer funds between two accounts using double-entry ledger.
    Idempotent: repeating with the same txn_id returns the existing transaction.
    Guaranteed deadlock-free using deterministic wallet locking.
    """
    if amount_paise <= 0:
        raise AppError(400, "INVALID_AMOUNT", "Amount must be strictly positive.")

    if from_account_id == to_account_id:
        raise AppError(400, "SELF_TRANSFER", "Cannot transfer funds to the same account.")

    # 1. Idempotency check
    existing = await get_transaction_by_id(session, txn_id)
    if existing is not None:
        return existing

    # 2. Lock both wallets in strict ascending order of UUID
    payer_wallet, payee_wallet = await lock_wallets_ordered(
        session, from_account_id, to_account_id
    )

    # 3. Check account statuses
    if payer_wallet.account.status != AccountStatus.ACTIVE:
        raise account_frozen("Payer account is frozen or inactive.")
    if payee_wallet.account.status != AccountStatus.ACTIVE:
        raise account_frozen("Payee account is frozen or inactive.")

    # 4. Solvency invariant: non-system accounts cannot go negative
    if not payer_wallet.account.is_system and payer_wallet.balance_paise < amount_paise:
        raise insufficient_funds("Insufficient balance for this payment.")

    now = datetime.now(UTC)

    # 5. Apply balance delta
    payer_wallet.balance_paise -= amount_paise
    payee_wallet.balance_paise += amount_paise

    # 6. Record transaction
    txn = Transaction(
        id=txn_id,
        kind=kind,
        payer_account_id=from_account_id,
        payee_account_id=to_account_id,
        amount_paise=amount_paise,
        note=note,
        status=TxnStatus.SUCCESS,
        receipt_json=receipt_json,
        receipt_signature=receipt_signature,
        created_at=now,
        completed_at=now,
    )
    session.add(txn)
    await session.flush()

    # 7. Record exactly one DEBIT and one CREDIT ledger entry
    debit_entry = LedgerEntry(
        txn_id=txn.id,
        account_id=from_account_id,
        direction=LedgerDirection.DEBIT,
        amount_paise=amount_paise,
        balance_after_paise=payer_wallet.balance_paise,
        created_at=now,
    )
    credit_entry = LedgerEntry(
        txn_id=txn.id,
        account_id=to_account_id,
        direction=LedgerDirection.CREDIT,
        amount_paise=amount_paise,
        balance_after_paise=payee_wallet.balance_paise,
        created_at=now,
    )
    session.add(debit_entry)
    session.add(credit_entry)
    await session.commit()

    # Re-fetch transaction with relationships loaded
    committed_txn = await get_transaction_by_id(session, txn.id)
    assert committed_txn is not None
    return committed_txn
