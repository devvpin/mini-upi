"""
bank.limits — Financial limit enforcement (per-transaction, daily velocity, min amount).

Crypto concept: Rate limiting and volume caps acting as damage-containment controls.
Threat mitigated: Automated drained wallets, mass unauthorized withdrawals.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.bank.models import Transaction, TxnStatus
from app.core.config import get_settings
from app.core.errors import AppError, limit_exceeded


async def check_transaction_limits(
    session: AsyncSession,
    payer_account_id: uuid.UUID,
    amount_paise: int,
) -> None:
    """
    Enforce min/max per-transaction caps and 24-hour daily cumulative limits.
    """
    settings = get_settings()

    # Minimum transaction: ₹1 (100 paise)
    if amount_paise < 100:
        raise AppError(400, "LIMIT_EXCEEDED", "Minimum transaction amount is ₹1.00.")

    # Max per transaction: ₹5,000 (500,000 paise)
    if amount_paise > settings.max_txn_paise:
        max_rs = settings.max_txn_paise // 100
        raise limit_exceeded(f"Amount exceeds per-transaction limit of ₹{max_rs:,}.")

    # Cumulative 24-hour volume limit
    since = datetime.now(UTC) - timedelta(hours=24)
    stmt = (
        select(func.coalesce(func.sum(Transaction.amount_paise), 0))
        .where(
            Transaction.payer_account_id == payer_account_id,
            Transaction.status == TxnStatus.SUCCESS,
            Transaction.created_at >= since,
        )
    )
    res = await session.execute(stmt)
    spent_24h = int(res.scalar() or 0)

    if spent_24h + amount_paise > settings.daily_limit_paise:
        daily_rs = settings.daily_limit_paise // 100
        raise limit_exceeded(
            f"Daily payment limit of ₹{daily_rs:,} would be exceeded."
        )
