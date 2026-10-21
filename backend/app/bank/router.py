"""
bank.router — Endpoints for wallet balance, VPA resolution, and transaction history.

Crypto concept: Principle of least privilege; privacy-preserving masking; rate limiting.
Threat mitigated: Horizontal balance snooping, directory scraping.
"""

from __future__ import annotations

import collections
import time
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.bank.models import LedgerDirection
from app.bank.repository import (
    get_or_create_account_for_user,
    get_vpa_by_handle,
    list_transactions_for_account,
)
from app.bank.schemas import (
    TransactionSummary,
    VpaMeResponse,
    VpaResolveResponse,
    WalletResponse,
)
from app.core.config import get_settings
from app.core.database import get_db
from app.core.errors import payee_not_found, rate_limited
from app.identity.deps import get_current_user
from app.identity.models import User

router = APIRouter(prefix="", tags=["wallet"])

# In-memory sliding window rate limiter for /vpa/resolve (30 requests/min per user)
_resolve_rate_limits: dict[str, list[float]] = collections.defaultdict(list)


def mask_display_name(name: str) -> str:
    """Mask full name for privacy during directory lookup: 'Aarav Patel' -> 'A**** P****'."""
    parts = name.strip().split()
    masked_parts: list[str] = []
    for part in parts:
        if len(part) <= 1:
            masked_parts.append(part)
        else:
            masked_parts.append(part[0] + "*" * (len(part) - 1))
    return " ".join(masked_parts)


@router.get("/wallet", response_model=WalletResponse)
async def get_wallet(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> WalletResponse:
    """Get current user's wallet balance and 5 most recent transactions."""
    settings = get_settings()
    account, vpa = await get_or_create_account_for_user(
        session, user, vpa_suffix=settings.vpa_suffix
    )
    balance_paise = account.wallet.balance_paise if account.wallet else 0
    txns = await list_transactions_for_account(session, account.id, limit=5)

    recent_summaries: list[TransactionSummary] = []
    for t in txns:
        is_payer = t.payer_account_id == account.id
        direction = LedgerDirection.DEBIT if is_payer else LedgerDirection.CREDIT
        counterparty_acc = t.payee_account if is_payer else t.payer_account
        cp_user = counterparty_acc.user
        cp_handle = (
            counterparty_acc.vpas[0].handle
            if counterparty_acc.vpas
            else ("treasury" if counterparty_acc.is_system else "unknown")
        )
        if cp_user:
            cp_name = mask_display_name(cp_user.full_name)
        else:
            cp_name = "Treasury" if counterparty_acc.is_system else "System"

        recent_summaries.append(
            TransactionSummary(
                id=t.id,
                amount_paise=t.amount_paise,
                direction=direction,
                counterparty_handle=cp_handle,
                counterparty_name=cp_name,
                note=t.note,
                status=t.status if isinstance(t.status, str) else t.status.value,
                created_at=t.created_at,
            )
        )

    return WalletResponse(
        account_id=account.id,
        balance_paise=balance_paise,
        balance_rupees=balance_paise / 100.0,
        primary_vpa=vpa.handle,
        recent_transactions=recent_summaries,
    )


@router.get("/vpa/resolve", response_model=VpaResolveResponse)
async def resolve_vpa(
    handle: Annotated[str, Query(..., min_length=3, max_length=128)],
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> VpaResolveResponse:
    """
    Resolve a VPA handle to display name. Returns only a masked name.
    Strictly rate limited to 30 calls per minute per user to prevent directory scraping.
    """
    now = time.time()
    user_id_str = str(user.id)
    history = _resolve_rate_limits[user_id_str]
    # Prune timestamps older than 60 seconds
    valid_history = [t for t in history if now - t < 60.0]
    if len(valid_history) >= 30:
        raise rate_limited("VPA directory lookup rate limit exceeded (30/min).")

    valid_history.append(now)
    _resolve_rate_limits[user_id_str] = valid_history

    vpa = await get_vpa_by_handle(session, handle)
    if vpa is None or vpa.account.user is None:
        raise payee_not_found("No account found for this VPA.")

    masked = mask_display_name(vpa.account.user.full_name)
    return VpaResolveResponse(handle=vpa.handle, masked_name=masked)


def format_qr_payload(
    vpa: str,
    amount_paise: int | None = None,
    note: str | None = None,
    hmac_key: bytes | None = None,
) -> str:
    """Format standard campus UPI QR payload: miniupi://pay?vpa=...&am=...&tn=...&sig=..."""
    import hashlib
    import hmac

    parts = [f"vpa={vpa}"]
    if amount_paise is not None:
        parts.append(f"am={amount_paise}")
    if note is not None:
        parts.append(f"tn={note}")
    if hmac_key is not None:
        sig_data = "&".join(parts).encode("utf-8")
        sig = hmac.new(hmac_key, sig_data, hashlib.sha256).hexdigest()
        parts.append(f"sig={sig}")
    return f"miniupi://pay?{'&'.join(parts)}"


@router.get("/vpa/me", response_model=VpaMeResponse)
async def get_my_vpa(
    amount_paise: Annotated[int | None, Query(ge=100)] = None,
    note: Annotated[str | None, Query(max_length=200)] = None,
    sign: Annotated[bool, Query()] = False,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> VpaMeResponse:
    """Return authenticated user's VPAs and QR payment payload."""
    settings = get_settings()
    account, primary_vpa = await get_or_create_account_for_user(
        session, user, vpa_suffix=settings.vpa_suffix
    )
    all_handles = [v.handle for v in account.vpas]

    hmac_key = settings.audit_hmac_key.encode("utf-8") if sign else None
    qr = format_qr_payload(
        vpa=primary_vpa.handle,
        amount_paise=amount_paise,
        note=note,
        hmac_key=hmac_key,
    )

    return VpaMeResponse(
        primary_vpa=primary_vpa.handle,
        all_vpas=all_handles,
        qr_payload=qr,
    )


@router.get("/transactions", response_model=list[TransactionSummary])
async def list_user_transactions(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: Annotated[datetime | None, Query()] = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[TransactionSummary]:
    """Cursor-paginated transaction history for the authenticated user only."""
    settings = get_settings()
    account, _ = await get_or_create_account_for_user(
        session, user, vpa_suffix=settings.vpa_suffix
    )
    txns = await list_transactions_for_account(
        session, account.id, limit=limit, cursor_created_at=cursor
    )

    summaries: list[TransactionSummary] = []
    for t in txns:
        is_payer = t.payer_account_id == account.id
        direction = LedgerDirection.DEBIT if is_payer else LedgerDirection.CREDIT
        counterparty_acc = t.payee_account if is_payer else t.payer_account
        cp_user = counterparty_acc.user
        cp_handle = (
            counterparty_acc.vpas[0].handle
            if counterparty_acc.vpas
            else ("treasury" if counterparty_acc.is_system else "unknown")
        )
        if cp_user:
            cp_name = mask_display_name(cp_user.full_name)
        else:
            cp_name = "Treasury" if counterparty_acc.is_system else "System"

        summaries.append(
            TransactionSummary(
                id=t.id,
                amount_paise=t.amount_paise,
                direction=direction,
                counterparty_handle=cp_handle,
                counterparty_name=cp_name,
                note=t.note,
                status=t.status if isinstance(t.status, str) else t.status.value,
                created_at=t.created_at,
            )
        )
    return summaries
