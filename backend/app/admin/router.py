"""
admin.router — Administrative routes for CSV import, stats, and user management.

Crypto concept: Strict RBAC enforcement via require_role("admin"); audit traceability.
Threat mitigated: Unauthorized administrative access and data tampering.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.csv_import import process_import
from app.bank.schemas import TopupRequest, TopupResponse
from app.core.database import get_db
from app.identity.deps import require_role
from app.identity.models import User
from app.identity.schemas import ImportResult

router = APIRouter(prefix="/admin", tags=["admin"])


class ImportJsonRequest(BaseModel):
    departments_csv: str | None = None
    classes_csv: str | None = None
    users_csv: str | None = None
    dry_run: bool = False


@router.post("/import", response_model=ImportResult)
async def import_hierarchy(
    request: Request,
    session: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> ImportResult:
    """
    Import departments, classes, and users from CSV data.
    Requires admin role. Supports dry-run validation.
    Accepts both JSON payload and multipart form data.
    """
    content_type = request.headers.get("content-type", "")

    dept_str: str | None = None
    class_str: str | None = None
    user_str: str | None = None
    is_dry_run: bool = False

    if "multipart/form-data" in content_type:
        form = await request.form()
        is_dry_run = str(form.get("dry_run", "false")).lower() in ("true", "1", "yes")

        d_file = form.get("departments_file")
        if d_file and hasattr(d_file, "read"):
            dept_str = (await d_file.read()).decode("utf-8")

        c_file = form.get("classes_file")
        if c_file and hasattr(c_file, "read"):
            class_str = (await c_file.read()).decode("utf-8")

        u_file = form.get("users_file")
        if u_file and hasattr(u_file, "read"):
            user_str = (await u_file.read()).decode("utf-8")
    else:
        try:
            body = await request.json()
            req = ImportJsonRequest(**body)
            dept_str = req.departments_csv
            class_str = req.classes_csv
            user_str = req.users_csv
            is_dry_run = req.dry_run
        except Exception:
            pass

    creds_path = Path("scripts/seed/one_time_credentials.csv")

    return await process_import(
        session=session,
        departments_csv=dept_str,
        classes_csv=class_str,
        users_csv=user_str,
        dry_run=is_dry_run,
        credentials_output_path=creds_path,
    )


@router.post("/topup", response_model=TopupResponse)
async def admin_topup(
    req: TopupRequest,
    session: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> TopupResponse:
    """
    Top-up a user's wallet from the TREASURY system account.
    Audited: Requires a reason, logs transfer in double-entry ledger.
    """
    from app.bank.ledger import post_transfer
    from app.bank.models import TxnKind
    from app.bank.repository import (
        get_or_create_account_for_user,
        get_or_create_treasury,
        get_vpa_by_handle,
    )
    from app.core.config import get_settings
    from app.core.errors import payee_not_found
    from app.identity.repository import get_user_by_college_id

    settings = get_settings()
    treasury = await get_or_create_treasury(session)

    # Resolve target user and account
    target_user: User | None = None
    if req.college_id:
        target_user = await get_user_by_college_id(session, req.college_id)
    elif req.vpa:
        vpa_obj = await get_vpa_by_handle(session, req.vpa)
        if vpa_obj and vpa_obj.account.user:
            target_user = vpa_obj.account.user

    if target_user is None:
        raise payee_not_found("Target user for top-up not found.")

    target_acc, target_vpa = await get_or_create_account_for_user(
        session, target_user, vpa_suffix=settings.vpa_suffix
    )

    txn_id = uuid.uuid4()
    txn = await post_transfer(
        session=session,
        txn_id=txn_id,
        from_account_id=treasury.id,
        to_account_id=target_acc.id,
        amount_paise=req.amount_paise,
        note=f"Top-up: {req.reason}",
        kind=TxnKind.TOPUP,
    )

    new_balance = target_acc.wallet.balance_paise if target_acc.wallet else 0
    return TopupResponse(
        txn_id=txn.id,
        recipient_college_id=target_user.college_id,
        recipient_vpa=target_vpa.handle,
        amount_paise=req.amount_paise,
        new_balance_paise=new_balance,
        reason=req.reason,
    )


@router.post("/audit/verify")
async def audit_verify_ledger(
    session: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin", "auditor")),
) -> dict[str, Any]:
    """
    Verify the mathematical consistency of the double-entry ledger:
    - Global zero-sum invariant (sum of all balances = 0)
    - Double-entry debit/credit equality
    - Historical replay from entry 1 to current balance
    """
    from app.bank.verifier import verify_ledger

    report = await verify_ledger(session)
    return {
        "ok": report.ok,
        "total_wallets": report.total_wallets,
        "sum_wallet_balances_paise": report.sum_wallet_balances_paise,
        "zero_sum_verified": report.zero_sum_verified,
        "total_transactions": report.total_transactions,
        "balanced_entries_verified": report.balanced_entries_verified,
        "history_replay_verified": report.history_replay_verified,
        "errors": report.errors,
    }


@router.get("/stats")
async def get_admin_stats(
    session: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Admin dashboard stats overview: user counts and financial summary."""
    from sqlalchemy import func, select

    from app.bank.models import Transaction, TxnStatus

    user_count_res = await session.execute(select(func.count(User.id)))
    user_count = int(user_count_res.scalar() or 0)

    txn_count_res = await session.execute(
        select(func.count(Transaction.id)).where(Transaction.status == TxnStatus.SUCCESS)
    )
    txn_count = int(txn_count_res.scalar() or 0)

    vol_res = await session.execute(
        select(func.coalesce(func.sum(Transaction.amount_paise), 0)).where(
            Transaction.status == TxnStatus.SUCCESS
        )
    )
    volume_paise = int(vol_res.scalar() or 0)

    return {
        "status": "ok",
        "total_users": user_count,
        "total_transactions": txn_count,
        "total_volume_paise": volume_paise,
        "total_volume_rupees": volume_paise / 100.0,
    }
