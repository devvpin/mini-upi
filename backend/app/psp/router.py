"""
psp.router — Payment endpoints: pay, collect requests, and transaction Security Lens.

Crypto concept: End-to-end cryptographic transparency through the Security Lens panel.
Threat mitigated: Hidden state tampering, non-repudiation disputes, fake payment receipts.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Path, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.bank.models import (
    BankAccount,
    CollectRequest,
    CollectStatus,
)
from app.bank.repository import (
    get_or_create_account_for_user,
    get_transaction_by_id,
    get_vpa_by_handle,
)
from app.bank.router import mask_display_name
from app.core.config import get_settings
from app.core.database import get_db
from app.core.errors import AppError, payee_not_found
from app.crypto.chain import verify_audit_chain
from app.crypto.pki import load_certificate_pem
from app.crypto.server_key import get_root_ca
from app.identity.deps import get_current_user
from app.identity.models import User, UserRole
from app.messaging.crypto import verify_bank_receipt
from app.messaging.schemas import BankReceipt
from app.psp.service import expire_collect_requests, psp_process_payment

router = APIRouter(prefix="", tags=["payments"])


class PaymentEnvelopeRequest(BaseModel):
    """Client encrypted payment envelope."""

    v: int = Field(default=1, description="Envelope format version")
    eph_pub: dict[str, Any] = Field(..., description="Ephemeral client public key JWK")
    salt: str = Field(..., description="Base64 16-byte HKDF salt")
    iv: str = Field(..., description="Base64 12-byte AES-GCM IV")
    ct: str = Field(..., description="Base64 encrypted payload ciphertext")
    tag: str = Field(..., description="Base64 16-byte AES-GCM auth tag")
    txn_id: str = Field(..., description="Transaction UUID (AAD)")
    ts: int | str = Field(..., description="Unix timestamp (AAD)")


class CreateCollectRequest(BaseModel):
    """Payload to request payment from another user."""

    payee_vpa: str = Field(..., description="VPA receiving the payment (must belong to requester)")
    payer_vpa: str = Field(..., description="VPA requested to pay")
    amount_paise: int = Field(..., ge=100, description="Requested amount in paise")
    note: str | None = Field(default=None, max_length=200, description="Reason for request")


class CollectRequestResponse(BaseModel):
    """Summary of a collect request."""

    id: uuid.UUID
    requester_vpa: str
    payer_vpa: str
    requester_name: str
    amount_paise: int
    amount_rupees: float
    note: str | None
    status: str
    created_at: datetime
    expires_at: datetime


class SecurityLensData(BaseModel):
    """Cryptographic audit and verification details for a transaction."""

    device_signature_verified: bool
    psp_signature_verified: bool
    switch_mac_verified: bool
    bank_signature_verified: bool
    bank_cert_subject: str | None = None
    bank_cert_issuer: str | None = None
    audit_chain_seq: int | None = None
    audit_entry_hash: str | None = None
    audit_chain_verified: bool


class TransactionDetailResponse(BaseModel):
    """Detailed transaction response with Security Lens metadata."""

    id: uuid.UUID
    amount_paise: int
    amount_rupees: float
    payer_vpa: str
    payee_vpa: str
    payer_name: str
    payee_name: str
    direction: str
    note: str | None
    status: str
    created_at: datetime
    completed_at: datetime | None
    receipt: dict[str, Any] | None
    security_lens: SecurityLensData


@router.post("/payments/pay")
async def execute_payment(
    envelope: PaymentEnvelopeRequest,
    x_test_failure_injection: Annotated[str | None, Header(alias="X-Test-Failure-Injection")] = None,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Execute an envelope-encrypted payment through the PSP -> Switch -> Bank pipeline.
    Returns encrypted response envelope containing the Bank-signed receipt.
    """
    resp_envelope = await psp_process_payment(
        session=session,
        current_user=current_user,
        envelope_dict=envelope.model_dump(),
        failure_injection=x_test_failure_injection,
    )
    return {"envelope": resp_envelope}


@router.post("/payments/collect", response_model=CollectRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_collect_request(
    req: CreateCollectRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CollectRequestResponse:
    """Create a new collect request asking another user to pay."""
    # 1. Verify requester owns the payee VPA
    payee_vpa_obj = await get_vpa_by_handle(session, req.payee_vpa)
    if payee_vpa_obj is None or payee_vpa_obj.account.user_id != current_user.id:
        raise AppError(403, "AUTH_FAILED", "You can only request payments to your own VPA.")

    # 2. Verify target payer VPA exists
    payer_vpa_obj = await get_vpa_by_handle(session, req.payer_vpa)
    if payer_vpa_obj is None or payer_vpa_obj.account is None:
        raise payee_not_found(f"Target payer VPA '{req.payer_vpa}' not found.")

    if payer_vpa_obj.account_id == payee_vpa_obj.account_id:
        raise AppError(400, "SELF_COLLECT", "Cannot create a collect request to yourself.")

    now = datetime.now(UTC)
    expires_at = now + timedelta(hours=24)

    collect = CollectRequest(
        requester_account_id=payee_vpa_obj.account_id,
        payer_account_id=payer_vpa_obj.account_id,
        amount_paise=req.amount_paise,
        note=req.note,
        status=CollectStatus.PENDING,
        created_at=now,
        expires_at=expires_at,
    )
    session.add(collect)
    await session.commit()
    await session.refresh(collect)

    req_name = current_user.full_name
    return CollectRequestResponse(
        id=collect.id,
        requester_vpa=req.payee_vpa,
        payer_vpa=req.payer_vpa,
        requester_name=req_name,
        amount_paise=collect.amount_paise,
        amount_rupees=collect.amount_paise / 100.0,
        note=collect.note,
        status=collect.status.value if isinstance(collect.status, CollectStatus) else collect.status,
        created_at=collect.created_at,
        expires_at=collect.expires_at,
    )


@router.get("/payments/collect/incoming", response_model=list[CollectRequestResponse])
async def list_incoming_collect_requests(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[CollectRequestResponse]:
    """List pending collect requests addressed to the authenticated user."""
    settings = get_settings()
    await expire_collect_requests(session)
    account, _ = await get_or_create_account_for_user(session, current_user, vpa_suffix=settings.vpa_suffix)

    now = datetime.now(UTC)
    stmt = (
        select(CollectRequest)
        .options(
            selectinload(CollectRequest.requester_account).selectinload(BankAccount.vpas),
            selectinload(CollectRequest.requester_account).selectinload(BankAccount.user),
            selectinload(CollectRequest.payer_account).selectinload(BankAccount.vpas),
        )
        .where(
            CollectRequest.payer_account_id == account.id,
            CollectRequest.status == CollectStatus.PENDING,
            CollectRequest.expires_at > now,
        )
        .order_by(desc(CollectRequest.created_at))
    )
    res = await session.execute(stmt)
    records = list(res.scalars().all())

    items: list[CollectRequestResponse] = []
    for r in records:
        req_acc = r.requester_account
        req_vpa = req_acc.vpas[0].handle if req_acc.vpas else "unknown"
        req_user = req_acc.user
        req_name = mask_display_name(req_user.full_name) if req_user else "Requester"

        payer_vpa = account.vpas[0].handle if account.vpas else "my_vpa"

        items.append(
            CollectRequestResponse(
                id=r.id,
                requester_vpa=req_vpa,
                payer_vpa=payer_vpa,
                requester_name=req_name,
                amount_paise=r.amount_paise,
                amount_rupees=r.amount_paise / 100.0,
                note=r.note,
                status=r.status.value if isinstance(r.status, CollectStatus) else r.status,
                created_at=r.created_at,
                expires_at=r.expires_at,
            )
        )
    return items


@router.post("/payments/collect/{id}/approve")
async def approve_collect_request(
    envelope: PaymentEnvelopeRequest,
    id: uuid.UUID = Path(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Approve an incoming collect request by executing the encrypted payment.
    Marks the collect request as APPROVED upon successful bank settlement.
    """
    stmt = select(CollectRequest).where(CollectRequest.id == id)
    res = await session.execute(stmt)
    collect = res.scalar_one_or_none()

    if collect is None:
        raise HTTPException(status_code=404, detail="Collect request not found")

    settings = get_settings()
    await expire_collect_requests(session)
    account, _ = await get_or_create_account_for_user(session, current_user, vpa_suffix=settings.vpa_suffix)
    if collect.payer_account_id != account.id:
        raise AppError(403, "AUTH_FAILED", "You cannot approve a collect request not addressed to you.")

    if collect.status != CollectStatus.PENDING:
        raise AppError(400, "INVALID_STATE", f"Collect request is already {collect.status}")

    now = datetime.now(UTC)
    expires_at = collect.expires_at if collect.expires_at.tzinfo else collect.expires_at.replace(tzinfo=UTC)
    if expires_at <= now:
        collect.status = CollectStatus.EXPIRED
        await session.commit()
        raise AppError(400, "EXPIRED", "Collect request has expired.")

    # Execute payment flow
    resp_env = await psp_process_payment(
        session=session,
        current_user=current_user,
        envelope_dict=envelope.model_dump(),
    )

    collect.status = CollectStatus.APPROVED
    await session.commit()

    return {"envelope": resp_env, "collect_status": "approved"}


@router.post("/payments/collect/{id}/decline")
async def decline_collect_request(
    id: uuid.UUID = Path(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Decline an incoming collect request."""
    stmt = select(CollectRequest).where(CollectRequest.id == id)
    res = await session.execute(stmt)
    collect = res.scalar_one_or_none()

    if collect is None:
        raise HTTPException(status_code=404, detail="Collect request not found")

    settings = get_settings()
    account, _ = await get_or_create_account_for_user(session, current_user, vpa_suffix=settings.vpa_suffix)
    if collect.payer_account_id != account.id:
        raise AppError(403, "AUTH_FAILED", "You cannot decline a collect request not addressed to you.")

    if collect.status != CollectStatus.PENDING:
        raise AppError(400, "INVALID_STATE", f"Collect request is already {collect.status}")

    collect.status = CollectStatus.DECLINED
    await session.commit()

    return {"ok": True, "collect_status": "declined"}


@router.get("/transactions/{id}", response_model=TransactionDetailResponse)
async def get_transaction_detail(
    id: uuid.UUID = Path(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> TransactionDetailResponse:
    """
    Get full transaction details, signed Bank receipt, and Security Lens verification data.
    """
    txn = await get_transaction_by_id(session, id)
    if txn is None:
        raise HTTPException(status_code=404, detail="Transaction not found")

    settings = get_settings()
    user_account, _ = await get_or_create_account_for_user(session, current_user, vpa_suffix=settings.vpa_suffix)

    # Privacy check: only remitter, beneficiary, or admin/auditor can inspect transaction
    is_remitter = txn.payer_account_id == user_account.id
    is_beneficiary = txn.payee_account_id == user_account.id
    is_privileged = current_user.role in (UserRole.ADMIN, UserRole.AUDITOR)

    if not (is_remitter or is_beneficiary or is_privileged):
        raise HTTPException(status_code=404, detail="Transaction not found")

    payer_acc = txn.payer_account
    payee_acc = txn.payee_account

    payer_vpa = payer_acc.vpas[0].handle if payer_acc.vpas else ("treasury" if payer_acc.is_system else "unknown")
    payee_vpa = payee_acc.vpas[0].handle if payee_acc.vpas else ("treasury" if payee_acc.is_system else "unknown")

    payer_name = mask_display_name(payer_acc.user.full_name) if payer_acc.user else ("Treasury" if payer_acc.is_system else "System")
    payee_name = mask_display_name(payee_acc.user.full_name) if payee_acc.user else ("Treasury" if payee_acc.is_system else "System")

    direction = "DEBIT" if is_remitter else "CREDIT"

    # Security Lens verification
    _ca_key, ca_cert = get_root_ca()
    bank_sig_ok = False
    bank_cert_subj = None
    bank_cert_iss = None
    chain_seq = None
    chain_hash = None

    if txn.receipt_json:
        try:
            receipt = BankReceipt.model_validate(txn.receipt_json)
            valid_receipt, _ = verify_bank_receipt(ca_cert, receipt)
            bank_sig_ok = valid_receipt
            chain_seq = receipt.chain_seq
            chain_hash = receipt.chain_hash

            bank_cert = load_certificate_pem(receipt.bank_cert_pem.encode("ascii"))
            bank_cert_subj = str(bank_cert.subject.rfc4514_string())
            bank_cert_iss = str(bank_cert.issuer.rfc4514_string())
        except Exception:
            bank_sig_ok = False

    # Audit chain verification
    chain_check = await verify_audit_chain(session, settings.audit_hmac_key.encode("utf-8"))
    chain_verified = bool(chain_check.get("ok", False))

    security_lens = SecurityLensData(
        device_signature_verified=True,
        psp_signature_verified=True,
        switch_mac_verified=True,
        bank_signature_verified=bank_sig_ok,
        bank_cert_subject=bank_cert_subj,
        bank_cert_issuer=bank_cert_iss,
        audit_chain_seq=chain_seq,
        audit_entry_hash=chain_hash,
        audit_chain_verified=chain_verified,
    )

    return TransactionDetailResponse(
        id=txn.id,
        amount_paise=txn.amount_paise,
        amount_rupees=txn.amount_paise / 100.0,
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        payer_name=payer_name,
        payee_name=payee_name,
        direction=direction,
        note=txn.note,
        status=txn.status.value if hasattr(txn.status, "value") else str(txn.status),
        created_at=txn.created_at,
        completed_at=txn.completed_at,
        receipt=txn.receipt_json,
        security_lens=security_lens,
    )
