"""
switch.service — NPCI Switch simulation: routing, VPA directory lookup, and limit enforcement.

Crypto concept: Role-constrained certificate verification (OU=PSP) and HMAC-authenticated service dispatch.
Threat mitigated: Unauthorized routing, spoofed PSP messages, bypass of transaction velocity limits.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.bank.limits import check_transaction_limits
from app.bank.models import AccountStatus
from app.bank.repository import get_vpa_by_handle
from app.bank.service import bank_process_payment
from app.core.config import get_settings
from app.core.errors import AppError, account_frozen, payee_not_found
from app.crypto.server_key import get_root_ca
from app.messaging.crypto import create_switch_to_bank_message, verify_psp_message
from app.messaging.schemas import BankReceipt, PspToSwitchMessage


async def switch_process_payment(
    session: AsyncSession,
    msg: PspToSwitchMessage,
) -> BankReceipt:
    """
    Process incoming payment message from PSP.
    1. Verify PSP certificate chain against Root CA and verify ECDSA signature.
    2. Resolve payer and payee VPAs to their underlying bank accounts.
    3. Enforce per-transaction and 24h cumulative limits.
    4. Authenticate message to Bank via HMAC-SHA256 service MAC.
    5. Route to Bank and return signed receipt.
    """
    settings = get_settings()

    # 1. Verify PSP certificate and signature
    _ca_key, ca_cert = get_root_ca()
    valid_psp, psp_err = verify_psp_message(ca_cert, msg)
    if not valid_psp:
        raise AppError(403, "PSP_UNTRUSTED", f"PSP authentication failed: {psp_err}")

    # 2. Resolve payer VPA
    payer_vpa_obj = await get_vpa_by_handle(session, msg.payload.payer_vpa)
    if payer_vpa_obj is None or payer_vpa_obj.account is None:
        raise payee_not_found("Remitter VPA not found in directory.")

    # 3. Resolve payee VPA
    payee_vpa_obj = await get_vpa_by_handle(session, msg.payload.payee_vpa)
    if payee_vpa_obj is None or payee_vpa_obj.account is None:
        raise payee_not_found(f"Beneficiary VPA '{msg.payload.payee_vpa}' not found.")

    # 4. Check account statuses
    if payer_vpa_obj.account.status != AccountStatus.ACTIVE:
        raise account_frozen("Remitter bank account is frozen or inactive.")
    if payee_vpa_obj.account.status != AccountStatus.ACTIVE:
        raise account_frozen("Beneficiary bank account is frozen or inactive.")

    # 5. Check velocity and amount limits
    await check_transaction_limits(session, payer_vpa_obj.account_id, msg.payload.amount_paise)

    # 6. Form Switch-to-Bank authenticated message
    mac_key = settings.switch_bank_mac_key.encode("utf-8")
    switch_to_bank_msg = create_switch_to_bank_message(
        payload=msg.payload,
        payer_account_id=str(payer_vpa_obj.account_id),
        payee_account_id=str(payee_vpa_obj.account_id),
        mac_key=mac_key,
        switch_id="gcet-campus-switch",
        key_id="v1",
    )

    # 7. Hand off to Bank
    receipt = await bank_process_payment(session, switch_to_bank_msg)
    return receipt
