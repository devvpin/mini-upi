"""
bank.service — Bank party transaction execution and cryptographic receipt generation.

Crypto concept: Atomic state transition combining double-entry balance posting,
tamper-evident audit chaining, and Bank-signed receipt issuance in a single DB commit.
Threat mitigated: Split-brain states, unsigned transaction confirmations, audit gaps.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.bank.models import (
    AccountStatus,
    LedgerDirection,
    LedgerEntry,
    Transaction,
    TxnKind,
    TxnStatus,
)
from app.bank.repository import get_transaction_by_id, lock_wallets_ordered
from app.core.config import get_settings
from app.core.errors import (
    AppError,
    account_frozen,
    insufficient_funds,
)
from app.crypto.chain import append_audit_entry
from app.crypto.server_key import get_bank_service_keys
from app.messaging.crypto import create_bank_receipt, verify_switch_to_bank_message
from app.messaging.schemas import BankReceipt, SwitchToBankMessage


async def bank_process_payment(
    session: AsyncSession,
    msg: SwitchToBankMessage,
) -> BankReceipt:
    """
    Execute verified Switch-to-Bank transfer instruction atomically.
    1. Verify Switch HMAC-SHA256 service MAC.
    2. Check idempotency.
    3. Lock wallets in deterministic order.
    4. Post double-entry ledger entries.
    5. Append tamper-evident audit log entry.
    6. Sign cryptographic bank receipt.
    7. Commit transaction.
    """
    settings = get_settings()

    # 1. Verify Switch-to-Bank MAC
    mac_key = settings.switch_bank_mac_key.encode("utf-8")
    valid_mac, mac_err = verify_switch_to_bank_message(msg, mac_key)
    if not valid_mac:
        raise AppError(403, "MAC_INVALID", f"Internal service authentication failed: {mac_err}")

    txn_id = uuid.UUID(msg.payload.txn_id)
    payer_acc_id = uuid.UUID(msg.payer_account_id)
    payee_acc_id = uuid.UUID(msg.payee_account_id)
    amount_paise = msg.payload.amount_paise

    # 2. Idempotency check
    existing = await get_transaction_by_id(session, txn_id)
    if existing is not None and existing.status == TxnStatus.SUCCESS and existing.receipt_json:
        return BankReceipt.model_validate(existing.receipt_json)

    # 3. Lock wallets in ascending UUID order to guarantee no deadlocks
    payer_wallet, payee_wallet = await lock_wallets_ordered(session, payer_acc_id, payee_acc_id)

    # Check account statuses
    if payer_wallet.account.status != AccountStatus.ACTIVE:
        raise account_frozen("Payer bank account is frozen or inactive.")
    if payee_wallet.account.status != AccountStatus.ACTIVE:
        raise account_frozen("Payee bank account is frozen or inactive.")

    # Check solvency
    if not payer_wallet.account.is_system and payer_wallet.balance_paise < amount_paise:
        raise insufficient_funds("Insufficient balance for this payment.")

    now = datetime.now(UTC)

    # 4. Update balances
    payer_wallet.balance_paise -= amount_paise
    payee_wallet.balance_paise += amount_paise

    # 5. Create Transaction record
    txn = Transaction(
        id=txn_id,
        kind=TxnKind.PAY,
        payer_account_id=payer_acc_id,
        payee_account_id=payee_acc_id,
        amount_paise=amount_paise,
        note=msg.payload.note,
        status=TxnStatus.SUCCESS,
        created_at=now,
        completed_at=now,
    )
    session.add(txn)
    await session.flush()

    # 6. Post balanced double-entry ledger rows
    debit = LedgerEntry(
        txn_id=txn.id,
        account_id=payer_acc_id,
        direction=LedgerDirection.DEBIT,
        amount_paise=amount_paise,
        balance_after_paise=payer_wallet.balance_paise,
        created_at=now,
    )
    credit = LedgerEntry(
        txn_id=txn.id,
        account_id=payee_acc_id,
        direction=LedgerDirection.CREDIT,
        amount_paise=amount_paise,
        balance_after_paise=payee_wallet.balance_paise,
        created_at=now,
    )
    session.add(debit)
    session.add(credit)
    await session.flush()

    # 7. Append hash-chained audit log entry in the SAME transaction
    audit_key = settings.audit_hmac_key.encode("utf-8")
    audit_event = {
        "event": "PAY_OK",
        "txn_id": str(txn_id),
        "payer_vpa": msg.payload.payer_vpa,
        "payee_vpa": msg.payload.payee_vpa,
        "amount_paise": amount_paise,
        "payer_account_id": str(payer_acc_id),
        "payee_account_id": str(payee_acc_id),
    }
    chain_entry = await append_audit_entry(
        session=session,
        event_type="PAY_OK",
        payload=audit_event,
        audit_hmac_key=audit_key,
        txn_id=txn_id,
    )

    # 8. Sign cryptographic Bank receipt
    bank_key, bank_cert, _ca_cert = get_bank_service_keys()
    receipt = create_bank_receipt(
        bank_key=bank_key,
        bank_cert=bank_cert,
        txn_id=str(txn_id),
        payer_vpa=msg.payload.payer_vpa,
        payee_vpa=msg.payload.payee_vpa,
        amount_paise=amount_paise,
        note=msg.payload.note,
        chain_seq=chain_entry.seq,
        chain_hash=chain_entry.entry_hash.hex(),
        completed_at=now.isoformat(),
    )

    # 9. Persist receipt onto transaction record
    txn.receipt_json = receipt.to_dict()
    txn.receipt_signature = receipt.bank_signature
    await session.commit()

    return receipt
