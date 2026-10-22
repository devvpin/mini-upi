"""
psp.service — Payment Service Provider payment ingress and security controls.

Crypto concept: Defense-in-depth authorization verifying:
1. TLS + JWT session integrity.
2. App-layer envelope decryption with ephemeral ECDH.
3. Anti-replay nonce table + acceptance timestamp window.
4. Client device possession via non-extractable ECDSA signature.
5. User authorization factor via Argon2id MPIN with 3-strike lockout.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.bank.models import Transaction, TxnStatus
from app.bank.repository import get_transaction_by_id, get_vpa_by_handle
from app.core.config import get_settings
from app.core.errors import (
    AppError,
    auth_failed,
    device_not_bound,
    envelope_invalid,
    replay_detected,
    signature_invalid,
    timestamp_skew,
)
from app.crypto.canonical import canonical_json_bytes
from app.crypto.chain import append_audit_entry
from app.crypto.envelope import decrypt_request, encrypt_response
from app.crypto.kdf import verify_secret
from app.crypto.nonce import check_and_record_nonce, validate_timestamp
from app.crypto.server_key import get_psp_service_keys, get_server_ecdh_keys
from app.crypto.signing import jwk_to_public_key, raw_to_der, verify_signature
from app.identity.models import Device, MpinCredential, User
from app.messaging.crypto import sign_psp_message
from app.messaging.schemas import InnerPaymentRequest, PaymentPayload
from app.switch.service import switch_process_payment


async def _log_audit_rejection(
    session: AsyncSession,
    event: str,
    reason: str,
    user_id: uuid.UUID,
    txn_id: str | None = None,
) -> None:
    """Audit security rejections into tamper-evident log."""
    settings = get_settings()
    audit_data = {
        "reason": reason,
        "user_id": str(user_id),
        "txn_id": txn_id or "unknown",
    }
    txn_uuid: uuid.UUID | None = None
    if txn_id:
        try:
            txn_uuid = uuid.UUID(txn_id)
        except Exception:
            pass
    await append_audit_entry(
        session=session,
        event_type=event,
        payload=audit_data,
        audit_hmac_key=settings.audit_hmac_key.encode("utf-8"),
        actor_user_id=user_id,
        txn_id=txn_uuid,
    )
    await session.commit()


async def expire_collect_requests(session: AsyncSession) -> int:
    """Mark pending collect requests past their expiry time as expired."""
    from app.bank.models import CollectRequest, CollectStatus

    now = datetime.now(UTC)
    rows = (
        await session.execute(
            select(CollectRequest).where(
                CollectRequest.status == CollectStatus.PENDING,
                CollectRequest.expires_at <= now,
            )
        )
    ).scalars().all()
    for row in rows:
        row.status = CollectStatus.EXPIRED
    if rows:
        await session.commit()
    return len(rows)


async def psp_process_payment(
    session: AsyncSession,
    current_user: User,
    envelope_dict: dict[str, Any],
    failure_injection: str | None = None,
    expected_payment: tuple[str, str, int] | None = None,
) -> tuple[dict[str, Any], PaymentPayload]:
    """
    Ingress pipeline for payment execution:
    Decrypt envelope -> check timestamp -> check nonce -> verify device sig -> verify MPIN -> call Switch.
    Returns encrypted response envelope.
    """
    settings = get_settings()
    server_priv, _, _, _ = get_server_ecdh_keys()

    # Demo mode failure injection hooks
    if settings.demo_mode and failure_injection:
        if failure_injection == "corrupt_ciphertext":
            raw_ct = base64.b64decode(envelope_dict["ct"])
            corrupted = bytearray(raw_ct)
            if corrupted:
                corrupted[0] ^= 0x01
            envelope_dict = dict(envelope_dict, ct=base64.b64encode(corrupted).decode())

    # 1. Decrypt app-layer envelope
    try:
        plaintext_bytes, derived_key = decrypt_request(server_priv, envelope_dict)
    except Exception as e:
        await _log_audit_rejection(
            session,
            event="PAY_REJECTED",
            reason=f"Envelope decryption failed: {e}",
            user_id=current_user.id,
            txn_id=str(envelope_dict.get("txn_id")),
        )
        raise envelope_invalid("Invalid or tampered payment envelope.") from e

    # 2. Parse inner payment payload
    try:
        inner_json = json.loads(plaintext_bytes.decode("utf-8"))
        inner_req = InnerPaymentRequest.model_validate(inner_json)
        payload = inner_req.payload
    except Exception as e:
        await _log_audit_rejection(
            session,
            event="PAY_REJECTED",
            reason=f"Inner payload format error: {e}",
            user_id=current_user.id,
            txn_id=str(envelope_dict.get("txn_id")),
        )
        raise envelope_invalid(f"Malformed payment request: {e}") from e

    txn_uuid = uuid.UUID(payload.txn_id)

    if expected_payment is not None:
        expected_payer, expected_payee, expected_amount = expected_payment
        if (
            payload.payer_vpa != expected_payer
            or payload.payee_vpa != expected_payee
            or payload.amount_paise != expected_amount
        ):
            raise AppError(400, "COLLECT_MISMATCH", "Payment does not match the collect request.")

    # 3. Timestamp window check
    ok_ts, ts_err = validate_timestamp(payload.ts, window_seconds=settings.ts_window_seconds)
    if not ok_ts:
        await _log_audit_rejection(
            session,
            event="PAY_REJECTED",
            reason=f"Timestamp skew: {ts_err}",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise timestamp_skew(f"Transaction timestamp expired or out of range: {ts_err}")

    # 4. Verify remitter ownership before checking idempotent completion.
    payer_vpa_obj = await get_vpa_by_handle(session, payload.payer_vpa)
    if payer_vpa_obj is None or payer_vpa_obj.account is None or payer_vpa_obj.account.user_id != current_user.id:
        await _log_audit_rejection(
            session,
            event="PAY_REJECTED",
            reason=f"User {current_user.id} does not own remitter VPA '{payload.payer_vpa}'",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise auth_failed("You are not authorized to pay from this VPA.")

    # A network retry repeats the same signed nonce. Return its receipt before
    # replay detection, but only to the original payer and only for matching data.
    existing_txn = await get_transaction_by_id(session, txn_uuid)
    if existing_txn is not None and existing_txn.status == TxnStatus.SUCCESS and existing_txn.receipt_json:
        if (
            existing_txn.payer_account_id != payer_vpa_obj.account_id
            or existing_txn.amount_paise != payload.amount_paise
        ):
            raise AppError(409, "TXN_ID_CONFLICT", "Transaction ID is already in use.")
        receipt_bytes = canonical_json_bytes(existing_txn.receipt_json)
        return encrypt_response(derived_key, receipt_bytes, payload.txn_id), payload

    # 5. Anti-replay nonce check
    nonce_val = payload.nonce
    if settings.demo_mode and failure_injection == "replay_nonce":
        # Force a duplicate nonce condition
        nonce_val = "replayed-fixed-nonce-value"
        await check_and_record_nonce(session, nonce_val, current_user.id, settings.ts_window_seconds)

    ok_nonce, nonce_err = await check_and_record_nonce(
        session, nonce_val, current_user.id, window_seconds=settings.ts_window_seconds
    )
    if not ok_nonce:
        await _log_audit_rejection(
            session,
            event="REPLAY_DETECTED",
            reason=f"Duplicate nonce: {nonce_err}",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise replay_detected(f"Transaction rejected: {nonce_err}")

    # 6. Device signature verification
    dev_stmt = select(Device).where(
        Device.user_id == current_user.id,
        Device.revoked_at.is_(None),
    )
    dev_res = await session.execute(dev_stmt)
    active_devices = list(dev_res.scalars().all())

    if not active_devices:
        await _log_audit_rejection(
            session,
            event="DEVICE_REJECTED",
            reason="No active registered device found for user",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise device_not_bound("No registered client device. Please register your device key.")

    device_sig_b64 = inner_req.device_sig
    if settings.demo_mode and failure_injection == "corrupt_signature":
        raw_sig = bytearray(base64.b64decode(device_sig_b64))
        if raw_sig:
            raw_sig[0] ^= 0x01
        device_sig_b64 = base64.b64encode(raw_sig).decode()

    # Canonical bytes of payment payload
    signable_bytes = canonical_json_bytes(payload.model_dump())
    try:
        raw_sig_bytes = base64.b64decode(device_sig_b64)
        der_sig = raw_to_der(raw_sig_bytes)
    except Exception as e:
        await _log_audit_rejection(
            session,
            event="DEVICE_REJECTED",
            reason=f"Malformed device signature: {e}",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise signature_invalid("Invalid digital signature encoding.") from e

    device_verified = False
    device_err = None
    for dev in active_devices:
        try:
            jwk = json.loads(dev.public_key_jwk) if isinstance(dev.public_key_jwk, str) else dev.public_key_jwk
            pub_key = jwk_to_public_key(jwk)
            if verify_signature(pub_key, signable_bytes, der_sig):
                device_verified = True
                break
        except Exception as e:
            device_err = f"Exception: {e}"
            continue

    if not device_verified:
        await _log_audit_rejection(
            session,
            event="DEVICE_REJECTED",
            reason=f"Device signature verification failed against all active keys ({device_err}, devices={len(active_devices)})",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise signature_invalid(f"Digital signature verification failed. Device key mismatch ({device_err}).")

    # 8. MPIN verification with 3-strike lockout
    mpin_stmt = select(MpinCredential).where(MpinCredential.user_id == current_user.id)
    mpin_res = await session.execute(mpin_stmt)
    mpin_cred = mpin_res.scalar_one_or_none()

    if mpin_cred is None:
        raise AppError(400, "MPIN_NOT_SET", "MPIN has not been configured for your account.")

    now_utc = datetime.now(UTC)
    locked_until = mpin_cred.locked_until
    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=UTC)
    if locked_until and locked_until > now_utc:
        remaining_sec = int((locked_until - now_utc).total_seconds())
        await _log_audit_rejection(
            session,
            event="ACCOUNT_LOCKED",
            reason="Attempted payment while MPIN locked",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise AppError(
            403,
            "ACCOUNT_LOCKED",
            f"MPIN entry locked due to repeated failures. Try again in {remaining_sec}s.",
        )

    valid_mpin = verify_secret(inner_req.mpin, mpin_cred.mpin_hash, settings.pepper)
    if not valid_mpin:
        mpin_cred.failed_count += 1
        if mpin_cred.failed_count >= 3:
            mpin_cred.locked_until = now_utc + timedelta(minutes=15)
        await session.commit()

        await _log_audit_rejection(
            session,
            event="MPIN_FAIL",
            reason=f"Invalid MPIN entered (strike {mpin_cred.failed_count}/3)",
            user_id=current_user.id,
            txn_id=payload.txn_id,
        )
        raise auth_failed("Authentication failed. Invalid MPIN.")

    # Reset MPIN failures upon successful validation
    mpin_cred.failed_count = 0
    mpin_cred.locked_until = None

    # 9. Build PSP-signed message for Switch
    psp_key, psp_cert, _ca_cert = get_psp_service_keys()
    psp_msg = sign_psp_message(
        psp_key=psp_key,
        psp_cert=psp_cert,
        payload=payload,
        psp_id="gcet-campus-psp",
    )

    # 10. Call Switch pipeline
    receipt = await switch_process_payment(session, psp_msg)

    # 11. Encrypt receipt for client using symmetric key derived during request decryption
    receipt_bytes = canonical_json_bytes(receipt.to_dict())
    resp_envelope = encrypt_response(derived_key, receipt_bytes, payload.txn_id)

    return resp_envelope, payload
