"""
messaging.crypto — Signing, MACing, and verification helpers for inter-module messages.

Crypto concept: Digital signatures and HMAC authentication ensuring end-to-end chain of custody.
Threat mitigated: Rogue service message tampering, MITM replay, fraudulent bank receipt generation.
"""

from __future__ import annotations

import base64
import time
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto.canonical import canonical_json_bytes
from app.crypto.hmac_ import sign_service_message, verify_service_message
from app.crypto.pki import certificate_to_pem, load_certificate_pem, verify_certificate
from app.crypto.signing import (
    der_to_raw,
    raw_to_der,
    sign_bytes,
    verify_signature,
)
from app.messaging.schemas import (
    BankReceipt,
    PaymentPayload,
    PspToSwitchMessage,
    SwitchToBankMessage,
)


def sign_psp_message(
    psp_key: ec.EllipticCurvePrivateKey,
    psp_cert: x509.Certificate,
    payload: PaymentPayload,
    psp_id: str = "gcet-campus-psp",
) -> PspToSwitchMessage:
    """Sign payment routing payload with PSP private key."""
    psp_ts = int(time.time())
    signable = {
        "payload": payload.model_dump(),
        "psp_id": psp_id,
        "psp_ts": psp_ts,
    }
    data = canonical_json_bytes(signable)
    der_sig = sign_bytes(psp_key, data)
    raw_sig = der_to_raw(der_sig)
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")

    return PspToSwitchMessage(
        payload=payload,
        psp_id=psp_id,
        psp_cert_pem=certificate_to_pem(psp_cert),
        psp_signature=sig_b64,
        psp_ts=psp_ts,
    )


def verify_psp_message(
    ca_cert: x509.Certificate,
    msg: PspToSwitchMessage,
) -> tuple[bool, str | None]:
    """Verify PSP certificate chain, role (OU=PSP), and cryptographic signature."""
    try:
        psp_cert = load_certificate_pem(msg.psp_cert_pem.encode("ascii"))
    except Exception as e:
        return False, f"Invalid PSP certificate PEM: {e}"

    # 1. Verify cert chain and role
    valid_cert, err = verify_certificate(ca_cert, psp_cert, expected_role="PSP")
    if not valid_cert:
        return False, f"PSP certificate invalid: {err}"

    # 2. Verify signature
    signable = {
        "payload": msg.payload.model_dump(),
        "psp_id": msg.psp_id,
        "psp_ts": msg.psp_ts,
    }
    data = canonical_json_bytes(signable)
    try:
        raw_sig = base64.b64decode(msg.psp_signature)
        der_sig = raw_to_der(raw_sig)
    except Exception as e:
        return False, f"Malformed signature format: {e}"

    pub_key = psp_cert.public_key()
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        return False, "PSP certificate public key is not an EllipticCurvePublicKey"

    if not verify_signature(pub_key, data, der_sig):
        return False, "PSP signature verification failed"

    return True, None


def create_switch_to_bank_message(
    payload: PaymentPayload,
    payer_account_id: str,
    payee_account_id: str,
    mac_key: bytes,
    switch_id: str = "gcet-campus-switch",
    key_id: str = "v1",
) -> SwitchToBankMessage:
    """Authenticate Switch-to-Bank transfer instruction using HMAC-SHA256."""
    ts = int(time.time())
    message_content = {
        "payer_account_id": payer_account_id,
        "payee_account_id": payee_account_id,
        "payload": payload.model_dump(),
        "switch_id": switch_id,
    }
    sig_envelope = sign_service_message(
        key=mac_key,
        payload=message_content,
        msg_id=payload.txn_id,
        ts=ts,
        key_id=key_id,
    )

    return SwitchToBankMessage(
        payload=payload,
        payer_account_id=payer_account_id,
        payee_account_id=payee_account_id,
        switch_id=switch_id,
        ts=ts,
        key_id=key_id,
        mac=sig_envelope["mac"],
    )


def verify_switch_to_bank_message(
    msg: SwitchToBankMessage,
    mac_key: bytes,
) -> tuple[bool, str | None]:
    """Verify Switch-to-Bank HMAC-SHA256 integrity and key_id."""
    message_content = {
        "payer_account_id": msg.payer_account_id,
        "payee_account_id": msg.payee_account_id,
        "payload": msg.payload.model_dump(),
        "switch_id": msg.switch_id,
    }
    envelope = {
        "payload": message_content,
        "msg_id": msg.payload.txn_id,
        "ts": msg.ts,
        "key_id": msg.key_id,
        "mac": msg.mac,
    }

    if not verify_service_message(mac_key, envelope):
        return False, "Switch-to-Bank HMAC service MAC verification failed"

    return True, None


def create_bank_receipt(
    bank_key: ec.EllipticCurvePrivateKey,
    bank_cert: x509.Certificate,
    txn_id: str,
    payer_vpa: str,
    payee_vpa: str,
    amount_paise: int,
    note: str | None,
    chain_seq: int,
    chain_hash: str,
    completed_at: str | None = None,
) -> BankReceipt:
    """Generate Bank-signed receipt committing transaction completion and audit hash."""
    ts_str = completed_at or datetime.now(UTC).isoformat()
    receipt_data = {
        "amount_paise": amount_paise,
        "chain_hash": chain_hash,
        "chain_seq": chain_seq,
        "completed_at": ts_str,
        "note": note,
        "payee_vpa": payee_vpa,
        "payer_vpa": payer_vpa,
        "status": "SUCCESS",
        "txn_id": txn_id,
    }

    data = canonical_json_bytes(receipt_data)
    der_sig = sign_bytes(bank_key, data)
    raw_sig = der_to_raw(der_sig)
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")

    return BankReceipt(
        txn_id=txn_id,
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=amount_paise,
        note=note,
        status="SUCCESS",
        completed_at=ts_str,
        bank_cert_pem=certificate_to_pem(bank_cert),
        bank_signature=sig_b64,
        chain_seq=chain_seq,
        chain_hash=chain_hash,
    )


def verify_bank_receipt(
    ca_cert: x509.Certificate,
    receipt: BankReceipt,
) -> tuple[bool, str | None]:
    """Verify Bank receipt certificate chain, role (OU=BANK), and signature."""
    try:
        bank_cert = load_certificate_pem(receipt.bank_cert_pem.encode("ascii"))
    except Exception as e:
        return False, f"Invalid Bank certificate PEM: {e}"

    # 1. Verify cert chain and role
    valid_cert, err = verify_certificate(ca_cert, bank_cert, expected_role="BANK")
    if not valid_cert:
        return False, f"Bank certificate invalid: {err}"

    # 2. Verify signature
    receipt_data = {
        "amount_paise": receipt.amount_paise,
        "chain_hash": receipt.chain_hash,
        "chain_seq": receipt.chain_seq,
        "completed_at": receipt.completed_at,
        "note": receipt.note,
        "payee_vpa": receipt.payee_vpa,
        "payer_vpa": receipt.payer_vpa,
        "status": receipt.status,
        "txn_id": receipt.txn_id,
    }
    data = canonical_json_bytes(receipt_data)
    try:
        raw_sig = base64.b64decode(receipt.bank_signature)
        der_sig = raw_to_der(raw_sig)
    except Exception as e:
        return False, f"Malformed signature format: {e}"

    pub_key = bank_cert.public_key()
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        return False, "Bank certificate public key is not an EllipticCurvePublicKey"

    if not verify_signature(pub_key, data, der_sig):
        return False, "Bank receipt signature verification failed"

    return True, None
