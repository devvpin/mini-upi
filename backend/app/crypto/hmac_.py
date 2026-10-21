"""
crypto.hmac_ — Internal service authentication and integrity.

Crypto concept: HMAC-SHA256 message authentication codes with key rotation support.
Threat mitigated: Inter-service message tampering and forgery (Switch <-> Bank).

Features:
- Deterministic canonical message binding: HMAC(K, canonical(payload) || ts || msg_id).
- Constant-time verification using hmac.compare_digest.
- Key ID tagging for zero-downtime key rotation.
"""

from __future__ import annotations

import base64
import hmac
from hashlib import sha256
from typing import Any

from app.crypto.canonical import canonical_json


def compute_service_mac(
    key: bytes,
    payload: Any,
    msg_id: str,
    ts: int | str,
) -> bytes:
    """
    Compute HMAC-SHA256 over canonical(payload) || ts || msg_id.
    """
    body_canonical = canonical_json(payload)
    data = body_canonical + f"{ts}{msg_id}".encode()
    return hmac.new(key, data, sha256).digest()


def sign_service_message(
    key: bytes,
    payload: Any,
    msg_id: str,
    ts: int | str,
    key_id: str = "v1",
) -> dict[str, Any]:
    """
    Produce a signed service envelope with payload, metadata, and HMAC.
    """
    mac = compute_service_mac(key, payload, msg_id, ts)
    return {
        "payload": payload,
        "msg_id": msg_id,
        "ts": ts,
        "key_id": key_id,
        "mac": base64.b64encode(mac).decode("ascii"),
    }


def verify_service_message(
    key: bytes,
    message: dict[str, Any],
) -> bool:
    """
    Verify HMAC on service message in constant time.
    """
    try:
        payload = message["payload"]
        msg_id = str(message["msg_id"])
        ts = message["ts"]
        mac_b64 = message["mac"]
        expected_mac = base64.b64decode(mac_b64)
    except (KeyError, TypeError, ValueError):
        return False

    actual_mac = compute_service_mac(key, payload, msg_id, ts)
    return hmac.compare_digest(actual_mac, expected_mac)
