"""
crypto.envelope — Application-layer envelope encryption.

Crypto concept: Hybrid encryption using ECDH (P-256) + HKDF-SHA256 + AES-256-GCM.
Threat mitigated: Eavesdropping, TLS termination interception, payload tampering.

Protocol specification:
1. Client generates ephemeral P-256 keypair: (e_priv, e_pub).
2. Shared secret: shared = ECDH(e_priv, server_static_pub).
3. Symmetric key: key = HKDF-SHA256(shared, salt=random 16B, info=b"miniupi/v1/envelope", L=32).
4. Encryption: (ct, tag) = AES-256-GCM(key, iv=random 12B, plaintext, AAD = txn_id || ts).
5. Transmitted payload:
   {
       "v": 1,
       "eph_pub": <JWK dict>,
       "salt": <b64>,
       "iv": <b64>,
       "ct": <b64>,
       "tag": <b64>,
       "txn_id": <str>,
       "ts": <int | str>
   }
6. Response encryption: Encrypt response with the same derived key,
   fresh 12B IV, and AAD = txn_id || "resp".
"""

from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.crypto.signing import jwk_to_public_key, public_key_to_jwk

ENVELOPE_INFO = b"miniupi/v1/envelope"
SALT_LEN = 16
IV_LEN = 12
KEY_LEN = 32
TAG_LEN = 16


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    return base64.b64decode(data)


def derive_shared_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    salt: bytes,
) -> bytes:
    """
    Derive 256-bit symmetric key from ECDH shared secret using HKDF-SHA256.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        info=ENVELOPE_INFO,
    )
    return hkdf.derive(shared_secret)


def encrypt_payload(
    server_public_key: ec.EllipticCurvePublicKey,
    plaintext: bytes,
    txn_id: str,
    ts: int | str,
) -> dict[str, Any]:
    """
    Encrypt plaintext for server using a fresh ephemeral keypair.
    Used by client or client simulation.
    """
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key()

    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_shared_key(eph_priv, server_public_key, salt)

    aad = f"{txn_id}{ts}".encode()
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, aad)

    ct = ct_with_tag[:-TAG_LEN]
    tag = ct_with_tag[-TAG_LEN:]

    return {
        "v": 1,
        "eph_pub": public_key_to_jwk(eph_pub),
        "salt": _b64_encode(salt),
        "iv": _b64_encode(iv),
        "ct": _b64_encode(ct),
        "tag": _b64_encode(tag),
        "txn_id": txn_id,
        "ts": ts,
    }


def decrypt_request(
    server_private_key: ec.EllipticCurvePrivateKey,
    envelope: dict[str, Any],
) -> tuple[bytes, bytes]:
    """
    Decrypt an incoming request envelope.

    Returns:
        tuple of (plaintext_bytes, derived_symmetric_key)
        The symmetric key is returned so the caller can encrypt the response.
    """
    version = envelope.get("v")
    if version != 1:
        raise ValueError(f"Unsupported envelope version: {version}")

    eph_pub_jwk = envelope.get("eph_pub")
    if not isinstance(eph_pub_jwk, dict):
        raise ValueError("Malformed envelope: 'eph_pub' must be a JWK dictionary")

    eph_public_key = jwk_to_public_key(eph_pub_jwk)
    salt = _b64_decode(envelope["salt"])
    iv = _b64_decode(envelope["iv"])
    ct = _b64_decode(envelope["ct"])
    tag = _b64_decode(envelope["tag"])
    txn_id = str(envelope["txn_id"])
    ts = envelope["ts"]

    if len(salt) != SALT_LEN or len(iv) != IV_LEN or len(tag) != TAG_LEN:
        raise ValueError("Invalid cryptographic parameter length in envelope")

    key = derive_shared_key(server_private_key, eph_public_key, salt)
    aad = f"{txn_id}{ts}".encode()

    aesgcm = AESGCM(key)
    ct_with_tag = ct + tag
    plaintext = aesgcm.decrypt(iv, ct_with_tag, aad)

    return plaintext, key


def encrypt_response(
    derived_key: bytes,
    plaintext: bytes,
    txn_id: str,
) -> dict[str, Any]:
    """
    Encrypt a response using the symmetric key derived during request decryption.
    Uses a fresh 12-byte IV and AAD = txn_id || "resp".
    """
    iv = os.urandom(IV_LEN)
    aad = f"{txn_id}resp".encode()

    aesgcm = AESGCM(derived_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, aad)

    ct = ct_with_tag[:-TAG_LEN]
    tag = ct_with_tag[-TAG_LEN:]

    return {
        "v": 1,
        "iv": _b64_encode(iv),
        "ct": _b64_encode(ct),
        "tag": _b64_encode(tag),
        "txn_id": txn_id,
    }


def decrypt_response(
    derived_key: bytes,
    response_envelope: dict[str, Any],
    txn_id: str,
) -> bytes:
    """
    Decrypt a response envelope using the symmetric key.
    """
    version = response_envelope.get("v")
    if version != 1:
        raise ValueError(f"Unsupported envelope version: {version}")

    iv = _b64_decode(response_envelope["iv"])
    ct = _b64_decode(response_envelope["ct"])
    tag = _b64_decode(response_envelope["tag"])
    aad = f"{txn_id}resp".encode()

    aesgcm = AESGCM(derived_key)
    ct_with_tag = ct + tag
    return aesgcm.decrypt(iv, ct_with_tag, aad)
