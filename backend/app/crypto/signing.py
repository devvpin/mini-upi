"""
crypto.signing — ECDSA P-256 digital signature utilities.

Crypto concept: Digital signatures with ECDSA (secp256r1 / P-256) and SHA-256.
Threat mitigated: Transaction tampering, impersonation, repudiation.

Features:
- Seamless conversion between IEEE P1363 raw 64-byte (r || s) format used by
  WebCrypto and ASN.1 DER format used by OpenSSL/cryptography.
- JWK import and export for browser public keys.
- Constant-time and secure verification with explicit error handling.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string with optional padding."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes as unpadded base64url string."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def raw_to_der(raw_sig: bytes) -> bytes:
    """
    Convert IEEE P1363 raw 64-byte (r || s) ECDSA signature to ASN.1 DER.

    WebCrypto produces 64-byte raw signatures (32 bytes r + 32 bytes s).
    OpenSSL / cryptography library requires DER format.
    """
    if len(raw_sig) != 64:
        raise ValueError(f"Expected 64-byte raw signature, got {len(raw_sig)} bytes")
    r = int.from_bytes(raw_sig[:32], byteorder="big")
    s = int.from_bytes(raw_sig[32:], byteorder="big")
    return encode_dss_signature(r, s)


def der_to_raw(der_sig: bytes) -> bytes:
    """
    Convert ASN.1 DER ECDSA signature to IEEE P1363 raw 64-byte (r || s).

    Useful for sending signatures from Python backend to browser WebCrypto.
    """
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


def jwk_to_public_key(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """
    Parse an EC P-256 public key from JWK format.

    Expects:
        { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
    """
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Invalid JWK: must be kty='EC' and crv='P-256'")

    x_b64 = jwk.get("x")
    y_b64 = jwk.get("y")
    if not isinstance(x_b64, str) or not isinstance(y_b64, str):
        raise ValueError("JWK missing 'x' or 'y' coordinate")

    x_bytes = _b64url_decode(x_b64)
    y_bytes = _b64url_decode(y_b64)

    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("JWK coordinates must be 32 bytes for P-256")

    x_int = int.from_bytes(x_bytes, byteorder="big")
    y_int = int.from_bytes(y_bytes, byteorder="big")

    public_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
    return public_numbers.public_key()


def public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Convert an EC P-256 public key to JWK format."""
    public_numbers = public_key.public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, byteorder="big")
    y_bytes = public_numbers.y.to_bytes(32, byteorder="big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(x_bytes),
        "y": _b64url_encode(y_bytes),
    }


def generate_ecdsa_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a fresh ECDSA P-256 keypair."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def sign_bytes(
    private_key: ec.EllipticCurvePrivateKey,
    data: bytes,
    raw: bool = False,
) -> bytes:
    """
    Sign data with ECDSA-SHA256.

    If raw=True, returns 64-byte (r || s). Otherwise returns DER.
    """
    der_sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    if raw:
        return der_to_raw(der_sig)
    return der_sig


def verify_signature(
    public_key: ec.EllipticCurvePublicKey,
    data: bytes,
    signature: bytes,
) -> bool:
    """
    Verify ECDSA-SHA256 signature against data.

    Accepts either raw 64-byte signature or DER signature.
    Returns True if valid, False otherwise. Never throws on invalid signature.
    """
    if len(signature) == 64:
        try:
            der_sig = raw_to_der(signature)
        except Exception:
            return False
    else:
        der_sig = signature

    try:
        public_key.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def load_private_key_pem(
    pem_bytes: bytes, password: bytes | None = None
) -> ec.EllipticCurvePrivateKey:
    """Load an EC private key from PEM bytes."""
    key = serialization.load_pem_private_key(pem_bytes, password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Loaded key is not an EllipticCurvePrivateKey")
    return key


def load_public_key_pem(pem_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Load an EC public key from PEM bytes."""
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Loaded key is not an EllipticCurvePublicKey")
    return key
