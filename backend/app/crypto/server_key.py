"""
crypto.server_key — Server cryptographic identity and key management.

Crypto concept: CA-signed server public key distribution and static ECDH endpoint.
Threat mitigated: Rogue server spoofing, unauthorized MITM key injection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app.core.config import get_settings
from app.crypto.pki import certificate_to_pem, generate_ca, issue_service_cert
from app.crypto.signing import (
    load_private_key_pem,
    public_key_to_jwk,
)

_cached_private_key: ec.EllipticCurvePrivateKey | None = None
_cached_cert: x509.Certificate | None = None
_cached_ca_cert: x509.Certificate | None = None


def get_server_ecdh_keys() -> tuple[
    ec.EllipticCurvePrivateKey,
    ec.EllipticCurvePublicKey,
    x509.Certificate,
    x509.Certificate,
]:
    """
    Load or lazily initialize the server ECDH static keypair and its CA-signed cert.
    """
    global _cached_private_key, _cached_cert, _cached_ca_cert
    if _cached_private_key is not None and _cached_cert is not None and _cached_ca_cert is not None:
        return _cached_private_key, _cached_private_key.public_key(), _cached_cert, _cached_ca_cert

    settings = get_settings()

    # Try loading from configured paths if they exist
    key_path = Path(settings.server_ecdh_key_path)
    cert_path = Path(settings.psp_cert_path)
    ca_path = Path(settings.ca_cert_path)

    if key_path.exists() and cert_path.exists() and ca_path.exists():
        _cached_private_key = load_private_key_pem(key_path.read_bytes())
        _cached_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        _cached_ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
        return _cached_private_key, _cached_private_key.public_key(), _cached_cert, _cached_ca_cert

    # Generate ephemeral dev/test Root CA and server cert if not on disk
    ca_key, ca_cert = generate_ca(validity_days=365)
    server_key, server_cert = issue_service_cert(
        ca_key, ca_cert, role="SERVER", common_name="Mini-UPI Server"
    )

    _cached_private_key = server_key
    _cached_cert = server_cert
    _cached_ca_cert = ca_cert

    return _cached_private_key, _cached_private_key.public_key(), _cached_cert, _cached_ca_cert


def get_server_key_payload() -> dict[str, Any]:
    """Format the public server key endpoint response."""
    _priv, pub, cert, ca_cert = get_server_ecdh_keys()
    return {
        "v": 1,
        "algorithm": "ECDH-P256-AES256GCM",
        "public_key": public_key_to_jwk(pub),
        "cert_pem": certificate_to_pem(cert),
        "ca_cert_pem": certificate_to_pem(ca_cert),
    }
