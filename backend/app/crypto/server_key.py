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


_cached_ca_key: ec.EllipticCurvePrivateKey | None = None
_cached_psp_key: ec.EllipticCurvePrivateKey | None = None
_cached_psp_cert: x509.Certificate | None = None
_cached_bank_key: ec.EllipticCurvePrivateKey | None = None
_cached_bank_cert: x509.Certificate | None = None


def get_root_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Retrieve or generate root CA key and certificate."""
    global _cached_ca_key, _cached_ca_cert
    if _cached_ca_key is not None and _cached_ca_cert is not None:
        return _cached_ca_key, _cached_ca_cert

    settings = get_settings()
    ca_path = Path(settings.ca_cert_path)
    ca_key_path = Path(settings.ca_key_path)
    if ca_path.exists() and ca_key_path.exists():
        _cached_ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
        _cached_ca_key = load_private_key_pem(ca_key_path.read_bytes())
        return _cached_ca_key, _cached_ca_cert

    ca_key, ca_cert = generate_ca(validity_days=365)
    _cached_ca_key = ca_key
    _cached_ca_cert = ca_cert
    return _cached_ca_key, _cached_ca_cert


def get_psp_service_keys() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate, x509.Certificate]:
    """Retrieve or generate PSP service keypair and X.509 cert signed by Root CA."""
    global _cached_psp_key, _cached_psp_cert
    ca_key, ca_cert = get_root_ca()

    if _cached_psp_key is not None and _cached_psp_cert is not None:
        return _cached_psp_key, _cached_psp_cert, ca_cert

    settings = get_settings()
    key_path = Path(settings.psp_key_path)
    cert_path = Path(settings.psp_cert_path)
    if key_path.exists() and cert_path.exists():
        _cached_psp_key = load_private_key_pem(key_path.read_bytes())
        _cached_psp_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return _cached_psp_key, _cached_psp_cert, ca_cert

    psp_key, psp_cert = issue_service_cert(ca_key, ca_cert, role="PSP", common_name="GCET Campus PSP")
    _cached_psp_key = psp_key
    _cached_psp_cert = psp_cert
    return _cached_psp_key, _cached_psp_cert, ca_cert


def get_bank_service_keys() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate, x509.Certificate]:
    """Retrieve or generate Bank service keypair and X.509 cert signed by Root CA."""
    global _cached_bank_key, _cached_bank_cert
    ca_key, ca_cert = get_root_ca()

    if _cached_bank_key is not None and _cached_bank_cert is not None:
        return _cached_bank_key, _cached_bank_cert, ca_cert

    settings = get_settings()
    key_path = Path(settings.bank_key_path)
    cert_path = Path(settings.bank_cert_path)
    if key_path.exists() and cert_path.exists():
        _cached_bank_key = load_private_key_pem(key_path.read_bytes())
        _cached_bank_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return _cached_bank_key, _cached_bank_cert, ca_cert

    bank_key, bank_cert = issue_service_cert(
        ca_key, ca_cert, role="BANK", common_name="GCET Campus Bank"
    )
    _cached_bank_key = bank_key
    _cached_bank_cert = bank_cert
    return _cached_bank_key, _cached_bank_cert, ca_cert


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

    ca_key, ca_cert = get_root_ca()
    settings = get_settings()

    key_path = Path(settings.server_ecdh_key_path)
    cert_path = Path(settings.server_cert_path)

    if key_path.exists() and cert_path.exists():
        _cached_private_key = load_private_key_pem(key_path.read_bytes())
        _cached_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        _cached_ca_cert = ca_cert
        return _cached_private_key, _cached_private_key.public_key(), _cached_cert, _cached_ca_cert

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
