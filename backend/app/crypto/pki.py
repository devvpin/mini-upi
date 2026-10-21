"""
crypto.pki — Public Key Infrastructure (PKI) and X.509 certificate validation.

Crypto concept: Hierarchical trust model with digital certificates (X.509 v3).
Threat mitigated: Man-in-the-middle, rogue service impersonation, unauthorized service roles.

Rules:
- Root CA signs service certificates for PSP, Switch, and Bank.
- Certs embed role in OrganizationalUnitName (OU).
- Validation verifies signature chain, validity window, and role claim.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_ca(
    validity_days: int = 3650,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate offline Root CA ECDSA P-256 keypair and self-signed X.509 cert."""
    ca_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GCET Campus"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Mini-UPI Root CA"),
        ]
    )

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return ca_key, cert


def issue_service_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    role: Literal["PSP", "SWITCH", "BANK", "SERVER"],
    common_name: str,
    validity_days: int = 365,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Issue a role-constrained service certificate signed by Root CA."""
    service_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GCET Campus"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(service_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_agreement=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(f"{role.lower()}.gcet.internal")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return service_key, cert


def load_certificate_pem(pem_bytes: bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM-encoded bytes."""
    return x509.load_pem_x509_certificate(pem_bytes)


def certificate_to_pem(cert: x509.Certificate) -> str:
    """Serialize an X.509 certificate to PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def extract_role_from_cert(cert: x509.Certificate) -> str | None:
    """Extract role claim from certificate OrganizationalUnit (OU) or CommonName (CN)."""
    ou_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if ou_attrs:
        return str(ou_attrs[0].value)

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        cn_val = str(cn_attrs[0].value)
        for role in ("PSP", "SWITCH", "BANK", "SERVER"):
            if role in cn_val.upper():
                return role
    return None


def verify_certificate(
    ca_cert: x509.Certificate,
    cert: x509.Certificate,
    expected_role: str | None = None,
    now: datetime | None = None,
) -> tuple[bool, str | None]:
    """
    Verify an X.509 certificate against the Root CA.

    Checks:
    1. Validity period (not_before <= now <= not_after).
    2. Cryptographic signature issued directly by CA.
    3. Role claim in subject matches expected_role.

    Returns:
        tuple (is_valid: bool, error_reason: str | None)
    """
    check_time = now or datetime.now(UTC)

    # 1. Validity window
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        # Compatibility with older cryptography versions
        not_before = cert.not_valid_before.replace(tzinfo=UTC)
        not_after = cert.not_valid_after.replace(tzinfo=UTC)

    if check_time < not_before:
        return False, f"Certificate not yet valid (valid from {not_before.isoformat()})"
    if check_time > not_after:
        return False, f"Certificate expired (expired at {not_after.isoformat()})"

    # 2. Signature verification
    try:
        cert.verify_directly_issued_by(ca_cert)
    except Exception as e:
        return False, f"Signature verification failed against CA: {e}"

    # 3. Role check
    if expected_role is not None:
        actual_role = extract_role_from_cert(cert)
        if actual_role is None or actual_role.upper() != expected_role.upper():
            return (
                False,
                f"Role mismatch: certificate role '{actual_role}' "
                f"does not match expected '{expected_role}'",
            )

    return True, None
