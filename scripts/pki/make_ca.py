"""
scripts/pki/make_ca.py — Mini-PKI Root CA and service certificate issuer.

Crypto concept: Offline root Certification Authority (CA) issuing role-constrained
X.509 v3 certificates with ECDSA P-256 and SHA-256.
Threat mitigated: Rogue service insertion, TLS/Service-level spoofing.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
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

    now = datetime.now(timezone.utc)
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

    now = datetime.now(timezone.utc)
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


def save_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def save_cert(cert: x509.Certificate, path: Path) -> None:
    pem = cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Root CA and Service Certs")
    parser.add_argument("--out-dir", default="scripts/pki/out", help="Output directory")
    args = parser.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("Generating Root CA...")
    ca_key, ca_cert = generate_ca()
    save_key(ca_key, out / "ca_key.pem")
    save_cert(ca_cert, out / "ca_cert.pem")

    for role in ("PSP", "SWITCH", "BANK", "SERVER"):
        print(f"Issuing {role} certificate...")
        s_key, s_cert = issue_service_cert(ca_key, ca_cert, role=role, common_name=f"Mini-UPI {role}")
        save_key(s_key, out / f"{role.lower()}_key.pem")
        save_cert(s_cert, out / f"{role.lower()}_cert.pem")

    print(f"Certificates successfully generated in {out}")


if __name__ == "__main__":
    main()
