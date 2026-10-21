"""
test_phase3.py — Phase 3 cryptographic test suite.

Tests every cryptographic primitive and security guarantee required by Phase 3:
1. Canonical JSON serialization matching test vectors, rejecting floats.
2. ECDSA P-256 raw (r || s) ↔ DER conversion, signing, verification, JWK import/export.
3. Envelope encryption (ECDH + HKDF + AES-256-GCM) with AAD binding and negative tests.
4. HMAC-SHA256 service message integrity with key_id.
5. Hash-chained audit log: append, verify, and tamper detection pin-pointing exact seq.
6. Mini-PKI X.509 cert validation: validity window, chain check, role claim mismatch.
7. Anti-replay nonce table and timestamp window enforcement.
8. Device registration, listing, revocation, MPIN 3-strike lockout via API.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.exceptions import InvalidTag
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.core.database import get_db
from app.crypto.canonical import canonical_json, canonical_json_str
from app.crypto.chain import append_audit_entry, verify_audit_chain
from app.crypto.envelope import (
    decrypt_request,
    decrypt_response,
    encrypt_payload,
    encrypt_response,
)
from app.crypto.hmac_ import sign_service_message, verify_service_message
from app.crypto.models import AuditLog
from app.crypto.nonce import check_and_record_nonce, validate_timestamp
from app.crypto.pki import generate_ca, issue_service_cert, verify_certificate
from app.crypto.signing import (
    der_to_raw,
    generate_ecdsa_keypair,
    jwk_to_public_key,
    public_key_to_jwk,
    raw_to_der,
    sign_bytes,
    verify_signature,
)
from app.identity.models import Base, User, UserRole
from app.identity.repository import create_class, create_department, create_user
from app.main import create_app

TEST_PEPPER = "test-static-pepper-value-for-phase3-testing-minimum-32"
TEST_JWT_SECRET = "test-jwt-secret-phase3-testing-minimum-32-chars-long"
TEST_AUDIT_KEY = "test-audit-key-phase3-testing-minimum-32-chars-long"
TEST_MAC_KEY = "test-mac-key-phase3-testing-minimum-32-chars-long"


@pytest.fixture(autouse=True)
def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("PEPPER", TEST_PEPPER)
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setenv("AUDIT_HMAC_KEY", TEST_AUDIT_KEY)
    monkeypatch.setenv("SWITCH_BANK_MAC_KEY", TEST_MAC_KEY)
    monkeypatch.setenv("APP_ENV", "test")
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def async_db() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def app_client(async_db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    # Reset server key cache to avoid stale CA certs between tests
    import app.crypto.server_key as sk
    sk._cached_private_key = None
    sk._cached_cert = None
    sk._cached_ca_cert = None

    app = create_app()

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield async_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ── 1. Canonical JSON Tests ──────────────────────────────────────────────────


def test_canonical_json_vectors() -> None:
    """Verify canonical JSON serializer against shared cross-language vectors."""
    vector_path = Path(__file__).parent / "vectors" / "canonical.json"
    with open(vector_path, encoding="utf-8") as f:
        vectors = json.load(f)

    for vec in vectors:
        actual = canonical_json_str(vec["input"])
        assert actual == vec["expected"], f"Failed on: {vec['description']}"


def test_canonical_json_rejects_floats() -> None:
    """Ensure floating point numbers are strictly forbidden in canonical JSON."""
    with pytest.raises(ValueError, match="Floats are prohibited"):
        canonical_json({"amount": 10.5})


# ── 2. ECDSA Signing and IEEE P1363 / DER Conversion ─────────────────────────


def test_ecdsa_raw_der_conversion_and_signing() -> None:
    """Test ECDSA keypair generation, raw (r || s) <-> DER conversions, and verification."""
    priv, pub = generate_ecdsa_keypair()
    data = b"transfer:alice->bob:50000"

    der_sig = sign_bytes(priv, data, raw=False)
    assert verify_signature(pub, data, der_sig) is True

    raw_sig = der_to_raw(der_sig)
    assert len(raw_sig) == 64

    converted_der = raw_to_der(raw_sig)
    assert verify_signature(pub, data, converted_der) is True
    assert verify_signature(pub, data, raw_sig) is True

    tampered_raw = bytearray(raw_sig)
    tampered_raw[10] ^= 0xFF
    assert verify_signature(pub, data, bytes(tampered_raw)) is False
    assert verify_signature(pub, b"tampered-data", raw_sig) is False


def test_ecdsa_jwk_roundtrip() -> None:
    """Test EC P-256 public key export to and import from JWK format."""
    priv, pub = generate_ecdsa_keypair()
    jwk = public_key_to_jwk(pub)
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"

    imported_pub = jwk_to_public_key(jwk)
    data = b"test-jwk-verification"
    der_sig = sign_bytes(priv, data)
    assert verify_signature(imported_pub, data, der_sig) is True


# ── 3. Envelope Encryption & Decryption ──────────────────────────────────────


def test_envelope_encryption_roundtrip() -> None:
    """Test client -> server request encryption and server -> client response encryption."""
    server_priv, server_pub = generate_ecdsa_keypair()
    plaintext = b'{"action":"pay","amount_paise":50000}'
    txn_id = str(uuid.uuid4())
    ts = 1700000000

    req_env = encrypt_payload(server_pub, plaintext, txn_id=txn_id, ts=ts)
    assert req_env["v"] == 1

    decrypted_request, derived_key = decrypt_request(server_priv, req_env)
    assert decrypted_request == plaintext

    resp_plaintext = b'{"status":"SUCCESS","balance_paise":45000}'
    resp_env = encrypt_response(derived_key, resp_plaintext, txn_id=txn_id)

    decrypted_response = decrypt_response(derived_key, resp_env, txn_id=txn_id)
    assert decrypted_response == resp_plaintext


def test_envelope_negative_tests() -> None:
    """Tampering with ciphertext, tag, AAD, or keys must cause decryption failure."""
    server_priv, server_pub = generate_ecdsa_keypair()
    plaintext = b"confidential payment data"
    txn_id = str(uuid.uuid4())
    ts = 1700000000

    req_env = encrypt_payload(server_pub, plaintext, txn_id=txn_id, ts=ts)

    # Flipped ciphertext bit
    ct_bytes = bytearray(base64.b64decode(req_env["ct"]))
    ct_bytes[0] ^= 0x01
    bad_env = dict(req_env, ct=base64.b64encode(ct_bytes).decode())
    with pytest.raises(InvalidTag):
        decrypt_request(server_priv, bad_env)

    # Flipped tag bit
    tag_bytes = bytearray(base64.b64decode(req_env["tag"]))
    tag_bytes[0] ^= 0x01
    bad_tag_env = dict(req_env, tag=base64.b64encode(tag_bytes).decode())
    with pytest.raises(InvalidTag):
        decrypt_request(server_priv, bad_tag_env)

    # Wrong AAD (tampered txn_id)
    bad_txn_env = dict(req_env, txn_id=str(uuid.uuid4()))
    with pytest.raises(InvalidTag):
        decrypt_request(server_priv, bad_txn_env)

    # Wrong AAD (tampered timestamp)
    bad_ts_env = dict(req_env, ts=ts + 1)
    with pytest.raises(InvalidTag):
        decrypt_request(server_priv, bad_ts_env)

    # Wrong server private key
    wrong_priv, _ = generate_ecdsa_keypair()
    with pytest.raises(InvalidTag):
        decrypt_request(wrong_priv, req_env)


# ── 4. HMAC Service Message Integrity ────────────────────────────────────────


def test_hmac_service_message_signing_and_verification() -> None:
    """HMAC-SHA256 message authentication and constant-time verification."""
    key = b"service-secret-switch-bank-test-key-32b!"
    payload = {"from_acc": "123", "to_acc": "456", "amount": 1000}
    msg_id = "msg-987"
    ts = 1700000000

    msg = sign_service_message(key, payload, msg_id, ts, key_id="v1")
    assert msg["key_id"] == "v1"
    assert verify_service_message(key, msg) is True

    tampered_msg = dict(msg, payload={"from_acc": "123", "to_acc": "456", "amount": 2000})
    assert verify_service_message(key, tampered_msg) is False

    assert verify_service_message(b"wrong-key-32-bytes-long!!!!!!!!", msg) is False


# ── 5. Hash-Chained Audit Log and Tamper Detection ───────────────────────────


@pytest.mark.asyncio
async def test_audit_hash_chain_and_tamper_pinpointing(async_db: AsyncSession) -> None:
    """
    Hash-chained audit log: sequential append, verification,
    and manual tamper detection pinpointing exact sequence number.
    """
    audit_key = TEST_AUDIT_KEY.encode("utf-8")

    for i in range(1, 6):
        await append_audit_entry(
            session=async_db,
            event_type=f"EVENT_{i}",
            payload={"action": f"test_{i}", "index": i},
            audit_hmac_key=audit_key,
        )
    await async_db.commit()

    report = await verify_audit_chain(async_db, audit_key)
    assert report["ok"] is True
    assert report["checked"] == 5
    assert report["first_bad_seq"] is None

    # Tamper with row 3's payload
    stmt = select(AuditLog).where(AuditLog.seq == 3)
    entry_3 = (await async_db.execute(stmt)).scalar_one()
    entry_3.payload_json = {"action": "tampered_action", "index": 3}
    await async_db.commit()

    tampered_report = await verify_audit_chain(async_db, audit_key)
    assert tampered_report["ok"] is False
    assert tampered_report["first_bad_seq"] == 3
    assert "seq=3" in str(tampered_report["error"])


# ── 6. Mini PKI and Certificate Validation ───────────────────────────────────


def test_pki_ca_and_certificate_validation() -> None:
    """Root CA issuance, validity window, signature validation, and role claim check."""
    ca_key, ca_cert = generate_ca(validity_days=365)

    _psp_key, psp_cert = issue_service_cert(ca_key, ca_cert, role="PSP", common_name="GCET PSP")
    valid, reason = verify_certificate(ca_cert, psp_cert, expected_role="PSP")
    assert valid is True

    valid, reason = verify_certificate(ca_cert, psp_cert, expected_role="BANK")
    assert valid is False
    assert "Role mismatch" in str(reason)

    past_time = datetime.now(UTC) + timedelta(days=400)
    valid, reason = verify_certificate(ca_cert, psp_cert, expected_role="PSP", now=past_time)
    assert valid is False
    assert "expired" in str(reason).lower()

    _fake_ca_key, fake_ca_cert = generate_ca()
    valid, reason = verify_certificate(fake_ca_cert, psp_cert, expected_role="PSP")
    assert valid is False
    assert "verification failed" in str(reason).lower() or "signature" in str(reason).lower()


# ── 7. Replay Protection & Timestamp Window ──────────────────────────────────


@pytest.mark.asyncio
async def test_nonce_replay_and_timestamp_window(async_db: AsyncSession) -> None:
    """Timestamp window validation and duplicate nonce consumption rejection."""
    test_user = User(
        id=uuid.uuid4(),
        role=UserRole.ADMIN,
        college_id="NONCE_ADMIN01",
        full_name="Nonce Admin",
        email="nonce_admin01@gcet.edu",
        password_hash="test",
        must_change_password=False,
    )
    async_db.add(test_user)
    await async_db.commit()

    now = datetime.now(UTC)
    ok, _ = validate_timestamp(now.timestamp(), window_seconds=60)
    assert ok is True

    ok, err = validate_timestamp((now - timedelta(seconds=90)).timestamp(), window_seconds=60)
    assert ok is False
    assert "outside acceptance window" in str(err)

    nonce_val = "unique-nonce-12345"
    ok, _ = await check_and_record_nonce(async_db, nonce_val, test_user.id, window_seconds=60)
    assert ok is True

    ok, err = await check_and_record_nonce(async_db, nonce_val, test_user.id, window_seconds=60)
    assert ok is False
    assert "Replay attack detected" in str(err)


# ── 8. Device Registration, MPIN Lockout via API ─────────────────────────────


@pytest.mark.asyncio
async def test_device_and_mpin_endpoints(
    app_client: AsyncClient,
    async_db: AsyncSession,
) -> None:
    """
    Integration test for device registration, listing, revocation,
    and MPIN 3-strike lockout via API endpoints.
    """
    from app.crypto.kdf import hash_secret

    settings = get_settings()

    # Create a test user
    dept = await create_department(async_db, code="cr", name="Crypto Dept")
    cls = await create_class(async_db, department_id=dept.id, name="TY-CR-A", year=3, division="A")
    user = await create_user(
        async_db,
        college_id="21CR001",
        full_name="Crypto Student",
        email="21cr001@gcet.edu",
        role=UserRole.STUDENT,
        password_hash=hash_secret(
            "Student@21CR001", settings.pepper, time_cost=1, memory_cost=1024
        ),
        department_id=dept.id,
        class_id=cls.id,
    )
    user.must_change_password = False
    await async_db.commit()

    # 1. Public server key endpoint
    srv_key_res = await app_client.get("/api/v1/crypto/server-key")
    assert srv_key_res.status_code == 200
    data = srv_key_res.json()
    assert data["algorithm"] == "ECDH-P256-AES256GCM"
    assert "public_key" in data and "cert_pem" in data

    # 2. Login
    login_res = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "21CR001", "password": "Student@21CR001"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}

    # 3. Register device
    _priv, pub = generate_ecdsa_keypair()
    jwk = public_key_to_jwk(pub)
    reg_res = await app_client.post(
        "/api/v1/devices/register",
        json={"public_key_jwk": jwk, "label": "Alice Pixel 8"},
        headers=auth,
    )
    assert reg_res.status_code == 201
    device_data = reg_res.json()
    device_id = device_data["id"]
    assert device_data["status"] == "active"

    # 4. List devices
    list_res = await app_client.get("/api/v1/devices", headers=auth)
    assert list_res.status_code == 200
    assert any(d["id"] == device_id for d in list_res.json())

    # 5. Set MPIN
    set_res = await app_client.post(
        "/api/v1/mpin/set", json={"mpin": "123456"}, headers=auth
    )
    assert set_res.status_code == 200

    # 6. Verify correct MPIN
    verify_ok = await app_client.post(
        "/api/v1/mpin/verify", json={"mpin": "123456"}, headers=auth
    )
    assert verify_ok.status_code == 200

    # 7. 3-strike lockout: 2 bad + 1 bad (trigger)
    for _ in range(2):
        bad_res = await app_client.post(
            "/api/v1/mpin/verify", json={"mpin": "999999"}, headers=auth
        )
        assert bad_res.status_code == 401

    strike_3 = await app_client.post(
        "/api/v1/mpin/verify", json={"mpin": "999999"}, headers=auth
    )
    assert strike_3.status_code == 423
    assert "locked" in strike_3.json()["detail"].lower()

    # Correct MPIN while locked → still 423
    locked_res = await app_client.post(
        "/api/v1/mpin/verify", json={"mpin": "123456"}, headers=auth
    )
    assert locked_res.status_code == 423

    # 8. Revoke device
    revoke_res = await app_client.delete(
        f"/api/v1/devices/{device_id}", headers=auth
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "revoked"
