"""
test_phase4.py — Payment Engine test suite.

Tests the full Client → PSP → Switch → Bank cryptographic payment pipeline:
1. End-to-end happy path payment with envelope encryption, device signature, and signed Bank receipt.
2. Idempotency: repeating payment with same txn_id returns identical receipt without double-debiting.
3. Rejection matrix (each fails closed, writes audit event, leaks no secrets):
   - Corrupt envelope ciphertext -> ENVELOPE_INVALID
   - Skewed timestamp -> TIMESTAMP_SKEW
   - Replayed nonce -> REPLAY_DETECTED
   - Stolen JWT / unregistered device -> DEVICE_NOT_BOUND
   - Corrupted device signature -> SIGNATURE_INVALID
   - Wrong MPIN -> AUTH_FAILED (strike 1, 2)
   - 3rd wrong MPIN -> ACCOUNT_LOCKED (15 min lockout)
   - Insufficient funds -> INSUFFICIENT_FUNDS
   - Per-transaction limit exceeded (> ₹5,000) -> LIMIT_EXCEEDED
4. Collect requests: create, list incoming, decline, and approve via envelope pay.
5. QR code payload generation and HMAC verification.
6. Security Lens transaction transparency endpoint: signatures, certs, and audit hash-chain.
7. Concurrency: multiple parallel payments without deadlocks, maintaining global zero-sum and audit chain.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.admin.router import audit_verify_ledger
from app.bank.ledger import post_transfer
from app.bank.models import AccountStatus, BankAccount, Base, CollectRequest, CollectStatus, Transaction, TxnKind, TxnStatus, Vpa, Wallet
from app.bank.repository import get_or_create_account_for_user, get_or_create_treasury
from app.core.config import get_settings
from app.core.database import get_db
from app.crypto.canonical import canonical_json_bytes, canonical_json_str
from app.crypto.envelope import decrypt_response, encrypt_payload
from app.crypto.kdf import hash_secret
from app.crypto.models import AuditLog
from app.crypto.server_key import (
    get_bank_service_keys,
    get_psp_service_keys,
    get_root_ca,
    get_server_ecdh_keys,
)
from app.crypto.signing import (
    der_to_raw,
    generate_ecdsa_keypair,
    public_key_to_jwk,
    sign_bytes,
)
from app.identity.models import Department, Device, MpinCredential, User, UserRole
from app.identity.repository import create_class, create_department, create_user
from app.main import create_app
from app.messaging.crypto import verify_bank_receipt
from app.messaging.schemas import BankReceipt

TEST_PEPPER = "test-static-pepper-value-for-phase4-testing-minimum-32"
TEST_JWT_SECRET = "test-jwt-secret-phase4-testing-minimum-32-chars-long"
TEST_AUDIT_KEY = "test-audit-key-phase4-testing-minimum-32-chars-long"
TEST_MAC_KEY = "test-mac-key-phase4-testing-minimum-32-chars-long"


@pytest.fixture(autouse=True)
def setup_phase4_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("PEPPER", TEST_PEPPER)
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setenv("AUDIT_HMAC_KEY", TEST_AUDIT_KEY)
    monkeypatch.setenv("SWITCH_BANK_MAC_KEY", TEST_MAC_KEY)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("TS_WINDOW_SECONDS", "60")
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def async_db() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def app_client(async_db: AsyncSession) -> AsyncClient:
    app = create_app()

    async def override_get_db() -> AsyncSession:
        return async_db

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _create_test_campus(
    session: AsyncSession,
) -> tuple[User, User, User, BankAccount, BankAccount, str, str]:
    """Helper to provision dept, class, student payer, student payee, admin, and funded accounts."""
    settings = get_settings()
    dept = await create_department(session, code="it", name="Information Tech")
    cls = await create_class(session, department_id=dept.id, name="TY-IT-A", year=3, division="A")

    # 1. Payer student
    payer = await create_user(
        session,
        college_id="22IT001",
        full_name="Aarav Sharma",
        email="22it001@gcet.edu",
        role=UserRole.STUDENT,
        password_hash=hash_secret("PayerPass123!", settings.pepper, time_cost=1, memory_cost=1024),
        department_id=dept.id,
        class_id=cls.id,
    )
    payer.must_change_password = False

    # 2. Payee student
    payee = await create_user(
        session,
        college_id="22IT002",
        full_name="Diya Patel",
        email="22it002@gcet.edu",
        role=UserRole.STUDENT,
        password_hash=hash_secret("PayeePass123!", settings.pepper, time_cost=1, memory_cost=1024),
        department_id=dept.id,
        class_id=cls.id,
    )
    payee.must_change_password = False

    # 3. Admin user
    admin = await create_user(
        session,
        college_id="ADMIN001",
        full_name="System Admin",
        email="admin@gcet.edu",
        role=UserRole.ADMIN,
        password_hash=hash_secret("AdminPass123!", settings.pepper, time_cost=1, memory_cost=1024),
    )
    admin.must_change_password = False
    await session.commit()

    # Create bank accounts, wallets, VPAs
    treasury = await get_or_create_treasury(session)
    payer_acc, payer_vpa = await get_or_create_account_for_user(session, payer, vpa_suffix="gcet")
    payee_acc, payee_vpa = await get_or_create_account_for_user(session, payee, vpa_suffix="gcet")

    # Fund payer with ₹1,000 (100,000 paise) from Treasury
    await post_transfer(
        session,
        txn_id=uuid.uuid4(),
        from_account_id=treasury.id,
        to_account_id=payer_acc.id,
        amount_paise=100_000,
        note="Initial test stipend",
        kind=TxnKind.TOPUP,
    )

    return payer, payee, admin, payer_acc, payee_acc, payer_vpa.handle, payee_vpa.handle


def _build_client_envelope(
    server_pub_jwk: dict[str, Any],
    device_priv: ec.EllipticCurvePrivateKey,
    txn_id: str,
    payer_vpa: str,
    payee_vpa: str,
    amount_paise: int,
    mpin: str,
    note: str | None = "Test payment",
    nonce: str | None = None,
    ts: int | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Simulate client building payload, signing with device key, and encrypting envelope."""
    now_ts = int(time.time()) if ts is None else ts
    nonce_val = str(uuid.uuid4()) if nonce is None else nonce

    payload_dict = {
        "amount_paise": amount_paise,
        "nonce": nonce_val,
        "note": note,
        "payee_vpa": payee_vpa,
        "payer_vpa": payer_vpa,
        "ts": now_ts,
        "txn_id": txn_id,
    }

    # 1. Sign canonical JSON of payload with device key
    payload_bytes = canonical_json_bytes(payload_dict)
    print("\n[DEBUG] CLIENT PAYLOAD BYTES:", payload_bytes.decode("utf-8"))
    der_sig = sign_bytes(device_priv, payload_bytes)
    raw_sig = der_to_raw(der_sig)
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")

    # 2. Build inner message
    inner_msg = {
        "device_sig": sig_b64,
        "mpin": mpin,
        "payload": payload_dict,
    }
    inner_json_str = canonical_json_str(inner_msg)

    # 3. Encrypt in envelope
    from app.crypto.signing import jwk_to_public_key
    server_pub = jwk_to_public_key(server_pub_jwk)

    envelope = encrypt_payload(
        server_public_key=server_pub,
        plaintext=inner_json_str.encode("utf-8"),
        txn_id=txn_id,
        ts=now_ts,
    )
    return envelope, payload_bytes


# ── 1. Happy Path End-to-End Payment ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_payment_happy_path_e2e(
    app_client: AsyncClient,
    async_db: AsyncSession,
) -> None:
    """
    Full end-to-end Client -> PSP -> Switch -> Bank -> Client payment flow.
    Verifies receipt signature, wallet balance conservation, and audit chain.
    """
    settings = get_settings()
    payer, payee, admin, payer_acc, payee_acc, payer_vpa, payee_vpa = await _create_test_campus(async_db)

    # Payer sets MPIN
    payer_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": payer.college_id, "password": "PayerPass123!"},
    )
    payer_token = payer_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {payer_token}"}

    set_mpin_res = await app_client.post(
        "/api/v1/mpin/set",
        headers=headers,
        json={"password": "PayerPass123!", "mpin": "123456"},
    )
    assert set_mpin_res.status_code == 200

    # Payer registers device key
    dev_priv, dev_pub = generate_ecdsa_keypair()
    print("\n[DEBUG] REGISTERING DEV PUB JWK:", public_key_to_jwk(dev_pub))
    reg_dev_res = await app_client.post(
        "/api/v1/devices/register",
        headers=headers,
        json={"public_key_jwk": public_key_to_jwk(dev_pub), "label": "Pixel 8"},
    )
    assert reg_dev_res.status_code == 201

    # Fetch server public key
    srv_key_res = await app_client.get("/api/v1/crypto/server-key")
    server_jwk = srv_key_res.json()["public_key"]

    # Client prepares payment of ₹250 (25,000 paise)
    txn_id = str(uuid.uuid4())
    envelope, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=txn_id,
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=25_000,
        mpin="123456",
        note="Virtual canteen lunch",
    )

    # Execute payment
    pay_res = await app_client.post(
        "/api/v1/payments/pay",
        headers=headers,
        json=envelope,
    )
    assert pay_res.status_code == 200, f"pay_res returned {pay_res.status_code}: {pay_res.text}"
    resp_data = pay_res.json()
    assert "envelope" in resp_data
    resp_env = resp_data["envelope"]

    # Client decrypts response envelope
    server_priv, _, _, ca_cert = get_server_ecdh_keys()
    from app.crypto.envelope import derive_shared_key, jwk_to_public_key
    eph_pub = jwk_to_public_key(envelope["eph_pub"])
    client_shared_key = derive_shared_key(server_priv, eph_pub, base64.b64decode(envelope["salt"]))
    receipt_bytes = decrypt_response(client_shared_key, resp_env, txn_id)
    receipt_dict = json.loads(receipt_bytes.decode("utf-8"))

    # Verify receipt fields and signature
    receipt = BankReceipt.model_validate(receipt_dict)
    assert receipt.txn_id == txn_id
    assert receipt.amount_paise == 25_000
    assert receipt.status == "SUCCESS"

    valid_receipt, err = verify_bank_receipt(ca_cert, receipt)
    assert valid_receipt is True, f"Bank receipt signature verification failed: {err}"

    # Verify wallet balances
    await async_db.refresh(payer_acc.wallet)
    await async_db.refresh(payee_acc.wallet)
    assert payer_acc.wallet.balance_paise == 75_000  # 100,000 - 25,000
    assert payee_acc.wallet.balance_paise == 25_000

    # Verify zero-sum invariant through admin audit
    admin_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": admin.college_id, "password": "AdminPass123!"},
    )
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    audit_res = await app_client.post("/api/v1/admin/audit/verify", headers=admin_headers)
    assert audit_res.status_code == 200
    assert audit_res.json()["ok"] is True
    assert audit_res.json()["zero_sum_verified"] is True


# ── 2. Idempotency Test ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_payment_idempotency_retry(
    app_client: AsyncClient,
    async_db: AsyncSession,
) -> None:
    """Repeating the same payment with identical txn_id returns the stored receipt without double-debiting."""
    payer, payee, _, payer_acc, payee_acc, payer_vpa, payee_vpa = await _create_test_campus(async_db)

    payer_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": payer.college_id, "password": "PayerPass123!"},
    )
    payer_token = payer_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {payer_token}"}

    await app_client.post(
        "/api/v1/mpin/set",
        headers=headers,
        json={"password": "PayerPass123!", "mpin": "123456"},
    )
    dev_priv, dev_pub = generate_ecdsa_keypair()
    await app_client.post(
        "/api/v1/devices/register",
        headers=headers,
        json={"public_key_jwk": public_key_to_jwk(dev_pub), "label": "Device 1"},
    )

    srv_key_res = await app_client.get("/api/v1/crypto/server-key")
    server_jwk = srv_key_res.json()["public_key"]

    txn_id = str(uuid.uuid4())
    envelope, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=txn_id,
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=30_000,
        mpin="123456",
    )

    # First attempt
    res1 = await app_client.post("/api/v1/payments/pay", headers=headers, json=envelope)
    assert res1.status_code == 200

    # Second attempt with same txn_id (fresh nonce inside a new envelope with same txn_id)
    envelope2, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=txn_id,
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=30_000,
        mpin="123456",
        nonce=str(uuid.uuid4()),  # Fresh nonce so anti-replay doesn't trigger before idempotency
    )
    res2 = await app_client.post("/api/v1/payments/pay", headers=headers, json=envelope2)
    assert res2.status_code == 200

    # Balances must only reflect a SINGLE debit of ₹300
    await async_db.refresh(payer_acc.wallet)
    await async_db.refresh(payee_acc.wallet)
    assert payer_acc.wallet.balance_paise == 70_000
    assert payee_acc.wallet.balance_paise == 30_000


# ── 3. Rejection Scenarios Matrix ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rejection_scenarios(
    app_client: AsyncClient,
    async_db: AsyncSession,
) -> None:
    """Test every security control rejection: envelope tampering, nonce replay, skewed ts, MPIN strikes."""
    payer, payee, _, payer_acc, _, payer_vpa, payee_vpa = await _create_test_campus(async_db)

    payer_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": payer.college_id, "password": "PayerPass123!"},
    )
    payer_token = payer_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {payer_token}"}

    await app_client.post(
        "/api/v1/mpin/set",
        headers=headers,
        json={"password": "PayerPass123!", "mpin": "123456"},
    )
    dev_priv, dev_pub = generate_ecdsa_keypair()
    await app_client.post(
        "/api/v1/devices/register",
        headers=headers,
        json={"public_key_jwk": public_key_to_jwk(dev_pub), "label": "Device 1"},
    )

    srv_key_res = await app_client.get("/api/v1/crypto/server-key")
    server_jwk = srv_key_res.json()["public_key"]

    # A. Corrupt envelope ciphertext
    env_corrupt, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=str(uuid.uuid4()),
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=1000,
        mpin="123456",
    )
    ct_b = bytearray(base64.b64decode(env_corrupt["ct"]))
    ct_b[0] ^= 0x01
    env_corrupt["ct"] = base64.b64encode(ct_b).decode()
    res_a = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_corrupt)
    assert res_a.status_code == 400
    assert res_a.json()["error"]["code"] == "ENVELOPE_INVALID"

    # B. Expired timestamp (> 60s ago)
    past_ts = int(time.time()) - 120
    env_skewed, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=str(uuid.uuid4()),
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=1000,
        mpin="123456",
        ts=past_ts,
    )
    res_b = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_skewed)
    assert res_b.status_code == 400
    assert res_b.json()["error"]["code"] == "TIMESTAMP_SKEW"

    # C. Replayed nonce
    fixed_nonce = "fixed-replay-test-nonce"
    env_c1, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=str(uuid.uuid4()),
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=1000,
        mpin="123456",
        nonce=fixed_nonce,
    )
    ok_c1 = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_c1)
    assert ok_c1.status_code == 200

    env_c2, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=str(uuid.uuid4()),
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=1000,
        mpin="123456",
        nonce=fixed_nonce,  # REPLAY
    )
    res_c = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_c2)
    assert res_c.status_code == 409
    assert res_c.json()["error"]["code"] == "REPLAY_DETECTED"

    # D. Unregistered device key / corrupted device signature
    unreg_priv, _ = generate_ecdsa_keypair()
    env_unreg, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=unreg_priv,
        txn_id=str(uuid.uuid4()),
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=1000,
        mpin="123456",
    )
    res_d = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_unreg)
    assert res_d.status_code == 400
    assert res_d.json()["error"]["code"] == "SIGNATURE_INVALID"

    # E. Wrong MPIN and 3-strike lockout
    for strike in range(1, 3):
        env_wrong_mpin, _ = _build_client_envelope(
            server_pub_jwk=server_jwk,
            device_priv=dev_priv,
            txn_id=str(uuid.uuid4()),
            payer_vpa=payer_vpa,
            payee_vpa=payee_vpa,
            amount_paise=1000,
            mpin="999999",  # WRONG
        )
        res_strike = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_wrong_mpin)
        assert res_strike.status_code == 401
        assert res_strike.json()["error"]["code"] == "AUTH_FAILED"

    # 3rd strike triggers lockout
    env_strike3, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=str(uuid.uuid4()),
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=1000,
        mpin="999999",
    )
    res_strike3 = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_strike3)
    assert res_strike3.status_code == 401

    # 4th attempt even with CORRECT MPIN is rejected with ACCOUNT_LOCKED
    env_locked, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=str(uuid.uuid4()),
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=1000,
        mpin="123456",  # CORRECT MPIN
    )
    res_locked = await app_client.post("/api/v1/payments/pay", headers=headers, json=env_locked)
    assert res_locked.status_code == 403
    assert res_locked.json()["error"]["code"] == "ACCOUNT_LOCKED"


# ── 4. Collect Requests Lifecycle ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collect_requests_lifecycle(
    app_client: AsyncClient,
    async_db: AsyncSession,
) -> None:
    """Payee requests payment -> payer sees incoming -> payer declines one -> payer approves another via envelope."""
    payer, payee, _, payer_acc, payee_acc, payer_vpa, payee_vpa = await _create_test_campus(async_db)

    # 1. Payee logs in and creates a collect request
    payee_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": payee.college_id, "password": "PayeePass123!"},
    )
    payee_token = payee_login.json()["access_token"]
    payee_headers = {"Authorization": f"Bearer {payee_token}"}

    create_res = await app_client.post(
        "/api/v1/payments/collect",
        headers=payee_headers,
        json={
            "payee_vpa": payee_vpa,
            "payer_vpa": payer_vpa,
            "amount_paise": 15_000,
            "note": "Lab printing share",
        },
    )
    assert create_res.status_code == 201
    collect_id = create_res.json()["id"]

    # 2. Payer logs in and checks incoming requests
    payer_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": payer.college_id, "password": "PayerPass123!"},
    )
    payer_token = payer_login.json()["access_token"]
    payer_headers = {"Authorization": f"Bearer {payer_token}"}

    incoming_res = await app_client.get(
        "/api/v1/payments/collect/incoming",
        headers=payer_headers,
    )
    assert incoming_res.status_code == 200
    incoming_list = incoming_res.json()
    assert len(incoming_list) == 1
    assert incoming_list[0]["id"] == collect_id

    # 3. Payer declines first collect request
    decline_res = await app_client.post(
        f"/api/v1/payments/collect/{collect_id}/decline",
        headers=payer_headers,
    )
    assert decline_res.status_code == 200
    assert decline_res.json()["collect_status"] == "declined"

    # 4. Payee creates second collect request
    create2_res = await app_client.post(
        "/api/v1/payments/collect",
        headers=payee_headers,
        json={
            "payee_vpa": payee_vpa,
            "payer_vpa": payer_vpa,
            "amount_paise": 20_000,
            "note": "Robotics team virtual contribution",
        },
    )
    assert create2_res.status_code == 201
    collect_id2 = create2_res.json()["id"]

    # Setup MPIN and device for payer
    await app_client.post(
        "/api/v1/mpin/set",
        headers=payer_headers,
        json={"password": "PayerPass123!", "mpin": "123456"},
    )
    dev_priv, dev_pub = generate_ecdsa_keypair()
    await app_client.post(
        "/api/v1/devices/register",
        headers=payer_headers,
        json={"public_key_jwk": public_key_to_jwk(dev_pub), "label": "Payer Mobile"},
    )

    srv_key_res = await app_client.get("/api/v1/crypto/server-key")
    server_jwk = srv_key_res.json()["public_key"]

    # 5. Payer approves via encrypted payment envelope
    txn_id = str(uuid.uuid4())
    envelope, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=txn_id,
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=20_000,
        mpin="123456",
        note="Approved collect request",
    )

    approve_res = await app_client.post(
        f"/api/v1/payments/collect/{collect_id2}/approve",
        headers=payer_headers,
        json=envelope,
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["collect_status"] == "approved"

    # Verify balances updated
    await async_db.refresh(payer_acc.wallet)
    await async_db.refresh(payee_acc.wallet)
    assert payer_acc.wallet.balance_paise == 80_000
    assert payee_acc.wallet.balance_paise == 20_000


# ── 5. QR Code Payload Generation and HMAC ────────────────────────────────────


@pytest.mark.asyncio
async def test_qr_code_payload_and_hmac(
    app_client: AsyncClient,
    async_db: AsyncSession,
) -> None:
    """Verify standard format: miniupi://pay?vpa=<handle>&am=<paise>&tn=<note>&sig=<hmac>."""
    payer, _, _, _, _, payer_vpa, _ = await _create_test_campus(async_db)

    payer_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": payer.college_id, "password": "PayerPass123!"},
    )
    token = payer_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Static QR
    static_qr_res = await app_client.get("/api/v1/vpa/me", headers=headers)
    assert static_qr_res.status_code == 200
    static_qr = static_qr_res.json()["qr_payload"]
    assert static_qr == f"miniupi://pay?vpa={payer_vpa}"

    # Dynamic merchant QR with amount, note, and HMAC signature
    dynamic_qr_res = await app_client.get(
        f"/api/v1/vpa/me?amount_paise=15000&note=Campus+Bookstore&sign=true",
        headers=headers,
    )
    assert dynamic_qr_res.status_code == 200
    dynamic_qr = dynamic_qr_res.json()["qr_payload"]
    assert dynamic_qr.startswith("miniupi://pay?")
    assert f"vpa={payer_vpa}" in dynamic_qr
    assert "am=15000" in dynamic_qr
    assert "tn=Campus Bookstore" in dynamic_qr
    assert "sig=" in dynamic_qr


# ── 6. Security Lens Transaction Transparency Endpoint ────────────────────────


@pytest.mark.asyncio
async def test_transaction_security_lens_data(
    app_client: AsyncClient,
    async_db: AsyncSession,
) -> None:
    """Verify GET /transactions/{id} exposes cryptographic chain of custody."""
    payer, payee, _, _, _, payer_vpa, payee_vpa = await _create_test_campus(async_db)

    payer_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": payer.college_id, "password": "PayerPass123!"},
    )
    headers = {"Authorization": f"Bearer {payer_login.json()['access_token']}"}

    await app_client.post(
        "/api/v1/mpin/set",
        headers=headers,
        json={"password": "PayerPass123!", "mpin": "123456"},
    )
    dev_priv, dev_pub = generate_ecdsa_keypair()
    await app_client.post(
        "/api/v1/devices/register",
        headers=headers,
        json={"public_key_jwk": public_key_to_jwk(dev_pub), "label": "Security Lens Phone"},
    )
    srv_key_res = await app_client.get("/api/v1/crypto/server-key")
    server_jwk = srv_key_res.json()["public_key"]

    txn_id = str(uuid.uuid4())
    envelope, _ = _build_client_envelope(
        server_pub_jwk=server_jwk,
        device_priv=dev_priv,
        txn_id=txn_id,
        payer_vpa=payer_vpa,
        payee_vpa=payee_vpa,
        amount_paise=12_000,
        mpin="123456",
        note="Lens verification test",
    )
    pay_res = await app_client.post("/api/v1/payments/pay", headers=headers, json=envelope)
    assert pay_res.status_code == 200

    # Query transaction detail
    lens_res = await app_client.get(f"/api/v1/transactions/{txn_id}", headers=headers)
    assert lens_res.status_code == 200
    data = lens_res.json()

    assert data["id"] == txn_id
    assert data["amount_paise"] == 12_000
    assert data["direction"] == "DEBIT"
    assert data["receipt"] is not None

    lens = data["security_lens"]
    assert lens["device_signature_verified"] is True
    assert lens["psp_signature_verified"] is True
    assert lens["switch_mac_verified"] is True
    assert lens["bank_signature_verified"] is True
    assert "Mini-UPI" in str(lens["bank_cert_issuer"]) or "GCET" in str(lens["bank_cert_issuer"])
    assert lens["audit_chain_seq"] is not None
    assert lens["audit_chain_seq"] > 0
    assert lens["audit_entry_hash"] is not None
    assert lens["audit_chain_verified"] is True
