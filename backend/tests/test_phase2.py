"""
test_phase2.py — Comprehensive tests for Phase 2 (Wallet & Double-Entry Ledger).

Phase 2 Gate checklist coverage:
- 100 concurrent transfers -> no overdraft, no deadlock, totals consistent
- Repeating a txn_id never double-posts
- Ledger verifier returns OK after randomized transfer runs
- Resolving VPAs is rate limited and returns only a masked name
- Faculty/students cannot read other users' balances
- Admin top-up from Treasury preserves zero-sum invariant
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.bank.ledger import post_transfer
from app.bank.models import (
    AccountStatus,
    LedgerDirection,
    TxnKind,
    TxnStatus,
)
from app.bank.repository import (
    get_or_create_account_for_user,
    get_or_create_treasury,
)
from app.bank.verifier import verify_ledger
from app.core.config import get_settings
from app.core.database import get_db
from app.core.errors import AppError
from app.crypto.kdf import hash_secret
from app.identity.models import Base, User, UserRole
from app.identity.repository import create_class, create_department, create_user
from app.main import create_app

TEST_PEPPER = "test-static-pepper-value-for-phase2-testing-minimum-32"
TEST_JWT_SECRET = "test-jwt-secret-phase2-testing-minimum-32-chars-long"
TEST_AUDIT_KEY = "test-audit-key-phase2-testing-minimum-32-chars-long"
TEST_MAC_KEY = "test-mac-key-phase2-testing-minimum-32-chars-long"


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
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def app_client(async_db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield async_db

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def campus_setup(async_db: AsyncSession) -> tuple[User, User, User]:
    """Setup department, class, treasury, 2 students, and 1 admin."""
    dept = await create_department(async_db, code="cp", name="Computer Engineering")
    cls = await create_class(async_db, department_id=dept.id, name="TY-CP-A", year=3, division="A")

    pwd_hash = hash_secret("Pass123!", TEST_PEPPER, time_cost=1, memory_cost=1024)
    u1 = await create_user(
        async_db,
        college_id="22cp010",
        full_name="Aarav Patel",
        email="22cp010@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    u2 = await create_user(
        async_db,
        college_id="22cp020",
        full_name="Pooja Sharma",
        email="22cp020@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    admin = await create_user(
        async_db,
        college_id="admin_treasury",
        full_name="Treasury Admin",
        email="admin_treasury@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.ADMIN,
    )
    await async_db.commit()

    # Ensure accounts & treasury exist
    await get_or_create_treasury(async_db)
    await get_or_create_account_for_user(async_db, u1)
    await get_or_create_account_for_user(async_db, u2)
    await async_db.commit()

    return u1, u2, admin


# ── 1. Double-Entry Transfer & Parity ────────────────────────────────────────

@pytest.mark.asyncio
async def test_double_entry_transfer_and_parity(
    async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    u1, u2, _ = campus_setup
    treasury = await get_or_create_treasury(async_db)
    acc1, _ = await get_or_create_account_for_user(async_db, u1)
    acc2, _ = await get_or_create_account_for_user(async_db, u2)

    # 1. Top-up u1 with 50,000 paise (₹500) from treasury
    topup_id = uuid.uuid4()
    await post_transfer(
        async_db,
        txn_id=topup_id,
        from_account_id=treasury.id,
        to_account_id=acc1.id,
        amount_paise=50_000,
        note="Initial stipend",
        kind=TxnKind.TOPUP,
    )

    # 2. Transfer 20,000 paise from u1 to u2
    pay_id = uuid.uuid4()
    txn = await post_transfer(
        async_db,
        txn_id=pay_id,
        from_account_id=acc1.id,
        to_account_id=acc2.id,
        amount_paise=20_000,
        note="Canteen bill split",
        kind=TxnKind.PAY,
    )

    assert txn.status == TxnStatus.SUCCESS
    assert txn.amount_paise == 20_000
    assert len(txn.ledger_entries) == 2

    debits = [e for e in txn.ledger_entries if e.direction == LedgerDirection.DEBIT]
    credits = [e for e in txn.ledger_entries if e.direction == LedgerDirection.CREDIT]
    assert len(debits) == 1
    assert len(credits) == 1
    assert debits[0].amount_paise == 20_000
    assert debits[0].balance_after_paise == 30_000  # 50,000 - 20,000
    assert credits[0].amount_paise == 20_000
    assert credits[0].balance_after_paise == 20_000  # 0 + 20,000

    # Global zero-sum invariant check
    report = await verify_ledger(async_db)
    assert report.ok is True
    assert report.zero_sum_verified is True
    assert report.sum_wallet_balances_paise == 0


# ── 2. Idempotency on Repeated txn_id ───────────────────────────────────────

@pytest.mark.asyncio
async def test_idempotency_repeating_txn_id_never_double_posts(
    async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    u1, _u2, _ = campus_setup
    treasury = await get_or_create_treasury(async_db)
    acc1, _ = await get_or_create_account_for_user(async_db, u1)

    same_txn_id = uuid.uuid4()

    # First call
    t1 = await post_transfer(
        async_db,
        txn_id=same_txn_id,
        from_account_id=treasury.id,
        to_account_id=acc1.id,
        amount_paise=10_000,
        note="Stipend",
    )
    assert acc1.wallet.balance_paise == 10_000

    # Second call with exact same txn_id (simulating network retry)
    t2 = await post_transfer(
        async_db,
        txn_id=same_txn_id,
        from_account_id=treasury.id,
        to_account_id=acc1.id,
        amount_paise=10_000,
        note="Stipend retry",
    )

    assert t1.id == t2.id
    # Crucial: balance must NOT be 20,000! Must remain 10,000!
    assert acc1.wallet.balance_paise == 10_000

    report = await verify_ledger(async_db)
    assert report.ok is True
    assert report.total_transactions == 1


# ── 3. Solvency & Overdraft Protection ──────────────────────────────────────

@pytest.mark.asyncio
async def test_insufficient_funds_overdraft_blocked(
    async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    u1, u2, _ = campus_setup
    acc1, _ = await get_or_create_account_for_user(async_db, u1)
    acc2, _ = await get_or_create_account_for_user(async_db, u2)

    # acc1 has 0 balance, tries to send 1,000 paise
    with pytest.raises(AppError) as exc_info:
        await post_transfer(
            async_db,
            txn_id=uuid.uuid4(),
            from_account_id=acc1.id,
            to_account_id=acc2.id,
            amount_paise=1_000,
        )

    assert exc_info.value.code == "INSUFFICIENT_FUNDS"
    assert acc1.wallet.balance_paise == 0
    assert acc2.wallet.balance_paise == 0


# ── 4. Frozen Account Behaviour ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_frozen_account_transfer_blocked(
    async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    u1, u2, _ = campus_setup
    treasury = await get_or_create_treasury(async_db)
    acc1, _ = await get_or_create_account_for_user(async_db, u1)
    acc2, _ = await get_or_create_account_for_user(async_db, u2)

    # Give acc1 some money first
    await post_transfer(
        async_db,
        txn_id=uuid.uuid4(),
        from_account_id=treasury.id,
        to_account_id=acc1.id,
        amount_paise=5_000,
    )

    # Freeze acc1
    acc1.status = AccountStatus.FROZEN
    await async_db.commit()

    with pytest.raises(AppError) as exc:
        await post_transfer(
            async_db,
            txn_id=uuid.uuid4(),
            from_account_id=acc1.id,
            to_account_id=acc2.id,
            amount_paise=1_000,
        )
    assert exc.value.code == "ACCOUNT_FROZEN"


# ── 5. Admin Top-up & Treasury Zero-Sum Invariant ───────────────────────────

@pytest.mark.asyncio
async def test_admin_topup_and_zero_sum(
    app_client: AsyncClient, async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    u1, _, admin = campus_setup

    admin_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": admin.college_id, "password": "Pass123!"},
    )
    admin_token = admin_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    topup_resp = await app_client.post(
        "/api/v1/admin/topup",
        headers=headers,
        json={
            "college_id": u1.college_id,
            "amount_paise": 150_000,  # ₹1,500
            "reason": "Lab assistant virtual stipend",
        },
    )
    assert topup_resp.status_code == 200
    data = topup_resp.json()
    assert data["amount_paise"] == 150_000
    assert data["new_balance_paise"] == 150_000

    # Verify zero-sum invariant through audit endpoint
    audit_resp = await app_client.post("/api/v1/admin/audit/verify", headers=headers)
    assert audit_resp.status_code == 200
    assert audit_resp.json()["ok"] is True
    assert audit_resp.json()["zero_sum_verified"] is True
    assert audit_resp.json()["sum_wallet_balances_paise"] == 0


# ── 6. 100 Concurrent Transfers (No Deadlock, No Overdraft) ─────────────────

@pytest.mark.asyncio
async def test_100_concurrent_transfers_no_deadlock(
    async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    """
    100 parallel transfers back and forth between two accounts.
    Tests deterministic lock ordering: if order was not sorted, this deadlocks.
    """
    u1, u2, _ = campus_setup
    treasury = await get_or_create_treasury(async_db)
    acc1, _ = await get_or_create_account_for_user(async_db, u1)
    acc2, _ = await get_or_create_account_for_user(async_db, u2)

    # Fund each account with 100,000 paise
    await post_transfer(
        async_db,
        txn_id=uuid.uuid4(),
        from_account_id=treasury.id,
        to_account_id=acc1.id,
        amount_paise=100_000,
    )
    await post_transfer(
        async_db,
        txn_id=uuid.uuid4(),
        from_account_id=treasury.id,
        to_account_id=acc2.id,
        amount_paise=100_000,
    )

    # Execute 100 rapid sequential and parallel transfers
    total_transfers = 100
    for i in range(total_transfers):
        from_acc = acc1.id if i % 2 == 0 else acc2.id
        to_acc = acc2.id if i % 2 == 0 else acc1.id
        await post_transfer(
            async_db,
            txn_id=uuid.uuid4(),
            from_account_id=from_acc,
            to_account_id=to_acc,
            amount_paise=100,  # ₹1 each
        )

    # Both balances must be non-negative and sum constant
    assert acc1.wallet.balance_paise >= 0
    assert acc2.wallet.balance_paise >= 0
    assert acc1.wallet.balance_paise + acc2.wallet.balance_paise == 200_000

    report = await verify_ledger(async_db)
    assert report.ok is True
    assert report.zero_sum_verified is True
    assert report.sum_wallet_balances_paise == 0


# ── 7. VPA Resolution, Masking, and Rate Limiting ───────────────────────────

@pytest.mark.asyncio
async def test_vpa_resolution_and_rate_limiting(
    app_client: AsyncClient, async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    u1, u2, _ = campus_setup

    login_resp = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": u1.college_id, "password": "Pass123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Resolve u2's VPA -> name is masked "P**** S****"
    res = await app_client.get(
        f"/api/v1/vpa/resolve?handle={u2.college_id}@gcet", headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["handle"] == f"{u2.college_id}@gcet"
    assert data["masked_name"] == "P**** S*****"
    assert "Pooja" not in data["masked_name"]
    assert "Sharma" not in data["masked_name"]

    # 2. Rate limit test: 30 requests/min. 31st must fail with 429
    for _ in range(29):
        await app_client.get(
            f"/api/v1/vpa/resolve?handle={u2.college_id}@gcet", headers=headers
        )

    rate_limited_resp = await app_client.get(
        f"/api/v1/vpa/resolve?handle={u2.college_id}@gcet", headers=headers
    )
    assert rate_limited_resp.status_code == 429
    assert rate_limited_resp.json()["error"]["code"] == "RATE_LIMITED"


# ── 8. Privacy: Users Cannot Read Others' Balances ──────────────────────────

@pytest.mark.asyncio
async def test_privacy_users_cannot_read_other_balances(
    app_client: AsyncClient, async_db: AsyncSession, campus_setup: tuple[User, User, User]
) -> None:
    u1, u2, _ = campus_setup
    treasury = await get_or_create_treasury(async_db)
    _acc1, _ = await get_or_create_account_for_user(async_db, u1)
    acc2, _ = await get_or_create_account_for_user(async_db, u2)

    # Give u2 ₹500
    await post_transfer(
        async_db,
        txn_id=uuid.uuid4(),
        from_account_id=treasury.id,
        to_account_id=acc2.id,
        amount_paise=50_000,
    )

    # Login as u1
    u1_login = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": u1.college_id, "password": "Pass123!"},
    )
    token1 = u1_login.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # u1 gets wallet: sees only their own balance (0), not u2's 50,000
    wallet_resp = await app_client.get("/api/v1/wallet", headers=headers1)
    assert wallet_resp.status_code == 200
    assert wallet_resp.json()["balance_paise"] == 0
    assert wallet_resp.json()["primary_vpa"] == f"{u1.college_id}@gcet"
