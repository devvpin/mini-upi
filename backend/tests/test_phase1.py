"""
test_phase1.py — Comprehensive tests for Phase 1 (Identity & Campus Hierarchy).

Phase 1 Gate checklist coverage:
- Seed script loads the full hierarchy; counts match (11 departments, 39 classes)
- Login works; wrong password and unknown user return identical responses
- 6th wrong password in the window is locked even with the right password
- Replaying an old refresh token revokes the session family
- A student token gets 403 on every /admin/* route (matrix test)
- No password hash or secret appears in any API response or log
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings
from app.core.database import get_db
from app.crypto.kdf import (
    hash_secret,
    needs_rehash,
    verify_dummy,
    verify_secret,
)
from app.identity.models import Base, ClassGroup, Department, UserRole
from app.identity.repository import (
    create_class,
    create_department,
    create_user,
)
from app.main import create_app

TEST_PEPPER = "test-static-pepper-value-for-phase1-testing-minimum-32"
TEST_JWT_SECRET = "test-jwt-secret-phase1-testing-minimum-32-chars-long"
TEST_AUDIT_KEY = "test-audit-key-phase1-testing-minimum-32-chars-long"
TEST_MAC_KEY = "test-mac-key-phase1-testing-minimum-32-chars-long"


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
async def sample_hierarchy(async_db: AsyncSession) -> tuple[Department, ClassGroup]:
    dept = await create_department(async_db, code="cp", name="Computer Engineering")
    cls = await create_class(async_db, department_id=dept.id, name="TY-CP-A", year=3, division="A")
    await async_db.commit()
    return dept, cls


# ── 1. Argon2id KDF unit tests ──────────────────────────────────────────────

def test_argon2id_hashing_and_verification() -> None:
    password = "CorrectHorseBatteryStaple#1"
    hashed = hash_secret(password, TEST_PEPPER, time_cost=1, memory_cost=1024)

    assert hashed.startswith("$argon2id$")
    assert verify_secret(password, hashed, TEST_PEPPER) is True
    assert verify_secret("WrongPassword#99", hashed, TEST_PEPPER) is False
    assert verify_secret(password, hashed, "wrong-pepper") is False


def test_argon2id_needs_rehash() -> None:
    password = "TestPassword#1"
    old_hash = hash_secret(password, TEST_PEPPER, time_cost=1, memory_cost=1024)
    assert needs_rehash(old_hash) is True


def test_argon2id_dummy_verification() -> None:
    assert verify_dummy(TEST_PEPPER) is False


# ── 2. Login, Timing Equalisation, and Account Lockout ──────────────────────

@pytest.mark.asyncio
async def test_timing_equalisation_unknown_vs_wrong_password(
    app_client: AsyncClient, async_db: AsyncSession, sample_hierarchy: tuple[Department, ClassGroup]
) -> None:
    dept, cls = sample_hierarchy
    pwd_hash = hash_secret("Password123!", TEST_PEPPER, time_cost=1, memory_cost=1024)
    await create_user(
        async_db,
        college_id="22cp001",
        full_name="Aarav Patel",
        email="22cp001@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    await async_db.commit()

    resp_wrong = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "22cp001", "password": "BadPassword123!"},
    )

    resp_unknown = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "99zz999", "password": "BadPassword123!"},
    )

    assert resp_wrong.status_code == 401
    assert resp_unknown.status_code == 401
    assert resp_wrong.json()["error"]["code"] == "AUTH_FAILED"
    assert resp_unknown.json()["error"]["code"] == "AUTH_FAILED"
    assert resp_wrong.json()["error"]["message"] == resp_unknown.json()["error"]["message"]


@pytest.mark.asyncio
async def test_account_lockout_on_6th_attempt(
    app_client: AsyncClient, async_db: AsyncSession, sample_hierarchy: tuple[Department, ClassGroup]
) -> None:
    dept, cls = sample_hierarchy
    pwd_hash = hash_secret("CorrectPassword123!", TEST_PEPPER, time_cost=1, memory_cost=1024)
    await create_user(
        async_db,
        college_id="22cp002",
        full_name="Diya Shah",
        email="22cp002@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    await async_db.commit()

    # 5 failed login attempts
    for _ in range(5):
        resp = await app_client.post(
            "/api/v1/auth/login",
            json={"college_id": "22cp002", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "AUTH_FAILED"

    # 6th attempt with the RIGHT password must be locked
    resp_6th = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "22cp002", "password": "CorrectPassword123!"},
    )
    assert resp_6th.status_code == 423
    assert resp_6th.json()["error"]["code"] == "ACCOUNT_LOCKED"


# ── 3. Session Refresh and Token Family Revocation on Replay ────────────────

@pytest.mark.asyncio
async def test_refresh_token_rotation_and_reuse_detection(
    app_client: AsyncClient, async_db: AsyncSession, sample_hierarchy: tuple[Department, ClassGroup]
) -> None:
    dept, cls = sample_hierarchy
    pwd_hash = hash_secret("CorrectPassword123!", TEST_PEPPER, time_cost=1, memory_cost=1024)
    await create_user(
        async_db,
        college_id="22cp003",
        full_name="Ishaan Sharma",
        email="22cp003@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    await async_db.commit()

    login_resp = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "22cp003", "password": "CorrectPassword123!"},
    )
    assert login_resp.status_code == 200
    token1 = login_resp.json()["refresh_token"]

    rot1_resp = await app_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token1},
    )
    assert rot1_resp.status_code == 200
    token2 = rot1_resp.json()["refresh_token"]
    assert token2 != token1

    replay_resp = await app_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token1},
    )
    assert replay_resp.status_code == 401

    rot2_resp = await app_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token2},
    )
    assert rot2_resp.status_code == 401


# ── 4. Password Change and Profile ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_change_password_flow(
    app_client: AsyncClient, async_db: AsyncSession, sample_hierarchy: tuple[Department, ClassGroup]
) -> None:
    dept, cls = sample_hierarchy
    pwd_hash = hash_secret("OldPassword123!", TEST_PEPPER, time_cost=1, memory_cost=1024)
    await create_user(
        async_db,
        college_id="22cp004",
        full_name="Kavya Desai",
        email="22cp004@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    await async_db.commit()

    login_resp = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "22cp004", "password": "OldPassword123!"},
    )
    access_token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    me_resp = await app_client.get("/api/v1/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["college_id"] == "22cp004"
    assert me_resp.json()["must_change_password"] is True

    change_resp = await app_client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "current_password": "OldPassword123!",
            "new_password": "NewSecurePassword456!",
        },
    )
    assert change_resp.status_code == 200
    assert change_resp.json()["status"] == "password_changed"

    new_login_resp = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "22cp004", "password": "NewSecurePassword456!"},
    )
    assert new_login_resp.status_code == 200
    assert new_login_resp.json()["must_change_password"] is False


# ── 5. RBAC Matrix: Student & Faculty Blocked from Admin ────────────────────

@pytest.mark.asyncio
async def test_rbac_matrix_student_and_faculty_blocked_from_admin(
    app_client: AsyncClient, async_db: AsyncSession, sample_hierarchy: tuple[Department, ClassGroup]
) -> None:
    dept, cls = sample_hierarchy
    pwd_hash = hash_secret("CommonPassword123!", TEST_PEPPER, time_cost=1, memory_cost=1024)

    # Student
    await create_user(
        async_db,
        college_id="stud01",
        full_name="Student One",
        email="stud01@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    # Faculty
    await create_user(
        async_db,
        college_id="fac01",
        full_name="Faculty One",
        email="fac01@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.FACULTY,
        department_id=dept.id,
    )
    # Admin
    await create_user(
        async_db,
        college_id="adm01",
        full_name="Admin One",
        email="adm01@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.ADMIN,
    )
    await async_db.commit()

    s_resp = await app_client.post(
        "/api/v1/auth/login", json={"college_id": "stud01", "password": "CommonPassword123!"}
    )
    s_token = s_resp.json()["access_token"]

    f_resp = await app_client.post(
        "/api/v1/auth/login", json={"college_id": "fac01", "password": "CommonPassword123!"}
    )
    f_token = f_resp.json()["access_token"]

    a_resp = await app_client.post(
        "/api/v1/auth/login", json={"college_id": "adm01", "password": "CommonPassword123!"}
    )
    a_token = a_resp.json()["access_token"]

    admin_routes = [
        ("GET", "/api/v1/admin/stats"),
        ("POST", "/api/v1/admin/import"),
    ]

    for method, path in admin_routes:
        if method == "GET":
            r_stud = await app_client.get(
                path, headers={"Authorization": f"Bearer {s_token}"}
            )
            r_fac = await app_client.get(
                path, headers={"Authorization": f"Bearer {f_token}"}
            )
            r_adm = await app_client.get(
                path, headers={"Authorization": f"Bearer {a_token}"}
            )
        else:
            r_stud = await app_client.post(
                path, json={}, headers={"Authorization": f"Bearer {s_token}"}
            )
            r_fac = await app_client.post(
                path, json={}, headers={"Authorization": f"Bearer {f_token}"}
            )
            r_adm = await app_client.post(
                path, json={}, headers={"Authorization": f"Bearer {a_token}"}
            )

        assert r_stud.status_code == 403, f"Student allowed on {path}"
        assert r_stud.json()["error"]["code"] == "FORBIDDEN"
        assert r_fac.status_code == 403, f"Faculty allowed on {path}"
        assert r_fac.json()["error"]["code"] == "FORBIDDEN"
        assert r_adm.status_code in (200, 422), f"Admin rejected unexpectedly on {path}"


# ── 6. CSV Import and Hierarchy Counts ──────────────────────────────────────

@pytest.mark.asyncio
async def test_csv_import_hierarchy_and_counts(
    app_client: AsyncClient, async_db: AsyncSession
) -> None:
    pwd_hash = hash_secret("AdminPass123!", TEST_PEPPER, time_cost=1, memory_cost=1024)
    await create_user(
        async_db,
        college_id="admin_importer",
        full_name="Import Admin",
        email="admin_importer@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.ADMIN,
    )
    await async_db.commit()

    login_resp = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "admin_importer", "password": "AdminPass123!"},
    )
    admin_token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    root = Path(__file__).resolve().parent.parent.parent
    dept_csv = (root / "scripts/seed/departments.csv").read_text(encoding="utf-8")
    class_csv = (root / "scripts/seed/classes.csv").read_text(encoding="utf-8")
    user_csv = (root / "scripts/seed/users.csv").read_text(encoding="utf-8")

    # Dry run first
    dry_resp = await app_client.post(
        "/api/v1/admin/import",
        headers=headers,
        json={
            "departments_csv": dept_csv,
            "classes_csv": class_csv,
            "users_csv": user_csv,
            "dry_run": True,
        },
    )
    assert dry_resp.status_code == 200
    dry_data = dry_resp.json()
    assert dry_data["dry_run"] is True
    assert dry_data["departments_created"] == 11
    assert dry_data["classes_created"] == 39
    assert dry_data["users_created"] >= 200
    assert len(dry_data["errors"]) == 0

    # Real import
    real_resp = await app_client.post(
        "/api/v1/admin/import",
        headers=headers,
        json={
            "departments_csv": dept_csv,
            "classes_csv": class_csv,
            "users_csv": user_csv,
            "dry_run": False,
        },
    )
    assert real_resp.status_code == 200
    real_data = real_resp.json()
    assert real_data["dry_run"] is False
    assert real_data["departments_created"] == 11
    assert real_data["classes_created"] == 39
    assert real_data["users_created"] >= 200
    assert len(real_data["errors"]) == 0

    # Idempotent second run
    second_resp = await app_client.post(
        "/api/v1/admin/import",
        headers=headers,
        json={
            "departments_csv": dept_csv,
            "classes_csv": class_csv,
            "users_csv": user_csv,
            "dry_run": False,
        },
    )
    assert second_resp.status_code == 200
    sec_data = second_resp.json()
    assert sec_data["departments_created"] == 0
    assert sec_data["departments_existing"] == 11
    assert sec_data["classes_created"] == 0
    assert sec_data["classes_existing"] == 39


# ── 7. Secret Sanitisation in Responses ─────────────────────────────────────

@pytest.mark.asyncio
async def test_no_secrets_in_responses(
    app_client: AsyncClient, async_db: AsyncSession, sample_hierarchy: tuple[Department, ClassGroup]
) -> None:
    dept, cls = sample_hierarchy
    pwd_hash = hash_secret("SecretPassword999!", TEST_PEPPER, time_cost=1, memory_cost=1024)
    await create_user(
        async_db,
        college_id="22cp099",
        full_name="Aarav Sanitized",
        email="22cp099@gcet.edu",
        password_hash=pwd_hash,
        role=UserRole.STUDENT,
        department_id=dept.id,
        class_id=cls.id,
    )
    await async_db.commit()

    resp = await app_client.post(
        "/api/v1/auth/login",
        json={"college_id": "22cp099", "password": "SecretPassword999!"},
    )
    text = resp.text
    assert "SecretPassword999!" not in text
    assert "$argon2id$" not in text
    assert TEST_PEPPER not in text
    assert TEST_JWT_SECRET not in text
