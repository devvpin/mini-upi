"""
identity.repository — Database operations for identity and campus hierarchy.

Crypto concept: Isolation of DB queries within repository boundary; ensures audit
and security checks cannot be bypassed.
Threat mitigated: SQL injection (parameterised queries), unauthorized DB modifications.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.identity.models import (
    ClassGroup,
    Department,
    RefreshToken,
    User,
    UserRole,
    UserStatus,
)

# ── Department Repository ───────────────────────────────────────────────────

async def get_department_by_code(session: AsyncSession, code: str) -> Department | None:
    stmt = select(Department).where(Department.code == code)
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def get_department_by_id(session: AsyncSession, dept_id: uuid.UUID) -> Department | None:
    stmt = select(Department).where(Department.id == dept_id)
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def create_department(session: AsyncSession, code: str, name: str) -> Department:
    dept = Department(code=code, name=name)
    session.add(dept)
    await session.flush()
    return dept


async def list_departments(session: AsyncSession) -> list[Department]:
    stmt = select(Department).order_by(Department.code)
    res = await session.execute(stmt)
    return list(res.scalars().all())


# ── Class Repository ────────────────────────────────────────────────────────

async def get_class_by_dept_year_name(
    session: AsyncSession, department_id: uuid.UUID, year: int, name: str
) -> ClassGroup | None:
    stmt = select(ClassGroup).where(
        ClassGroup.department_id == department_id,
        ClassGroup.year == year,
        ClassGroup.name == name,
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def create_class(
    session: AsyncSession,
    department_id: uuid.UUID,
    name: str,
    year: int,
    division: str | None = None,
) -> ClassGroup:
    cg = ClassGroup(
        department_id=department_id,
        name=name,
        year=year,
        division=division,
    )
    session.add(cg)
    await session.flush()
    return cg


async def list_classes(session: AsyncSession) -> list[ClassGroup]:
    stmt = select(ClassGroup).order_by(ClassGroup.year, ClassGroup.name)
    res = await session.execute(stmt)
    return list(res.scalars().all())


# ── User Repository ─────────────────────────────────────────────────────────

async def get_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    stmt = (
        select(User)
        .options(selectinload(User.department), selectinload(User.class_group))
        .where(User.id == user_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def get_user_by_college_id(session: AsyncSession, college_id: str) -> User | None:
    stmt = (
        select(User)
        .options(selectinload(User.department), selectinload(User.class_group))
        .where(User.college_id == college_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    stmt = select(User).where(User.email == email)
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def create_user(
    session: AsyncSession,
    college_id: str,
    full_name: str,
    email: str,
    password_hash: str,
    role: UserRole,
    department_id: uuid.UUID | None = None,
    class_id: uuid.UUID | None = None,
    must_change_password: bool = True,
    status: UserStatus = UserStatus.ACTIVE,
) -> User:
    user = User(
        college_id=college_id,
        full_name=full_name,
        email=email,
        password_hash=password_hash,
        role=role,
        department_id=department_id,
        class_id=class_id,
        must_change_password=must_change_password,
        status=status,
    )
    session.add(user)
    await session.flush()
    return user


async def record_login_failure(
    session: AsyncSession, user: User, max_attempts: int = 5, lock_minutes: int = 15
) -> None:
    """Record a failed login attempt; lock account after max_attempts."""
    user.failed_logins += 1
    if user.failed_logins >= max_attempts:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=lock_minutes)
    await session.flush()


async def reset_login_failures(session: AsyncSession, user: User) -> None:
    """Reset failed login count and unlock time upon successful login."""
    user.failed_logins = 0
    user.locked_until = None
    await session.flush()


async def update_user_password(
    session: AsyncSession, user: User, new_password_hash: str
) -> None:
    """Update user password and clear must_change_password flag."""
    user.password_hash = new_password_hash
    user.must_change_password = False
    await session.flush()


# ── Refresh Token Repository ────────────────────────────────────────────────

async def create_refresh_token(
    session: AsyncSession,
    user_id: uuid.UUID,
    token_hash: str,
    family_id: uuid.UUID,
    expires_at: datetime,
    device_id: uuid.UUID | None = None,
) -> RefreshToken:
    token = RefreshToken(
        family_id=family_id,
        user_id=user_id,
        device_id=device_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    session.add(token)
    await session.flush()
    return token


async def get_refresh_token_by_hash(
    session: AsyncSession, token_hash: str
) -> RefreshToken | None:
    stmt = (
        select(RefreshToken)
        .options(selectinload(RefreshToken.user))
        .where(RefreshToken.token_hash == token_hash)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def revoke_token_family(session: AsyncSession, family_id: uuid.UUID) -> None:
    """Revoke all tokens belonging to a family upon replay detection."""
    now = datetime.now(UTC)
    stmt = (
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    await session.execute(stmt)
    await session.flush()


async def revoke_refresh_token(session: AsyncSession, token: RefreshToken) -> None:
    """Revoke a single refresh token during rotation or logout."""
    token.revoked_at = datetime.now(UTC)
    await session.flush()
