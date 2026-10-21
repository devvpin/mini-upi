"""
core.database — Async SQLAlchemy engine and session factory.

Provides a single async engine and a session maker for the entire application.
All database access goes through these primitives; no module should create its
own engine.

Crypto concept: centralised DB access control supports the audit trail design
(only the bank module writes ledger rows).

Threat mitigated: rogue modules bypassing audit controls by creating ad-hoc
database connections.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

_engine = create_async_engine(
    get_settings().database_url,
    echo=(get_settings().app_env == "development"),
    pool_size=10,
    max_overflow=5,
)

async_session_factory = async_sessionmaker(
    _engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session."""
    async with async_session_factory() as session:
        yield session


async def check_db_connection() -> bool:
    """Check whether the database is reachable. Used by /ready."""
    try:
        async with _engine.connect() as conn:
            await conn.execute(
                # Use text() for raw SQL
                __import__("sqlalchemy").text("SELECT 1")
            )
        return True
    except Exception:
        return False
