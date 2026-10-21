"""
Tests for the /health and /ready endpoints and the config fail-fast behaviour.

Phase 0 gate items:
- GET /health → 200
- GET /ready → 200 when DB reachable, 503 when not
- App refuses to start if PEPPER, JWT_SECRET, or AUDIT_HMAC_KEY missing
- Logs contain request_id; secrets are scrubbed
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required env vars for all tests in this module."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
    monkeypatch.setenv("PEPPER", "test-pepper-value-minimum-length-secret-key-here")
    monkeypatch.setenv("JWT_SECRET", "test-jwt-secret-value-minimum-length-key")
    monkeypatch.setenv("AUDIT_HMAC_KEY", "test-audit-hmac-key-minimum-length-key")
    monkeypatch.setenv("SWITCH_BANK_MAC_KEY", "test-switch-bank-mac-key-min-length")
    monkeypatch.setenv("APP_ENV", "test")

    # Clear the cached settings so each test gets fresh config
    from app.core.config import get_settings
    get_settings.cache_clear()


@pytest.fixture
async def client(_set_test_env: None) -> AsyncClient:
    """Provide an async test client."""
    from app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── Health endpoint ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_health_includes_request_id_header(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert "x-request-id" in resp.headers


# ── Ready endpoint ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ready_returns_200_when_db_ok(client: AsyncClient) -> None:
    with patch("app.main.check_db_connection", new_callable=AsyncMock, return_value=True):
        resp = await client.get("/ready")
        assert resp.status_code == 200
        assert resp.json()["db"] == "ok"


@pytest.mark.asyncio
async def test_ready_returns_503_when_db_unreachable(client: AsyncClient) -> None:
    with patch("app.main.check_db_connection", new_callable=AsyncMock, return_value=False):
        resp = await client.get("/ready")
        assert resp.status_code == 503
        assert resp.json()["db"] == "unreachable"


# ── Config fail-fast ────────────────────────────────────────────────────────

def test_config_rejects_missing_pepper(monkeypatch: pytest.MonkeyPatch) -> None:
    """App must refuse to start if PEPPER is missing."""
    from app.core.config import Settings, get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("PEPPER", "")
    with pytest.raises(Exception, match=r"(?i)secret.*missing|blank"):
        Settings()  # type: ignore[call-arg]


def test_config_rejects_missing_jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import Settings, get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("JWT_SECRET", "")
    with pytest.raises(Exception, match=r"(?i)secret.*missing|blank"):
        Settings()  # type: ignore[call-arg]


def test_config_rejects_missing_audit_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import Settings, get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("AUDIT_HMAC_KEY", "")
    with pytest.raises(Exception, match=r"(?i)secret.*missing|blank"):
        Settings()  # type: ignore[call-arg]


# ── Log scrubbing ──────────────────────────────────────────────────────────

def test_secret_scrubbing_redacts_jwt() -> None:
    """Verify the log processor replaces JWT-like strings."""
    from app.core.logging import scrub_secrets

    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
    result = scrub_secrets(None, "", {"event": f"token is {fake_jwt}"})
    assert "eyJ" not in result["event"]
    assert "[REDACTED" in result["event"]


def test_secret_scrubbing_redacts_mpin() -> None:
    from app.core.logging import scrub_secrets

    result = scrub_secrets(None, "", {"event": 'mpin: 123456'})
    assert "123456" not in result["event"]
    assert "[REDACTED_MPIN]" in result["event"]
