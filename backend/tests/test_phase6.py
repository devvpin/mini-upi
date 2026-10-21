from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import get_settings
from app.main import create_app


@pytest.fixture(autouse=True)
def phase6_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("PEPPER", "phase6-pepper-minimum-32-characters")
    monkeypatch.setenv("JWT_SECRET", "phase6-jwt-secret-minimum-32-characters")
    monkeypatch.setenv("AUDIT_HMAC_KEY", "phase6-audit-key-minimum-32-characters")
    monkeypatch.setenv("SWITCH_BANK_MAC_KEY", "phase6-mac-key-minimum-32-characters")
    monkeypatch.setenv("APP_ENV", "test")
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_security_headers_are_present() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.headers["content-security-policy"].startswith("default-src")
    assert response.headers["strict-transport-security"].startswith("max-age")
    assert response.headers["x-frame-options"] == "DENY"


@pytest.mark.asyncio
async def test_payment_rate_limit_blocks_after_twenty_requests() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        responses = [
            await client.post(
                "/api/v1/payments/pay",
                json={},
            )
            for _ in range(21)
        ]
    assert responses[-1].status_code == 429
    assert responses[-1].json()["error"]["code"] == "RATE_LIMITED"
