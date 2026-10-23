"""
core.config — Pydantic Settings loader.

Reads configuration from environment variables (or .env file in development).
The app refuses to start if any cryptographic secret is missing, ensuring we
never run with weakened security.

Crypto concept: fail-fast secret validation at startup.
Threat mitigated: silent degradation to unsigned / unencrypted mode.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str

    # ── Crypto secrets (app refuses to start if any is blank) ─────────────
    pepper: str
    jwt_secret: str
    audit_hmac_key: str
    switch_bank_mac_key: str

    # ── Key / cert file paths (Phase 3+) ──────────────────────────────────
    ca_cert_path: str = "/run/secrets/ca_cert.pem"
    ca_key_path: str = "/run/secrets/ca_key.pem"
    psp_key_path: str = "/run/secrets/psp_key.pem"
    psp_cert_path: str = "/run/secrets/psp_cert.pem"
    bank_key_path: str = "/run/secrets/bank_key.pem"
    bank_cert_path: str = "/run/secrets/bank_cert.pem"
    server_ecdh_key_path: str = "/run/secrets/server_ecdh_key.pem"
    server_cert_path: str = "/run/secrets/server_cert.pem"

    # ── App behaviour ─────────────────────────────────────────────────────
    app_env: Literal["development", "production", "test"] = "development"
    web_origin: str = "https://localhost"
    vpa_suffix: str = "gcet"
    token_ttl_minutes: int = 15
    ts_window_seconds: int = 60
    max_txn_paise: int = 500_000
    daily_limit_paise: int = 2_000_000
    initial_balance_student_paise: int = 100_000
    initial_balance_faculty_paise: int = 200_000
    demo_mode: bool = False

    @field_validator("pepper", "jwt_secret", "audit_hmac_key", "switch_bank_mac_key")
    @classmethod
    def secrets_must_not_be_blank(cls, v: str, info: object) -> str:
        """Refuse to start if any cryptographic secret is missing or blank."""
        if not v or not v.strip():
            raise ValueError(
                "Required secret is missing or blank. "
                "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
