"""
conftest.py — Global test configuration and environment setup.
Sets mandatory environment variables before any module is imported during test collection.
"""

from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("PEPPER", "test-static-pepper-minimum-32-chars-long-secret")
os.environ.setdefault("JWT_SECRET", "test-static-jwt-secret-minimum-32-chars-secret")
os.environ.setdefault("AUDIT_HMAC_KEY", "test-static-audit-hmac-key-minimum-32-chars")
os.environ.setdefault("SWITCH_BANK_MAC_KEY", "test-static-switch-bank-mac-key-32-chars")
os.environ.setdefault("APP_ENV", "test")
