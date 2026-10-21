"""
identity.schemas — Pydantic request and response schemas for identity and auth.

Crypto concept: Strict input validation and sanitisation preventing injection attacks.
Threat mitigated: Type confusion, buffer overflows, format string vulnerabilities.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    college_id: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(default=900, description="Expiration in seconds (15 min)")
    refresh_token: str
    must_change_password: bool = False
    user: UserProfileResponse


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=256)


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class UserProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    college_id: str
    full_name: str
    email: str
    role: str
    status: str
    department_code: str | None = None
    class_name: str | None = None
    must_change_password: bool


class ImportResult(BaseModel):
    departments_created: int
    departments_existing: int
    classes_created: int
    classes_existing: int
    users_created: int
    users_updated: int
    errors: list[str]
    dry_run: bool
