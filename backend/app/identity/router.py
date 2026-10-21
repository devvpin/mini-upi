"""
identity.router — Endpoints for login, token refresh, logout, password change, and profile.

Crypto concept: Rate limiting, timing-equalised authentication, rotating refresh tokens.
Threat mitigated: Credential stuffing, brute-force attacks, session hijacking.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.identity.deps import get_current_user
from app.identity.models import User
from app.identity.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RefreshResponse,
    TokenResponse,
    UserProfileResponse,
)
from app.identity.service import (
    authenticate_user,
    change_password,
    logout_session,
    rotate_session,
)

router = APIRouter(prefix="", tags=["auth"])


def _serialize_user(user: User) -> UserProfileResponse:
    dept_code = user.department.code if user.department else None
    class_name = user.class_group.name if user.class_group else None
    role_str = user.role if isinstance(user.role, str) else user.role.value
    status_str = user.status if isinstance(user.status, str) else user.status.value
    return UserProfileResponse(
        id=user.id,
        college_id=user.college_id,
        full_name=user.full_name,
        email=user.email,
        role=role_str,
        status=status_str,
        department_code=dept_code,
        class_name=class_name,
        must_change_password=user.must_change_password,
    )


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    req: LoginRequest,
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate with college_id and password. Returns access and refresh tokens."""
    user, access_token, raw_refresh = await authenticate_user(
        session=session,
        college_id=req.college_id,
        password=req.password,
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=900,
        refresh_token=raw_refresh,
        must_change_password=user.must_change_password,
        user=_serialize_user(user),
    )


@router.post("/auth/refresh", response_model=RefreshResponse)
async def refresh(
    req: RefreshRequest,
    session: AsyncSession = Depends(get_db),
) -> RefreshResponse:
    """Rotate a refresh token to get a new access token and fresh refresh token."""
    new_access, new_refresh = await rotate_session(
        session=session,
        raw_refresh_token=req.refresh_token,
    )
    return RefreshResponse(
        access_token=new_access,
        token_type="bearer",
        expires_in=900,
        refresh_token=new_refresh,
    )


@router.post("/auth/logout")
async def logout(
    req: LogoutRequest,
    session: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Revoke refresh token session on logout."""
    await logout_session(session, req.refresh_token)
    return {"status": "logged_out"}


@router.post("/auth/change-password")
async def change_user_password(
    req: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Change user password after verifying current password."""
    await change_password(
        session=session,
        user=user,
        current_password=req.current_password,
        new_password=req.new_password,
    )
    return {"status": "password_changed"}


@router.get("/me", response_model=UserProfileResponse)
async def get_profile(
    user: User = Depends(get_current_user),
) -> UserProfileResponse:
    """Get current authenticated user profile."""
    return _serialize_user(user)
