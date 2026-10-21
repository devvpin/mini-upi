"""
identity.deps — FastAPI dependencies for authentication and role-based access control (RBAC).

Crypto concept: Stateless JWT bearer authentication with fine-grained RBAC enforcement.
Threat mitigated: Privilege escalation, horizontal authorization bypass.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import AppError, auth_failed
from app.identity.models import User, UserStatus
from app.identity.repository import get_user_by_id
from app.identity.tokens import decode_access_token


async def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and verify Bearer JWT from Authorization header, then load active user.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise auth_failed("Missing or invalid authorization header.")

    token = authorization.removeprefix("Bearer ").strip()
    payload = decode_access_token(token)

    try:
        user_id = uuid.UUID(payload["sub"])
    except (ValueError, KeyError):
        raise auth_failed("Invalid token subject.") from None

    user = await get_user_by_id(session, user_id)
    if user is None or user.status != UserStatus.ACTIVE:
        raise auth_failed("User not found or account deactivated.")

    return user


def require_role(*allowed_roles: str) -> Callable[[User], Awaitable[User]]:
    """
    Dependency factory to enforce role-based access control.
    Returns the user if their role is permitted, else raises 403 Forbidden.
    """
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        user_role = user.role if isinstance(user.role, str) else user.role.value
        if user_role not in allowed_roles:
            raise AppError(
                status_code=403,
                code="FORBIDDEN",
                message=f"Access denied. Requires one of roles: {', '.join(allowed_roles)}.",
            )
        return user

    return role_checker
