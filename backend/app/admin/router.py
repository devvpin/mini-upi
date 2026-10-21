"""
admin.router — Administrative routes for CSV import, stats, and user management.

Crypto concept: Strict RBAC enforcement via require_role("admin"); audit traceability.
Threat mitigated: Unauthorized administrative access and data tampering.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.csv_import import process_import
from app.core.database import get_db
from app.identity.deps import require_role
from app.identity.models import User
from app.identity.schemas import ImportResult

router = APIRouter(prefix="/admin", tags=["admin"])


class ImportJsonRequest(BaseModel):
    departments_csv: str | None = None
    classes_csv: str | None = None
    users_csv: str | None = None
    dry_run: bool = False


@router.post("/import", response_model=ImportResult)
async def import_hierarchy(
    request: Request,
    session: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> ImportResult:
    """
    Import departments, classes, and users from CSV data.
    Requires admin role. Supports dry-run validation.
    Accepts both JSON payload and multipart form data.
    """
    content_type = request.headers.get("content-type", "")

    dept_str: str | None = None
    class_str: str | None = None
    user_str: str | None = None
    is_dry_run: bool = False

    if "multipart/form-data" in content_type:
        form = await request.form()
        is_dry_run = str(form.get("dry_run", "false")).lower() in ("true", "1", "yes")

        d_file = form.get("departments_file")
        if d_file and hasattr(d_file, "read"):
            dept_str = (await d_file.read()).decode("utf-8")

        c_file = form.get("classes_file")
        if c_file and hasattr(c_file, "read"):
            class_str = (await c_file.read()).decode("utf-8")

        u_file = form.get("users_file")
        if u_file and hasattr(u_file, "read"):
            user_str = (await u_file.read()).decode("utf-8")
    else:
        try:
            body = await request.json()
            req = ImportJsonRequest(**body)
            dept_str = req.departments_csv
            class_str = req.classes_csv
            user_str = req.users_csv
            is_dry_run = req.dry_run
        except Exception:
            pass

    creds_path = Path("scripts/seed/one_time_credentials.csv")

    return await process_import(
        session=session,
        departments_csv=dept_str,
        classes_csv=class_str,
        users_csv=user_str,
        dry_run=is_dry_run,
        credentials_output_path=creds_path,
    )


@router.get("/stats")
async def get_admin_stats(
    _admin: User = Depends(require_role("admin")),
) -> dict[str, str | int]:
    """Admin dashboard stats overview."""
    return {"status": "ok", "message": "Admin stats overview"}
