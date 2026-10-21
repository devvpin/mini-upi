"""
admin.csv_import — Importer for campus hierarchy and user accounts from CSV.

Crypto concept: Input sanitisation, robust validation, password generation with CSPRNG.
Threat mitigated: Data corruption, malformed input injection, duplicate identity creation.
"""

from __future__ import annotations

import csv
import io
import re
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.crypto.kdf import hash_secret
from app.identity.models import ClassGroup, UserRole
from app.identity.repository import (
    create_class,
    create_department,
    create_user,
    get_class_by_dept_year_name,
    get_department_by_code,
    get_user_by_college_id,
    get_user_by_email,
)
from app.identity.schemas import ImportResult

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def generate_temporary_password(length: int = 12) -> str:
    """Generate a random temporary password using CSPRNG."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


@dataclass
class ImportStats:
    departments_created: int = 0
    departments_existing: int = 0
    classes_created: int = 0
    classes_existing: int = 0
    users_created: int = 0
    users_updated: int = 0
    errors: list[str] = field(default_factory=list)
    generated_credentials: list[dict[str, str]] = field(default_factory=list)


async def process_import(
    session: AsyncSession,
    *,
    departments_csv: str | None = None,
    classes_csv: str | None = None,
    users_csv: str | None = None,
    dry_run: bool = False,
    credentials_output_path: Path | None = None,
) -> ImportResult:
    """
    Import departments, classes, and users.
    Idempotent: skips or updates existing records.
    If dry_run is True, rolls back all changes.
    """
    stats = ImportStats()
    settings = get_settings()
    pepper = settings.pepper

    # 1. Departments CSV: code,name
    if departments_csv:
        reader = csv.DictReader(io.StringIO(departments_csv.strip()))
        seen_codes: set[str] = set()
        for idx, row in enumerate(reader, start=2):
            code = (row.get("code") or "").strip().lower()
            name = (row.get("name") or "").strip()
            if not code or not name:
                stats.errors.append(f"Departments line {idx}: Missing code or name.")
                continue
            if code in seen_codes:
                stats.errors.append(
                    f"Departments line {idx}: Duplicate department code '{code}' in CSV."
                )
                continue
            seen_codes.add(code)

            existing = await get_department_by_code(session, code)
            if existing:
                stats.departments_existing += 1
            else:
                await create_department(session, code=code, name=name)
                stats.departments_created += 1

    # 2. Classes CSV: department_code,name,year,division
    if classes_csv:
        reader = csv.DictReader(io.StringIO(classes_csv.strip()))
        for idx, row in enumerate(reader, start=2):
            dept_code = (row.get("department_code") or "").strip().lower()
            name = (row.get("name") or "").strip()
            year_str = (row.get("year") or "").strip()
            division = (row.get("division") or "").strip() or None

            try:
                year = int(year_str)
                if not (1 <= year <= 4):
                    raise ValueError()
            except ValueError:
                stats.errors.append(
                    f"Classes line {idx}: Invalid year '{year_str}' (must be 1..4)."
                )
                continue

            dept = await get_department_by_code(session, dept_code)
            if not dept:
                stats.errors.append(f"Classes line {idx}: Department '{dept_code}' not found.")
                continue

            existing_class = await get_class_by_dept_year_name(session, dept.id, year, name)
            if existing_class:
                stats.classes_existing += 1
            else:
                await create_class(session, dept.id, name=name, year=year, division=division)
                stats.classes_created += 1

    # 3. Users CSV: college_id,full_name,email,role,department_code,class_name,initial_password
    if users_csv:
        reader = csv.DictReader(io.StringIO(users_csv.strip()))
        seen_college_ids: set[str] = set()
        seen_emails: set[str] = set()

        for idx, row in enumerate(reader, start=2):
            college_id = (row.get("college_id") or "").strip().lower()
            full_name = (row.get("full_name") or "").strip()
            email = (row.get("email") or "").strip().lower()
            role_str = (row.get("role") or "").strip().lower()
            dept_code = (row.get("department_code") or "").strip().lower() or None
            class_name = (row.get("class_name") or "").strip() or None
            initial_password = (row.get("initial_password") or "").strip()

            if not college_id or not full_name or not email:
                stats.errors.append(f"Users line {idx}: Missing college_id, full_name, or email.")
                continue

            if not EMAIL_REGEX.match(email):
                stats.errors.append(f"Users line {idx}: Invalid email '{email}'.")
                continue

            if college_id in seen_college_ids:
                stats.errors.append(
                    f"Users line {idx}: Duplicate college_id '{college_id}' in CSV."
                )
                continue
            seen_college_ids.add(college_id)

            if email in seen_emails:
                stats.errors.append(f"Users line {idx}: Duplicate email '{email}' in CSV.")
                continue
            seen_emails.add(email)

            try:
                role = UserRole(role_str)
            except ValueError:
                stats.errors.append(f"Users line {idx}: Invalid role '{role_str}'.")
                continue

            dept_id = None
            if dept_code:
                dept = await get_department_by_code(session, dept_code)
                if not dept:
                    stats.errors.append(
                        f"Users line {idx}: Department '{dept_code}' does not exist."
                    )
                    continue
                dept_id = dept.id

            class_id = None
            if role == UserRole.STUDENT:
                if not class_name or not dept_id:
                    stats.errors.append(
                        f"Users line {idx}: Student must have both department and class."
                    )
                    continue
                # Search for class by name under dept
                from sqlalchemy import select
                cg_stmt = select(ClassGroup).where(
                    ClassGroup.department_id == dept_id, ClassGroup.name == class_name
                )
                cg_res = await session.execute(cg_stmt)
                cg = cg_res.scalar_one_or_none()
                if not cg:
                    stats.errors.append(
                        f"Users line {idx}: Class '{class_name}' "
                        f"not found under department '{dept_code}'."
                    )
                    continue
                class_id = cg.id

            password_to_use = initial_password or generate_temporary_password()
            if settings.app_env == "test":
                password_hash = hash_secret(
                    password_to_use, pepper, time_cost=1, memory_cost=1024
                )
            else:
                password_hash = hash_secret(password_to_use, pepper)

            existing_user = await get_user_by_college_id(session, college_id)
            if existing_user:
                existing_user.full_name = full_name
                existing_user.email = email
                existing_user.role = role
                existing_user.department_id = dept_id
                existing_user.class_id = class_id
                stats.users_updated += 1
            else:
                existing_email = await get_user_by_email(session, email)
                if existing_email:
                    stats.errors.append(
                        f"Users line {idx}: Email '{email}' already registered to another user."
                    )
                    continue

                await create_user(
                    session=session,
                    college_id=college_id,
                    full_name=full_name,
                    email=email,
                    password_hash=password_hash,
                    role=role,
                    department_id=dept_id,
                    class_id=class_id,
                    must_change_password=True,
                )
                stats.users_created += 1
                stats.generated_credentials.append(
                    {
                        "college_id": college_id,
                        "role": role_str,
                        "one_time_password": password_to_use,
                    }
                )

    if dry_run:
        await session.rollback()
    else:
        await session.commit()
        if credentials_output_path and stats.generated_credentials:
            credentials_output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(credentials_output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["college_id", "role", "one_time_password"])
                writer.writeheader()
                writer.writerows(stats.generated_credentials)

    return ImportResult(
        departments_created=stats.departments_created,
        departments_existing=stats.departments_existing,
        classes_created=stats.classes_created,
        classes_existing=stats.classes_existing,
        users_created=stats.users_created,
        users_updated=stats.users_updated,
        errors=stats.errors,
        dry_run=dry_run,
    )
