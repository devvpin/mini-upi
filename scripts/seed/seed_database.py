"""
seed_database.py — Populates the database with departments, classes, and users.

Reads:
- scripts/seed/departments.csv
- scripts/seed/classes.csv
- scripts/seed/users.csv

Generates:
- scripts/seed/one_time_credentials.csv (git-ignored)
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from app.admin.csv_import import process_import
from app.core.database import async_session_factory


async def run_seed() -> None:
    seed_dir = Path(__file__).parent
    dept_file = seed_dir / "departments.csv"
    class_file = seed_dir / "classes.csv"
    user_file = seed_dir / "users.csv"
    creds_file = seed_dir / "one_time_credentials.csv"

    dept_csv = dept_file.read_text(encoding="utf-8") if dept_file.exists() else None
    class_csv = class_file.read_text(encoding="utf-8") if class_file.exists() else None
    user_csv = user_file.read_text(encoding="utf-8") if user_file.exists() else None

    async with async_session_factory() as session:
        result = await process_import(
            session=session,
            departments_csv=dept_csv,
            classes_csv=class_csv,
            users_csv=user_csv,
            dry_run=False,
            credentials_output_path=creds_file,
        )

    print(
        f"Seeding completed:\n"
        f"  Departments created: {result.departments_created}, existing: {result.departments_existing}\n"
        f"  Classes created: {result.classes_created}, existing: {result.classes_existing}\n"
        f"  Users created: {result.users_created}, updated: {result.users_updated}\n"
        f"  Errors: {len(result.errors)}"
    )
    if result.errors:
        for err in result.errors[:10]:
            print(f"    - {err}")


if __name__ == "__main__":
    asyncio.run(run_seed())
