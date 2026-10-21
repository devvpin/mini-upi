"""
generate_seed_users.py — Generates sample users.csv for the campus hierarchy.

Outputs:
- 2 admins
- 22 faculty (2 per department across 11 departments)
- 200 students (distributed across the 39 classes)
"""

from __future__ import annotations

import csv
from pathlib import Path

DEPARTMENTS = ["cp", "it", "ec", "ee", "me", "ce", "ch", "mc", "ai", "ic", "ash"]

CLASSES = [
    # Year 1 (9 classes under ash)
    ("ash", "FY-CP-A"), ("ash", "FY-CP-B"), ("ash", "FY-IT"), ("ash", "FY-EC"),
    ("ash", "FY-EE"), ("ash", "FY-ME"), ("ash", "FY-CE"), ("ash", "FY-CH"), ("ash", "FY-MC"),
    # Year 2 (8 classes)
    ("cp", "SY-CP-A"), ("cp", "SY-CP-B"), ("it", "SY-IT"), ("ec", "SY-EC"),
    ("ee", "SY-EE"), ("me", "SY-ME"), ("ce", "SY-CE"), ("ch", "SY-CH"),
    # Year 3 (11 classes)
    ("cp", "TY-CP-A"), ("cp", "TY-CP-B"), ("it", "TY-IT-A"), ("it", "TY-IT-B"),
    ("ec", "TY-EC"), ("ee", "TY-EE"), ("me", "TY-ME"), ("ce", "TY-CE"),
    ("ch", "TY-CH"), ("mc", "TY-MC"), ("ai", "TY-AI"),
    # Year 4 (11 classes)
    ("cp", "LY-CP-A"), ("cp", "LY-CP-B"), ("it", "LY-IT-A"), ("it", "LY-IT-B"),
    ("ec", "LY-EC"), ("ee", "LY-EE"), ("me", "LY-ME"), ("ce", "LY-CE"),
    ("ch", "LY-CH"), ("mc", "LY-MC"), ("ai", "LY-AI"),
]

FIRST_NAMES = [
    "Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh", "Ayaan", "Krishna", "Ishaan",
    "Shaurya", "Atharva", "Advik", "Pranav", "Advaith", "Aaryan", "Dhruv", "Kabir", "Ritvik", "Darsh",
    "Ananya", "Diya", "Gauri", "Ishita", "Kavya", "Khushi", "Navya", "Pooja", "Priya", "Riya",
    "Roshni", "Saanvi", "Sara", "Shreya", "Sneha", "Tanvi", "Vanshika", "Zara", "Aarohi", "Meera"
]

LAST_NAMES = [
    "Patel", "Shah", "Sharma", "Verma", "Mehta", "Desai", "Joshi", "Bhatt", "Chauhan", "Trivedi",
    "Pandya", "Dave", "Kulkarni", "Iyer", "Nair", "Rao", "Reddy", "Gupta", "Singh", "Kumar"
]


def generate_users() -> list[dict[str, str]]:
    users: list[dict[str, str]] = []

    # 1. Admins
    users.append({
        "college_id": "admin01",
        "full_name": "Campus Administrator",
        "email": "admin01@gcet.edu",
        "role": "admin",
        "department_code": "cp",
        "class_name": "",
        "initial_password": "AdminPassword@123",
    })
    users.append({
        "college_id": "admin02",
        "full_name": "Deputy Administrator",
        "email": "admin02@gcet.edu",
        "role": "admin",
        "department_code": "it",
        "class_name": "",
        "initial_password": "AdminPassword@123",
    })

    # 2. Faculty (2 per department = 22 faculty)
    fac_idx = 1
    for dept in DEPARTMENTS:
        for i in range(1, 3):
            fname = FIRST_NAMES[(fac_idx * 3) % len(FIRST_NAMES)]
            lname = LAST_NAMES[(fac_idx * 5) % len(LAST_NAMES)]
            cid = f"fac_{dept}_{i:02d}"
            users.append({
                "college_id": cid,
                "full_name": f"Prof. {fname} {lname}",
                "email": f"{cid}@gcet.edu",
                "role": "faculty",
                "department_code": dept,
                "class_name": "",
                "initial_password": "FacultyPassword@123",
            })
            fac_idx += 1

    # 3. Students (~200 distributed across the 39 classes)
    student_count = 200
    for s_idx in range(1, student_count + 1):
        dept_code, class_name = CLASSES[(s_idx - 1) % len(CLASSES)]
        fname = FIRST_NAMES[(s_idx * 7) % len(FIRST_NAMES)]
        lname = LAST_NAMES[(s_idx * 11) % len(LAST_NAMES)]
        cid = f"22{dept_code[:2]}{s_idx:03d}"
        users.append({
            "college_id": cid,
            "full_name": f"{fname} {lname}",
            "email": f"{cid}@gcet.edu",
            "role": "student",
            "department_code": dept_code,
            "class_name": class_name,
            "initial_password": "StudentPassword@123",
        })

    return users


def main() -> None:
    users = generate_users()
    out_path = Path(__file__).parent / "users.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "college_id",
                "full_name",
                "email",
                "role",
                "department_code",
                "class_name",
                "initial_password",
            ],
        )
        writer.writeheader()
        writer.writerows(users)
    print(f"Generated {len(users)} users in {out_path}")


if __name__ == "__main__":
    main()
