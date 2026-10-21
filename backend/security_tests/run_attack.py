"""Run the Phase 6 attack-demo smoke checks.

The integration attack matrix is exercised by the Phase 3/4 rejection tests.
This command gives the seminar demo one stable entry point.
"""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    command = [sys.executable, "-m", "pytest", "tests/test_phase3.py", "tests/test_phase4.py", "-q"]
    result = subprocess.run(command, check=False)
    if result.returncode == 0:
        print("PASS = attack blocked")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
