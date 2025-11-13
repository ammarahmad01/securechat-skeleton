from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], log_path: Path) -> int:
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT)
        return proc.wait()


def main() -> int:
    tests = [
        "test_normal_chat.py",
        "test_invalid_cert.py",
        "test_tamper_message.py",
        "test_replay_attack.py",
        "test_nonrep_verification.py",
    ]
    rc_total = 0
    for t in tests:
        print(f"\n[RUNNING] {t}")
        rc = run([sys.executable, str(ROOT / "tests" / t)], ROOT / "tests" / "logs" / (Path(t).stem + ".log"))
        print(f"[RESULT] {t}: rc={rc}")
        rc_total = rc_total or rc
    print("\n[INFO] All tests completed.")
    return rc_total


if __name__ == "__main__":
    raise SystemExit(main())
