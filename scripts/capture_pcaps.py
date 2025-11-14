from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


SCENARIOS = [
    ("normal_chat", ROOT / "tests" / "test_normal_chat.py"),
    ("invalid_cert", ROOT / "tests" / "test_invalid_cert.py"),
    ("tamper_message", ROOT / "tests" / "test_tamper_message.py"),
    ("replay_attack", ROOT / "tests" / "test_replay_attack.py"),
    ("nonrep_verification", ROOT / "tests" / "test_nonrep_verification.py"),
]


def run_with_capture(tshark: str, iface: str, out_pcap: Path, test_script: Path) -> int:
    out_pcap.parent.mkdir(parents=True, exist_ok=True)
    # Start capture
    cap_cmd = [tshark, "-i", iface, "-f", "tcp port 5000", "-n", "-w", str(out_pcap)]
    cap = None
    rc = 1
    try:
        cap = subprocess.Popen(cap_cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        # Run the test
        test_cmd = [sys.executable, str(test_script)]
        rc = subprocess.call(test_cmd, cwd=ROOT)
    finally:
        if cap and cap.poll() is None:
            try:
                cap.terminate()
                cap.wait(timeout=5)
            except Exception:
                try:
                    cap.kill()
                except Exception:
                    pass
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture PCAPs for all scenarios using tshark")
    ap.add_argument("--tshark", required=True, help="Path to tshark executable")
    ap.add_argument("--iface", required=True, help="Interface index or name (e.g., 10 or 'Npcap Loopback Adapter')")
    ap.add_argument("--only", choices=[name for name, _ in SCENARIOS], help="Capture a single scenario only")
    args = ap.parse_args()

    tshark = args.tshark
    iface = args.iface
    pcaps_dir = ROOT / "tests" / "pcaps"

    scenarios = [s for s in SCENARIOS if (args.only is None or s[0] == args.only)]
    overall = 0
    for name, script in scenarios:
        print(f"[CAPTURE] {name} -> tests/pcaps/{name}.pcapng")
        rc = run_with_capture(tshark, iface, pcaps_dir / f"{name}.pcapng", script)
        print(f"[RESULT] {name}: rc={rc}")
        overall = overall or rc
    print("[INFO] Capture complete.")
    return overall


if __name__ == "__main__":
    raise SystemExit(main())
