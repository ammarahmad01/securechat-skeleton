from __future__ import annotations

import os
import sys
import time
import subprocess
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
CERTS = ROOT / "certs"
LOGS = ROOT / "tests" / "logs"
PCAPS = ROOT / "tests" / "pcaps"


def have_certs() -> bool:
    return all((CERTS / p).exists() for p in [
        "ca.cert.pem", "server-cert.pem", "server-key.pem", "client-cert.pem", "client-key.pem"
    ])


def maybe_start_capture(outfile: Path):
    tshark = shutil.which("tshark")
    if not tshark:
        print("[INFO] tshark not found; skipping PCAP capture")
        return None
    cmd = [tshark, "-i", "1", "-f", "tcp port 5000", "-w", str(outfile)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        return proc
    except Exception:
        print("[WARN] Failed to start tshark; skipping capture")
        return None


def main() -> int:
    if not have_certs():
        print("[ERROR] Missing certs in certs/ — generate via scripts/gen_ca.py and gen_cert.py")
        return 1

    # Ensure a test user exists directly via DB helper
    try:
        sys.path.insert(0, str(ROOT / "app"))
        from storage import db as dbmod  # type: ignore
        try:
            dbmod.init_db()
        except Exception:
            pass
        _ = dbmod.create_user("test@example.com", "testuser", "P@ssw0rd!")
    except Exception:
        pass

    server = subprocess.Popen([sys.executable, str(ROOT/"app"/"server.py")], cwd=ROOT)
    time.sleep(1.5)

    pcap_proc = maybe_start_capture(PCAPS / "normal_chat.pcapng")

    try:
        # Drive client via stdin: Login with email then send 2 messages, then quit
        client = subprocess.Popen([sys.executable, str(ROOT/"app"/"client.py")], cwd=ROOT,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        # Choose login (l) and email route (y)
        script = [
            "l\n",        # login
            "y\n",        # by email
            "test@example.com\n",
            "P@ssw0rd!\n",
            "Hello one\n",
            "Hello two\n",
            "/quit\n",
        ]
        for line in script:
            client.stdin.write(line)
            client.stdin.flush()
            time.sleep(0.3)
        out, _ = client.communicate(timeout=20)
        (LOGS / "normal_chat.log").write_text(out, encoding="utf-8")
    except Exception as e:
        print(f"[ERROR] Client run failed: {e}")
    finally:
        if pcap_proc:
            try:
                pcap_proc.terminate()
                pcap_proc.wait(timeout=3)
            except Exception:
                pass
        server.terminate()
        try:
            server.wait(timeout=3)
        except Exception:
            server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
