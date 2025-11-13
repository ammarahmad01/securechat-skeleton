from __future__ import annotations

import os
import sys
import time
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    # Ensure a known user exists for login flow
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
    # Start server
    server = subprocess.Popen([sys.executable, str(ROOT/"app"/"server.py")], cwd=ROOT)
    time.sleep(1.5)

    try:
        # Run a minimal chat via client with scripted input
        client = subprocess.Popen([sys.executable, str(ROOT/"app"/"client.py")], cwd=ROOT,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        script = [
            "l\n",               # login
            "y\n",               # by email
            "test@example.com\n",
            "P@ssw0rd!\n",
            "nonce\n",
            "/quit\n",
        ]
        for line in script:
            client.stdin.write(line)
            client.stdin.flush()
            time.sleep(0.3)
        out, _ = client.communicate(timeout=20)
        (ROOT/"tests"/"logs"/"nonrep_verification.log").write_text(out, encoding="utf-8")
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except Exception:
            server.kill()

    # Verify transcript and receipt using the tool
    # Pick the latest session_*_receipt.json
    transcripts = list((ROOT/"transcripts").glob("session_*_receipt.json"))
    if not transcripts:
        print("[ERROR] No session receipt found; ensure a session completed")
        return 1
    receipt = max(transcripts, key=lambda p: p.stat().st_mtime)
    log_path = receipt.with_suffix("")
    transcript_log = ROOT/"transcripts"/ ("session_" + receipt.stem.split("_receipt")[0].split("session_")[-1] + ".log")
    cmd = [sys.executable, str(ROOT/"tools"/"verify_transcript.py"), "--transcript", str(transcript_log), "--receipt", str(receipt), "--cert", str(ROOT/"certs"/"server-cert.pem")]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    (ROOT/"tests"/"logs"/"nonrep_verification.log").write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
    print(proc.stdout)
    return 0 if proc.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
