"""Offline verifier for chat transcripts and signed receipts.

Usage (PowerShell):
  python tools/verify_transcript.py --transcript transcripts/session_<id>.log \
    --receipt transcripts/session_<id>_receipt.json --cert certs/server-cert.pem

Exits 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography import x509


def project_root() -> Path:
    # tools/ -> project root
    return Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify transcript hash against signed receipt")
    parser.add_argument("--transcript", required=True, help="Path to transcript .log file")
    parser.add_argument("--receipt", required=True, help="Path to receipt .json file")
    parser.add_argument("--cert", required=True, help="Path to signer certificate (PEM)")
    args = parser.parse_args()

    root = project_root()
    # Ensure we can import app modules
    sys.path.insert(0, str(root / "app"))

    from storage.transcript import compute_transcript_sha256
    from crypto import sign as signmod

    tpath = Path(args.transcript)
    rpath = Path(args.receipt)
    cpath = Path(args.cert)

    if not tpath.exists():
        print(f"[ERROR] Transcript not found: {tpath}")
        return 1
    if not rpath.exists():
        print(f"[ERROR] Receipt not found: {rpath}")
        return 1
    if not cpath.exists():
        print(f"[ERROR] Certificate not found: {cpath}")
        return 1

    try:
        th_actual = compute_transcript_sha256(tpath)
    except Exception as e:
        print(f"[ERROR] Failed computing transcript hash: {e}")
        return 1

    try:
        receipt = json.loads(rpath.read_text(encoding="utf-8"))
        th_claimed = receipt.get("transcript_sha256")
        sig_b64 = receipt.get("sig")
        if not isinstance(th_claimed, str) or not isinstance(sig_b64, str):
            print("[ERROR] Receipt missing fields 'transcript_sha256' or 'sig'")
            return 1
    except Exception as e:
        print(f"[ERROR] Failed reading receipt: {e}")
        return 1

    if th_actual.lower() != th_claimed.lower():
        print("[ERROR] Transcript hash mismatch")
        print(f"  expected: {th_claimed}")
        print(f"  actual  : {th_actual}")
        return 1

    try:
        cert = x509.load_pem_x509_certificate(cpath.read_bytes())
        sig = base64.b64decode(sig_b64)
        raw = bytes.fromhex(th_actual)
        signmod.verify_signature(cert.public_key(), sig, raw)
    except Exception as e:
        print(f"[ERROR] Signature verification failed: {e}")
        return 1

    print("[OK] Transcript and receipt verified successfully")
    print(f"  signer : {cpath}")
    print(f"  hash   : {th_actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
