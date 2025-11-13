from __future__ import annotations

import base64
import json
import socket
import sys
import time
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[1]


def recv_json(sock: socket.socket, max_bytes: int = 65536) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            raise ValueError("message too large")
    line, _, _ = buf.partition(b"\n")
    if not line:
        raise ValueError("empty message")
    return json.loads(line.decode("utf-8"))


def send_json(sock: socket.socket, data: dict) -> None:
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(payload)


def self_signed_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Bogus Client"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "bogus-client"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def main() -> int:
    host = "127.0.0.1"
    port = int("5000")
    # Start server
    server = subprocess.Popen([sys.executable, str(ROOT/"app"/"server.py")], cwd=ROOT)
    time.sleep(1.5)
    try:
        sock = socket.create_connection((host, port), timeout=5)
        with sock:
            hello = {
                "type": "hello",
                "client_cert": self_signed_pem().decode("utf-8"),
                "nonce": base64.b64encode(b"x" * 16).decode("ascii"),
            }
            send_json(sock, hello)
            resp = recv_json(sock)
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except Exception:
            server.kill()
    (ROOT / "tests" / "logs" / "invalid_cert.log").write_text(json.dumps(resp, indent=2), encoding="utf-8")
    if resp.get("type") == "error" and resp.get("err") == "BAD CERT":
        print("[OK] BAD CERT received — certificate rejected as expected")
        return 0
    print(f"[ERROR] Unexpected response: {resp}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
