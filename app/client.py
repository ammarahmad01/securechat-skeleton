"""Minimal Secure Chat client: JSON hello with certificate exchange.

This pairs with app/server.py for a basic control-plane handshake.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import sys
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_cert(path: Path) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_server_cert(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    if cert.issuer != ca_cert.subject:
        raise ValueError("issuer mismatch")
    now = dt.datetime.now(dt.timezone.utc)
    try:
        nbf, naf = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        nbf = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        naf = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    if not (nbf <= now <= naf):
        raise ValueError("server cert not currently valid")
    # RSA signature check
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        asym_padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    # CN check contains 'server'
    cn = next((a.value for a in cert.subject if a.oid == x509.NameOID.COMMON_NAME), None)
    if not cn or "server" not in cn.lower():
        raise ValueError("unexpected server certificate CN")


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


def main() -> None:
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "5000"))

    root = project_root()
    ca_cert_path = root / "certs" / "ca.cert.pem"
    client_cert_path = root / "certs" / "client-cert.pem"

    ca_cert_pem = ca_cert_path.read_text(encoding="utf-8")
    client_cert_pem = client_cert_path.read_text(encoding="utf-8")

    hello = {
        "type": "hello",
        "client_cert": client_cert_pem,
        "nonce": base64.b64encode(os.urandom(16)).decode("ascii"),
    }

    with socket.create_connection((host, port), timeout=10) as s:
        send_json(s, hello)
        reply = recv_json(s)
        if reply.get("type") != "server_hello":
            err = reply.get("err", "unexpected reply")
            raise SystemExit(f"Handshake failed: {err}")

        server_cert_pem = reply.get("server_cert", "").encode("utf-8")
        server_cert = x509.load_pem_x509_certificate(server_cert_pem)
        ca_cert = load_cert(ca_cert_path)
        verify_server_cert(server_cert, ca_cert)
        print("[+] Handshake OK. Received server_hello.")


if __name__ == "__main__":
    main()
