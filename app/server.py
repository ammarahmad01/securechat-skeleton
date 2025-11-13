"""Minimal Secure Chat server: JSON hello with certificate exchange.

This is a control-plane handshake over plain TCP (no TLS yet):
- Client sends {type:"hello", client_cert:PEM, nonce:base64}
- Server verifies client cert against local CA, replies with
  {type:"server_hello", server_cert:PEM, nonce:base64}

Crypto and parsing by cryptography/json only; newline-delimited JSON framing.
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
from cryptography.hazmat.primitives import hashes

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


# ---------- Helpers ----------

def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_cert(path: Path) -> x509.Certificate:
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def verify_cert_chain(cert: x509.Certificate, ca_cert: x509.Certificate, expected_role: str) -> None:
    # Basic issuer/subject and time validity
    if cert.issuer != ca_cert.subject:
        raise ValueError("issuer subject mismatch")

    now = dt.datetime.now(dt.timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        # treat naive datetimes as UTC
        not_before = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

    if not (not_before <= now <= not_after):
        raise ValueError("certificate is not currently valid")

    # Signature verification (assuming RSA CA)
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError(f"signature verification failed: {e}")

    # Simple role check via CN substring
    cn = None
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            cn = attr.value
            break
    if not cn or expected_role.lower() not in cn.lower():
        raise ValueError("unexpected certificate role")


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


def handle_client(conn: socket.socket, ca_cert_path: Path, server_cert_path: Path) -> None:
    try:
        incoming = recv_json(conn)
        if incoming.get("type") != "hello":
            send_json(conn, {"type": "error", "err": "BAD MSG"})
            return
        client_cert_pem = incoming.get("client_cert", "").encode("utf-8")
        try:
            client_cert = x509.load_pem_x509_certificate(client_cert_pem)
        except Exception:
            send_json(conn, {"type": "error", "err": "BAD CERT FORMAT"})
            return

        ca_cert = load_cert(ca_cert_path)
        try:
            verify_cert_chain(client_cert, ca_cert, expected_role="client")
        except Exception as e:
            send_json(conn, {"type": "error", "err": "BAD CERT"})
            print(f"[!] Client cert rejected: {e}")
            return

        # Build server hello
        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        server_cert_pem = (server_cert_path.read_text(encoding="utf-8"))

        reply = {
            "type": "server_hello",
            "server_cert": server_cert_pem,
            "nonce": nonce,
        }
        send_json(conn, reply)
        print("[+] Server hello sent to client")
    except Exception as e:
        print(f"[!] Error handling client: {e}")
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()


def main() -> None:
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "5000"))

    root = project_root()
    ca_cert_path = root / "certs" / "ca.cert.pem"
    server_cert_path = root / "certs" / "server-cert.pem"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"[*] Server listening on {host}:{port}")
        conn, addr = s.accept()
        print(f"[*] Connection from {addr}")
        handle_client(conn, ca_cert_path, server_cert_path)


if __name__ == "__main__":
    main()
