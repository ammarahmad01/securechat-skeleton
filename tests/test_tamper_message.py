from __future__ import annotations

import base64
import json
import os
import socket
import sys
import time
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

from crypto import dh as dhmod
from crypto import aes as aesmod
from crypto import sign as signmod


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


def load_cert(path: Path) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_server_cert(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    if cert.issuer != ca_cert.subject:
        raise ValueError("issuer mismatch")
    ca_pub = ca_cert.public_key()
    ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, asym_padding.PKCS1v15(), cert.signature_hash_algorithm)


def main() -> int:
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "5000"))
    ca_cert_path = ROOT / "certs" / "ca.cert.pem"
    client_key_path = ROOT / "certs" / "client-key.pem"

    # Ensure test user exists directly via DB
    try:
        from storage import db as dbmod  # type: ignore
        try:
            dbmod.init_db()
        except Exception:
            pass
        _ = dbmod.create_user("tester@example.com", "tester", "secret")
    except Exception:
        pass

    # Start server
    server = subprocess.Popen([sys.executable, str(ROOT/"app"/"server.py")], cwd=ROOT)
    time.sleep(1.5)

    # Handshake hello
    s = socket.create_connection((host, port), timeout=5)
    with s:
        client_cert_pem = (ROOT / "certs" / "client-cert.pem").read_text(encoding="utf-8")
        hello = {"type": "hello", "client_cert": client_cert_pem, "nonce": base64.b64encode(os.urandom(16)).decode("ascii")}
        send_json(s, hello)
        sh = recv_json(s)
        if sh.get("type") != "server_hello":
            print("[ERROR] No server_hello")
            return 1
        server_cert = x509.load_pem_x509_certificate(sh["server_cert"].encode("utf-8"))
        verify_server_cert(server_cert, load_cert(ca_cert_path))

        # Control-plane DH
        p, g = dhmod.get_group()
        a = dhmod.gen_private(p)
        A = dhmod.compute_pub(g, a, p)
        send_json(s, {"type": "dh client", "g": g, "p": p, "A": A})
        ds = recv_json(s)
        B = int(ds["B"]) if ds.get("type") == "dh server" else None
        if B is None:
            print("[ERROR] No dh server")
            return 1
        Ks = dhmod.compute_shared(B, a, p)
        K = dhmod.derive_key(Ks)

        # Login via username to avoid email prompt
        payload = {"type": "login", "username": "tester", "password": "secret"}
        iv, ct = aesmod.encrypt_aes_cbc(K, json.dumps(payload).encode("utf-8"))
        send_json(s, {"type": "login_encrypted", "iv": base64.b64encode(iv).decode(), "ciphertext": base64.b64encode(ct).decode()})
        ack = recv_json(s)
        if ack.get("status") != "ok":
            print("[ERROR] Login failed; ensure user exists")
            return 1

        # Session DH
        p, g = dhmod.get_group()
        a2 = dhmod.gen_private(p)
        A2 = dhmod.compute_pub(g, a2, p)
        send_json(s, {"type": "session_dh_client", "p": p, "g": g, "A": A2})
        ds2 = recv_json(s)
        if ds2.get("type") != "session_dh_server":
            print("[ERROR] No session_dh_server")
            return 1
        B2 = int(ds2["B"])  # type: ignore
        K2 = dhmod.derive_key(dhmod.compute_shared(B2, a2, p))

        # Prepare signed message
        seq = 1
        ts = int(__import__("time").time() * 1000)
        iv3, ct3 = aesmod.encrypt_aes_cbc(K2, b"tamper-this")
        h = signmod.compute_message_hash(seq, ts, ct3)
        from cryptography.hazmat.primitives import serialization
        my_priv = serialization.load_pem_private_key(client_key_path.read_bytes(), password=None)
        sig = signmod.sign_hash(my_priv, h)

        # Tamper: flip one bit of ciphertext before sending
        ct_tampered = bytearray(ct3)
        ct_tampered[0] ^= 0x01
        send_json(s, {"type": "msg", "seqno": seq, "ts": ts, "iv": base64.b64encode(iv3).decode(), "ct": base64.b64encode(bytes(ct_tampered)).decode(), "sig": base64.b64encode(sig).decode()})

        # Server should drop; if it replies, it will likely send an error or nothing
        try:
            resp = recv_json(s)
        except Exception:
            resp = {"type": "<no-reply>"}
        (ROOT / "tests" / "logs" / "tamper_message.log").write_text(json.dumps(resp, indent=2), encoding="utf-8")
    print("[OK] Tamper test sent a modified ciphertext; check server log for signature failure")
    # Stop server
    server.terminate()
    try:
        server.wait(timeout=3)
    except Exception:
        server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
