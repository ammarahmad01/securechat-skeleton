from __future__ import annotations

import base64
import json
import os
import socket
import sys
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

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


def main() -> int:
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "5000"))
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
    __import__("time").sleep(1.5)

    s = socket.create_connection((host, port), timeout=5)
    with s:
        client_cert_pem = (ROOT / "certs" / "client-cert.pem").read_text(encoding="utf-8")
        send_json(s, {"type": "hello", "client_cert": client_cert_pem, "nonce": base64.b64encode(os.urandom(16)).decode("ascii")})
        sh = recv_json(s)
        if sh.get("type") != "server_hello":
            print("[ERROR] No server_hello")
            return 1

        # DH + login
        p, g = dhmod.get_group()
        a = dhmod.gen_private(p)
        A = dhmod.compute_pub(g, a, p)
        send_json(s, {"type": "dh client", "g": g, "p": p, "A": A})
        ds = recv_json(s)
        Ks = dhmod.derive_key(dhmod.compute_shared(int(ds["B"]), a, p))
        payload = {"type": "login", "username": "tester", "password": "secret"}
        iv, ct = aesmod.encrypt_aes_cbc(Ks, json.dumps(payload).encode("utf-8"))
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
        B2 = int(ds2["B"]) if ds2.get("type") == "session_dh_server" else None
        if B2 is None:
            print("[ERROR] No session DH reply")
            return 1
        K2 = dhmod.derive_key(dhmod.compute_shared(B2, a2, p))

        # Build one signed+encrypted message
        seq = 1
        ts = int(__import__("time").time() * 1000)
        iv3, ct3 = aesmod.encrypt_aes_cbc(K2, b"replay-this")
        h = signmod.compute_message_hash(seq, ts, ct3)
        from cryptography.hazmat.primitives import serialization
        my_priv = serialization.load_pem_private_key((ROOT/"certs"/"client-key.pem").read_bytes(), password=None)
        sig = signmod.sign_hash(my_priv, h)
        pkt = {"type": "msg", "seqno": seq, "ts": ts, "iv": base64.b64encode(iv3).decode(), "ct": base64.b64encode(ct3).decode(), "sig": base64.b64encode(sig).decode()}

        # Send twice (replay)
        send_json(s, pkt)
        try:
            _ = recv_json(s)
        except Exception:
            pass
        send_json(s, pkt)
        try:
            resp = recv_json(s)
        except Exception:
            resp = {"type": "<no-reply>"}
        (ROOT/"tests"/"logs"/"replay_attack.log").write_text(json.dumps(resp, indent=2), encoding="utf-8")
    print("[OK] Replay test sent a duplicate packet; check server log for replay warning")
    server.terminate()
    try:
        server.wait(timeout=3)
    except Exception:
        server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
