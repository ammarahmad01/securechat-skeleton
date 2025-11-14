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
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

from crypto import dh as dhmod
from crypto import aes as aesmod
from storage import db as dbmod

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

        # ---- Ephemeral DH key exchange ----
        msg = recv_json(conn)
        mtype = msg.get("type")
        if mtype not in ("dh client", "dh_client"):
            send_json(conn, {"type": "error", "err": "EXPECTED DH"})
            return
        try:
            g = int(msg["g"])
            p = int(msg["p"])
            A = int(msg["A"])
        except Exception:
            send_json(conn, {"type": "error", "err": "BAD DH"})
            return

        b = dhmod.gen_private(p)
        B = dhmod.compute_pub(g, b, p)
        Ks = dhmod.compute_shared(A, b, p)
        K = dhmod.derive_key(Ks)

        send_json(conn, {"type": "dh server", "B": B})

        # ---- Encrypted control-plane commands ----
        cmd = recv_json(conn)
        ctype = cmd.get("type")
        if ctype not in ("register_encrypted", "login_encrypted"):
            send_json(conn, {"type": "error", "err": "EXPECTED ENCRYPTED"})
            return

        try:
            iv = base64.b64decode(cmd["iv"])  # 16 bytes
            ct = base64.b64decode(cmd["ciphertext"]) 
        except Exception:
            send_json(conn, {"type": "error", "err": "BAD CIPHERTEXT"})
            return

        try:
            plain = aesmod.decrypt_aes_cbc(K, iv, ct)
            payload = json.loads(plain.decode("utf-8"))
        except Exception as e:
            send_json(conn, {"type": "error", "err": "DECRYPT FAIL"})
            print(f"[!] Decrypt/parse error: {e}")
            return

        if ctype == "register_encrypted":
            email = payload.get("email")
            username = payload.get("username")
            password = payload.get("password")
            ok = False
            try:
                dbmod.init_db()
                ok = dbmod.create_user(email, username, password)
            except Exception as e:
                print(f"[!] DB error on register: {e}")
            send_json(conn, {"type": "register_ack", "status": "ok" if ok else "fail"})
            if ok:
                print(f"[+] Registered new user: {username}")
        else:  # login_encrypted
            email = payload.get("email")
            username = payload.get("username")
            password = payload.get("password")
            ok = False
            try:
                if email:
                    ok = dbmod.verify_user_by_email(email, password)
                elif username:
                    ok = dbmod.verify_user(username, password)
            except Exception as e:
                print(f"[!] DB error on login: {e}")
            send_json(conn, {"type": "login_ack", "status": "ok" if ok else "fail"})
            if ok:
                ident = email or username or "<unknown>"
                print(f"[INFO] User {ident} authenticated successfully")

                # ---- New session DH exchange (data-plane key) ----
                print("[INFO] Session DH exchange started")
                sess_req = recv_json(conn)
                if sess_req.get("type") != "session_dh_client":
                    print("[!] Expected session_dh_client; closing")
                    return
                try:
                    p = int(sess_req["p"])  # type: ignore
                    g = int(sess_req["g"])  # type: ignore
                    A = int(sess_req["A"])  # type: ignore
                except Exception:
                    send_json(conn, {"type": "error", "err": "BAD SESSION DH"})
                    return

                b = dhmod.gen_private(p)
                B = dhmod.compute_pub(g, b, p)
                Ks = dhmod.compute_shared(A, b, p)
                K = dhmod.derive_key(Ks)

                # Reply with server part
                send_json(conn, {"type": "session_dh_server", "B": B})

                # Session metadata (in-memory only)
                session = {
                    "session_id": uuid.uuid4().hex,
                    "peer_fingerprint": client_cert.fingerprint(hashes.SHA256()).hex(),
                    "seqno": 0,
                    "rx_last_seq": 0,
                    "key": K,
                    "peer_cert": client_cert,
                }
                print(
                    f"[INFO] Session DH completed — session key derived and stored; "
                    f"session_id={session['session_id']}, seqno={session['seqno']}"
                )

                # ---- Encrypted chat message loop (verify -> decrypt -> transcript -> ack) ----
                from cryptography.hazmat.primitives import serialization
                from crypto import sign as signmod
                from common.utils import now_ms, b64e, b64d
                from storage.transcript import append_line, compute_transcript_sha256

                root_dir = Path(__file__).resolve().parent.parent
                server_key_path = root_dir / "certs" / "server-key.pem"
                with open(server_key_path, "rb") as f:
                    server_priv = serialization.load_pem_private_key(f.read(), password=None)

                first_seq_logged = None
                last_seq_logged = None
                while True:
                    try:
                        chat = recv_json(conn)
                    except Exception:
                        break
                    if chat.get("type") != "msg":
                        if chat.get("type") in {"bye", "quit"}:
                            break
                        continue
                    try:
                        seqno = int(chat["seqno"])  # type: ignore
                        ts = int(chat["ts"])  # type: ignore
                        iv = b64d(chat["iv"])  # type: ignore
                        ct = b64d(chat["ct"])  # type: ignore
                        sig = b64d(chat["sig"])  # type: ignore
                    except Exception:
                        print("[WARNING] Malformed message; dropped")
                        continue

                    if seqno <= session["rx_last_seq"]:
                        print("[WARNING] Replay or out-of-order message detected — dropped")
                        continue

                    hmsg = signmod.compute_message_hash(seqno, ts, ct)
                    try:
                        session["peer_cert"].public_key().verify(
                            sig, hmsg, asym_padding.PKCS1v15(), hashes.SHA256()
                        )
                    except Exception:
                        print("[ERROR] Signature verification failed")
                        continue

                    try:
                        plain = aesmod.decrypt_aes_cbc(session["key"], iv, ct)
                        text = plain.decode("utf-8", errors="replace")
                    except Exception as e:
                        print(f"[ERROR] Decryption failed: {e}")
                        continue

                    session["rx_last_seq"] = seqno
                    print(f"[INFO] Received message #{seqno} from peer — verified and decrypted")

                    append_line(session["session_id"], seqno, ts, b64e(ct), b64e(sig), session["peer_fingerprint"], root=root_dir)
                    if first_seq_logged is None:
                        first_seq_logged = seqno
                    last_seq_logged = seqno

                    # Send encrypted+signed ACK echo
                    session["seqno"] += 1
                    sseq = session["seqno"]
                    sts = now_ms()
                    ack_text = f"ack: {text}"
                    iv2, ct2 = aesmod.encrypt_aes_cbc(session["key"], ack_text.encode("utf-8"))
                    h2 = signmod.compute_message_hash(sseq, sts, ct2)
                    sig2 = signmod.sign_hash(server_priv, h2)
                    send_json(conn, {"type": "msg", "seqno": sseq, "ts": sts, "iv": b64e(iv2), "ct": b64e(ct2), "sig": b64e(sig2)})

                # ---- On session end: generate and sign receipt ----
                try:
                    tfile = (root_dir / "transcripts" / f"session_{session['session_id']}.log")
                    if tfile.exists() and first_seq_logged is not None and last_seq_logged is not None:
                        th = compute_transcript_sha256(tfile)
                        receipt = {
                            "type": "receipt",
                            "peer": "client",
                            "first_seq": int(first_seq_logged),
                            "last_seq": int(last_seq_logged),
                            "transcript_sha256": th,
                        }
                        # Sign hash (hex -> bytes)
                        raw = bytes.fromhex(th)
                        sig_r = signmod.sign_hash(server_priv, raw)
                        from common.utils import b64e as _b64e
                        receipt["sig"] = _b64e(sig_r)

                        rpath = root_dir / "transcripts" / f"session_{session['session_id']}_receipt.json"
                        rpath.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
                        print("[INFO] Session receipt generated and signed.")
                except Exception as e:
                    print(f"[WARNING] Failed to generate receipt: {e}")
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

    # Ensure DB schema exists on startup (no-op if already created)
    try:
        from storage import db as _dbmod
        _dbmod.init_db()
        print("[INFO] Database schema ensured (users table).")
    except Exception as e:
        print(f"[WARNING] Could not initialize database schema: {e}")

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
