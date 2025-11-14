# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:

- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure

```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

1. **Fork this repository** to your own GitHub account(using official nu email).  
   All development and commits must be performed in your fork.

2. **Set up environment**:

   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. **Initialize MySQL** (recommended via Docker):

   ```bash
   docker run -d --name securechat-db        -e MYSQL_ROOT_PASSWORD=rootpass        -e MYSQL_DATABASE=securechat        -e MYSQL_USER=scuser        -e MYSQL_PASSWORD=scpass        -p 3306:3306 mysql:8
   ```

4. **Create tables**:

   ```bash
   python -m app.storage.db --init
   ```

5. **Generate certificates** (after implementing the scripts):

   ```bash
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

6. **Run components** (after implementation):
   ```bash
   python -m app.server
   # in another terminal:
   python -m app.client
   ```

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## 🧪 Test Evidence Checklist

✔ Wireshark capture (encrypted payloads only)  
✔ Invalid/self-signed cert rejected (`BAD_CERT`)  
✔ Tamper test → signature verification fails (`SIG_FAIL`)  
✔ Replay test → rejected by seqno (`REPLAY`)  
✔ Non-repudiation → exported transcript + signed SessionReceipt verified offline

## 📜 Transcript Verification

After a chat session ends, the server writes a transcript and a signed receipt under `transcripts/`:

- `transcripts/session_<id>.log`: append-only log of verified messages
- `transcripts/session_<id>_receipt.json`: includes `transcript_sha256` and a signature by the server

Verify the transcript against the receipt offline using the provided tool:

PowerShell (Windows):

```
python tools/verify_transcript.py `
   --transcript transcripts/session_<id>.log `
   --receipt transcripts/session_<id>_receipt.json `
   --cert certs/server-cert.pem
```

Notes:

- Use `certs/client-cert.pem` if verifying a client-signed receipt.
- The tool exits with code `0` on success and `1` on failure.

## 🗄️ MySQL Database Setup

Set up MySQL, then put the credentials into `.env` (copy from `.env.example`). You can use Docker or a local MySQL installation.

Option A — Docker (quickest)

- Start MySQL 8 with a ready database and user:

```powershell
docker run -d --name securechat-db `
   -e MYSQL_ROOT_PASSWORD=rootpass `
   -e MYSQL_DATABASE=secure_chat `
   -e MYSQL_USER=scuser `
   -e MYSQL_PASSWORD=scpass `
   -p 3306:3306 mysql:8
```

- (Optional) Open a MySQL shell inside the container:

```powershell
docker exec -it securechat-db mysql -uroot -prootpass
```

Then you can run (SQL) if needed:

```sql
CREATE DATABASE IF NOT EXISTS secure_chat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'scuser'@'%' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON secure_chat.* TO 'scuser'@'%';
FLUSH PRIVILEGES;
```

Option B — Local MySQL installation

1. Open a MySQL shell as root:

```powershell
mysql -u root -p
```

2. Create the DB and app user (SQL):

```sql
CREATE DATABASE IF NOT EXISTS secure_chat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON secure_chat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
```

Populate `.env` with your DB credentials:

```dotenv
DB_HOST=localhost
DB_USER=scuser
DB_PASS=scpass
DB_NAME=secure_chat
```

Initialize tables from the app after MySQL is running:

```powershell
python -m app.storage.db --init
# or explicitly via Windows venv
& ".\.venv\Scripts\python.exe" -m app.storage.db --init
```

XAMPP (root user with blank password)

If you use XAMPP’s default MySQL with `root` and no password, set `.env` like this:

```dotenv
DB_HOST=localhost
DB_USER=root
DB_PASS=
DB_NAME=secure_chat
```

Then run the quick DB test to verify connectivity and table creation:

```powershell
python scripts/db_test.py
```

## 🔐 PKI & Certificate Generation

The system uses a local Root CA to issue separate server and client leaf certificates. These certificates enable mutual authentication and bind RSA public keys to identities.

Generate the CA (creates `certs/ca.key.pem`, `certs/ca.cert.pem`):

```powershell
python scripts/gen_ca.py --force
```

Generate server and client certificates (signed by the CA):

```powershell
python scripts/gen_cert.py --role server --cn "securechat-server" --force
python scripts/gen_cert.py --role client --cn "securechat-client" --force
```

Outputs (NOT committed):

- `certs/server-key.pem`, `certs/server-cert.pem`
- `certs/client-key.pem`, `certs/client-cert.pem`

Security note: Private keys and issued certificates are excluded via `.gitignore`; never commit them.

## 🚀 Starting Server & Client

Ensure `.env` is populated (see earlier section). Then start:

```powershell
python app/server.py
# In another terminal
python app/client.py
```

## 📡 Protocol Message Examples

Hello (client → server):

```json
{
  "type": "hello",
  "client_cert": "-----BEGIN CERTIFICATE-----...",
  "nonce": "mJ4s2dJQf1w2k9J8yV0hNw=="
}
```

Server Hello (server → client):

```json
{
  "type": "server_hello",
  "server_cert": "-----BEGIN CERTIFICATE-----...",
  "nonce": "qVtO7kP4c6h1H+K2mKj0xA=="
}
```

Ephemeral DH (client → server):

```json
{
  "type": "dh client",
  "g": 2,
  "p": 17976931348623159077083915679378745319786029604875,
  "A": 12345678901234567890
}
```

Ephemeral DH (server → client):

```json
{
  "type": "dh server",
  "B": 98765432109876543210
}
```

Encrypted Login (client → server):

```json
{
  "type": "login_encrypted",
  "iv": "rpY7pJ0Yb0dJrYH2eS2QxA==",
  "ciphertext": "B64ENC..."
}
```

Chat Message (encrypted + signed):

```json
{
  "type": "msg",
  "seqno": 5,
  "ts": 1699999999123,
  "iv": "54FJcVJQ6xq1W9G2MZyVvQ==",
  "ct": "B64ENC...",
  "sig": "B64SIG..."
}
```

Error Message:

```json
{
  "type": "error",
  "err": "BAD CERT"
}
```

Session Receipt:

```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 7,
  "transcript_sha256": "52cdabeb3ffa2907393ca4c2e9d7949fa172ce6f94b7450563595b74194a204f",
  "sig": "MEUCIQD..."
}
```

## 🧪 Automated Tests & PCAP Capture

Run all tests:

```powershell
python tests/run_all_tests.py
```

Manual packet capture example (Linux/macOS loopback):

```bash
tcpdump -i lo -w tests/pcaps/normal_chat.pcapng port 5000
```

Wireshark Display Filters:

```text
tcp.port == 5000
tcp contains "msg"
```

PCAP Descriptions:

- Normal Chat: Shows encrypted payload only; no plaintext message bodies.
- Invalid Cert: Handshake ends with `error` frame containing `BAD CERT`.
- Tampered Message: Modified ciphertext; server logs signature failure; packet differs by a few bytes.
- Replay Attack: Duplicate `seqno` and identical ciphertext; server logs replay warning.
- Non-Repudiation: Transcript and signed receipt produced; hash matches verification tool output.

## 📦 Submission & Packaging

Before submission:

- Run `python scripts/db_test.py` to confirm DB connectivity.
- Export schema & sample data: see `db/dump.sql`.
- Ensure `certs/` and private keys are NOT committed.
- Provide filled-out `submission/Report-A02.docx` and `submission/TestReport-A02.docx` (placeholders generated).

Security Reminder: Never commit private keys, real user passwords, or production database dumps.
