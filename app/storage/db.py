"""
MySQL helper layer for user registration and login.

Environment variables (loaded via python-dotenv when available):
- DB_HOST, DB_USER, DB_PASS, DB_NAME

Security notes:
- Passwords are never logged or returned.
- Stores a per-user 16-byte random salt (VARBINARY(16)).
- Stores a SHA-256 hash as hex (CHAR(64)) of: SHA256(salt || UTF8(password)).
"""

from __future__ import annotations

import os
import hmac
import hashlib
import secrets
from contextlib import contextmanager
from typing import Optional, Tuple, Dict, Any

try:
	from dotenv import load_dotenv

	load_dotenv()  # best-effort – ok if .env is missing
except Exception:
	pass

import pymysql


def _get_db_config() -> Dict[str, Any]:
	host = os.getenv("DB_HOST", "localhost")
	user = os.getenv("DB_USER")
	password = os.getenv("DB_PASS")
	database = os.getenv("DB_NAME")
	port_s = os.getenv("DB_PORT")
	port = int(port_s) if port_s and port_s.isdigit() else 3306

	missing = [k for k, v in {"DB_USER": user, "DB_PASS": password, "DB_NAME": database}.items() if not v]
	if missing:
		raise RuntimeError(f"Missing required DB env vars: {', '.join(missing)}")

	return dict(host=host, user=user, password=password, database=database, port=port, charset="utf8mb4")


@contextmanager
def get_conn():
	cfg = _get_db_config()
	conn = pymysql.connect(**cfg, autocommit=True)
	try:
		yield conn
	finally:
		try:
			conn.close()
		except Exception:
			pass


def init_db() -> None:
	"""Ensure the `users` table exists using the required schema."""
	ddl = (
		"CREATE TABLE IF NOT EXISTS users ("
		"  email VARCHAR(255) PRIMARY KEY,"
		"  username VARCHAR(255) UNIQUE,"
		"  salt VARBINARY(16),"
		"  pwd_hash CHAR(64)"
		")"
	)
	with get_conn() as conn:
		with conn.cursor() as cur:
			cur.execute(ddl)


def _hash_password(salt: bytes, password: str) -> str:
	if not isinstance(salt, (bytes, bytearray)):
		raise TypeError("salt must be bytes")
	if password is None:
		raise ValueError("password must not be None")
	h = hashlib.sha256()
	h.update(salt)
	h.update(password.encode("utf-8"))
	return h.hexdigest()


def create_user(email: str, username: str, password: str) -> bool:
	"""Create a new user row with a random 16-byte salt and SHA-256 hash.

	Returns True on success, False if username or email already exists.
	"""
	if not email or not username or not password:
		raise ValueError("email, username, and password are required")

	salt = secrets.token_bytes(16)
	pwd_hash = _hash_password(salt, password)

	sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
	try:
		with get_conn() as conn:
			with conn.cursor() as cur:
				cur.execute(sql, (email, username, salt, pwd_hash))
		return True
	except pymysql.err.IntegrityError:
		# email primary key or username unique violation
		return False


def verify_user(username: str, password: str) -> bool:
	"""Verify a username/password combo.

	Returns True if credentials are valid; False otherwise.
	"""
	if not username or not password:
		return False

	row = _get_auth_row_by_username(username)
	if not row:
		return False

	salt, stored_hex = row
	calc_hex = _hash_password(salt, password)
	return hmac.compare_digest(calc_hex, stored_hex)


def _get_auth_row_by_username(username: str) -> Optional[Tuple[bytes, str]]:
	sql = "SELECT salt, pwd_hash FROM users WHERE username=%s"
	with get_conn() as conn:
		with conn.cursor() as cur:
			cur.execute(sql, (username,))
			res = cur.fetchone()
			if not res:
				return None
			# fetchone returns a tuple; ensure expected types
			salt, pwd_hash = res[0], res[1]
			return salt, pwd_hash


def get_public_user(username: str) -> Optional[Dict[str, str]]:
	"""Return non-sensitive fields for a user, or None if not found."""
	sql = "SELECT email, username FROM users WHERE username=%s"
	with get_conn() as conn:
		with conn.cursor() as cur:
			cur.execute(sql, (username,))
			row = cur.fetchone()
			if not row:
				return None
			email, uname = row[0], row[1]
			return {"email": email, "username": uname}


__all__ = [
	"init_db",
	"create_user",
	"verify_user",
	"verify_user_by_email",
	"get_public_user",
]

def _get_auth_row_by_email(email: str) -> Optional[Tuple[bytes, str]]:
	sql = "SELECT salt, pwd_hash FROM users WHERE email=%s"
	with get_conn() as conn:
		with conn.cursor() as cur:
			cur.execute(sql, (email,))
			res = cur.fetchone()
			if not res:
				return None
			return res[0], res[1]


def verify_user_by_email(email: str, password: str) -> bool:
	if not email or not password:
		return False
	row = _get_auth_row_by_email(email)
	if not row:
		return False
	salt, stored_hex = row
	calc_hex = _hash_password(salt, password)
	return hmac.compare_digest(calc_hex, stored_hex)

