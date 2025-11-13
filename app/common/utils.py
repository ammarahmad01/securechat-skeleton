"""Small utilities: now_ms, base64 helpers, sha256 hex."""

from __future__ import annotations

import base64
import hashlib
import time


def now_ms() -> int:
	return int(time.time() * 1000)


def b64e(b: bytes) -> str:
	return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
	return base64.b64decode(s.encode("ascii"))


def sha256_hex(data: bytes) -> str:
	return hashlib.sha256(data).hexdigest()

