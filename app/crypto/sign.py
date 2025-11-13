"""RSA PKCS#1 v1.5 SHA-256 sign/verify + message hash helpers."""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def compute_message_hash(seqno: int, ts_ms: int, ciphertext: bytes) -> bytes:
	seq_b = seqno.to_bytes(8, "big", signed=False)
	ts_b = ts_ms.to_bytes(8, "big", signed=False)
	return hashlib.sha256(seq_b + ts_b + ciphertext).digest()


def load_private_key_pem(path: str, password: bytes | None = None):
	with open(path, "rb") as f:
		data = f.read()
	return serialization.load_pem_private_key(data, password=password)


def sign_hash(privkey, h: bytes) -> bytes:
	return privkey.sign(h, padding.PKCS1v15(), hashes.SHA256())


def verify_signature(pubkey, sig: bytes, h: bytes) -> None:
	pubkey.verify(sig, h, padding.PKCS1v15(), hashes.SHA256())


__all__ = [
	"compute_message_hash",
	"load_private_key_pem",
	"sign_hash",
	"verify_signature",
]

