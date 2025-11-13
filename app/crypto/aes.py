"""AES-128-CBC + PKCS#7 helpers using cryptography."""

from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
	padder = padding.PKCS7(block_size * 8).padder()
	return padder.update(data) + padder.finalize()


def unpad_pkcs7(padded: bytes, block_size: int = 16) -> bytes:
	unpadder = padding.PKCS7(block_size * 8).unpadder()
	return unpadder.update(padded) + unpadder.finalize()


def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
	enc = cipher.encryptor()
	ct = enc.update(pad_pkcs7(plaintext, 16)) + enc.finalize()
	return iv, ct


def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
	dec = cipher.decryptor()
	padded = dec.update(ciphertext) + dec.finalize()
	return unpad_pkcs7(padded, 16)


__all__ = [
	"pad_pkcs7",
	"unpad_pkcs7",
	"encrypt_aes_cbc",
	"decrypt_aes_cbc",
]

