"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation).

Provides a safe 2048-bit MODP Group (RFC 3526 group 14) with g=2.
"""

from __future__ import annotations

import hashlib
import secrets


# RFC 3526 Group 14 (2048-bit MODP)
_P_HEX = (
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
	"FFFFFFFFFFFFFFFF"
)

P = int(_P_HEX, 16)
G = 2


def get_group() -> tuple[int, int]:
	return P, G


def gen_private(p: int) -> int:
	n_bits = p.bit_length()
	while True:
		x = secrets.randbits(n_bits)
		x %= p - 2
		x += 2
		if 2 <= x <= p - 2:
			return x


def compute_pub(g: int, a: int, p: int) -> int:
	return pow(g, a, p)


def compute_shared(peer_pub: int, priv: int, p: int) -> int:
	return pow(peer_pub, priv, p)


def derive_key(shared: int) -> bytes:
	ks_bytes = shared.to_bytes((shared.bit_length() + 7) // 8 or 1, "big")
	return hashlib.sha256(ks_bytes).digest()[:16]


__all__ = [
	"get_group",
	"gen_private",
	"compute_pub",
	"compute_shared",
	"derive_key",
]

