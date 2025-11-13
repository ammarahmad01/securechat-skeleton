"""Append-only transcript log for verified, decrypted messages."""

from __future__ import annotations

from pathlib import Path


def _ensure_dir(p: Path) -> None:
	p.mkdir(parents=True, exist_ok=True)


def append_line(session_id: str, seqno: int, ts_ms: int, ct_b64: str, sig_b64: str, peer_fp: str, root: Path | None = None) -> Path:
	"""Append a transcript line.

	Format: seqno|timestamp|base64(ciphertext)|base64(signature)|peer-fingerprint
	Returns the transcript file path.
	"""
	root = root or Path.cwd()
	tdir = root / "transcripts"
	_ensure_dir(tdir)
	tfile = tdir / f"session_{session_id}.log"
	line = f"{seqno}|{ts_ms}|{ct_b64}|{sig_b64}|{peer_fp}\n"
	with open(tfile, "a", encoding="utf-8") as f:
		f.write(line)
	return tfile


__all__ = ["append_line"]

