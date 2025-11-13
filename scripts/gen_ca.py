"""
Create a self-signed Root CA using RSA and X.509 (cryptography).

Outputs:
- certs/ca.key.pem   (PEM-encoded RSA private key)
- certs/ca.cert.pem  (PEM-encoded self-signed certificate)

Defaults:
- Key size: 3072 (can be changed via --key-size)
- Subject: C, O provided via args; CN fixed to "SecureChat Root CA"
- Validity: 5 years
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID


def _chmod_600(path: Path) -> None:
	try:
		os.chmod(path, 0o600)
	except Exception:
		# On some systems (e.g., Windows), chmod may not behave as expected.
		pass


def build_parser() -> argparse.ArgumentParser:
	p = argparse.ArgumentParser(description="Generate a self-signed Root CA for SecureChat")
	p.add_argument("--country", "-C", default="US", help="Country Name (C)")
	p.add_argument("--org", "-O", default="SecureChat", help="Organization (O)")
	p.add_argument("--key-size", type=int, default=3072, choices=(2048, 3072, 4096), help="RSA key size")
	p.add_argument("--out-dir", default="certs", help="Output directory for CA key/cert")
	p.add_argument("--force", action="store_true", help="Overwrite existing files if present")
	return p


def main(argv: list[str] | None = None) -> int:
	args = build_parser().parse_args(argv)

	out_dir = Path(args.out_dir)
	out_dir.mkdir(parents=True, exist_ok=True)

	key_path = out_dir / "ca.key.pem"
	crt_path = out_dir / "ca.cert.pem"

	if not args.force and (key_path.exists() or crt_path.exists()):
		print(f"[!] Refusing to overwrite existing files without --force: {key_path}, {crt_path}")
		return 2

	print(f"[*] Generating RSA-{args.key_size} private key for Root CA ...")
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)

	subject = issuer = x509.Name(
		[
			x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.org),
			x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
		]
	)

	now = dt.datetime.utcnow()
	not_before = now - dt.timedelta(days=1)
	not_after = now + dt.timedelta(days=5 * 365)

	print("[*] Building self-signed X.509 certificate ...")
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(private_key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(not_before)
		.not_valid_after(not_after)
		.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
		.add_extension(
			x509.KeyUsage(
				digital_signature=False,
				content_commitment=False,
				key_encipherment=False,
				data_encipherment=False,
				key_agreement=False,
				key_cert_sign=True,
				crl_sign=True,
				encipher_only=False,
				decipher_only=False,
			),
			critical=True,
		)
		.add_extension(
			x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
		)
		.add_extension(
			x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
			critical=False,
		)
	)

	certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

	print(f"[*] Writing key  -> {key_path}")
	with open(key_path, "wb") as f:
		f.write(
			private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)
	_chmod_600(key_path)

	print(f"[*] Writing cert -> {crt_path}")
	with open(crt_path, "wb") as f:
		f.write(certificate.public_bytes(serialization.Encoding.PEM))

	print("[+] Root CA generated successfully!")

	# Short inspection
	print("\n--- CA Certificate Info ---")
	print(f"Subject: {certificate.subject.rfc4514_string()}")
	print(f"Issuer : {certificate.issuer.rfc4514_string()}")
	print(f"Serial : {hex(certificate.serial_number)}")
	try:
		print(f"Valid  : {certificate.not_valid_before_utc} -> {certificate.not_valid_after_utc}")
	except AttributeError:
		# cryptography<41 compatibility
		print(f"Valid  : {certificate.not_valid_before} -> {certificate.not_valid_after}")
	print("---------------------------")

	return 0


if __name__ == "__main__":
	sys.exit(main())

