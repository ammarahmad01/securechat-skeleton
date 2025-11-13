"""
Issue a server/client certificate signed by the Root CA created by gen_ca.py.

Usage examples:
  python scripts/gen_cert.py --role server --hostnames localhost --ips 127.0.0.1
  python scripts/gen_cert.py --role client --cn "securechat-client"

Outputs (under certs/):
  - server: server-key.pem, server-cert.pem
  - client: client-key.pem, client-cert.pem
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, DNSName, IPAddress, ExtendedKeyUsageOID


def _chmod_600(path: Path) -> None:
	try:
		os.chmod(path, 0o600)
	except Exception:
		pass


def build_parser() -> argparse.ArgumentParser:
	p = argparse.ArgumentParser(description="Issue a server/client certificate signed by the local CA")
	p.add_argument("--role", choices=["server", "client"], required=True, help="Certificate role")
	p.add_argument("--cn", default=None, help="Common Name for the certificate (default based on role)")
	p.add_argument("--country", "-C", default="US", help="Subject Country Name (C)")
	p.add_argument("--org", "-O", default="SecureChat", help="Subject Organization (O)")
	p.add_argument("--hostnames", default="localhost", help="Comma-separated DNS names for SAN (server role)")
	p.add_argument("--ips", default="127.0.0.1", help="Comma-separated IPs for SAN (server role)")
	p.add_argument("--days", type=int, default=365, help="Validity in days for leaf certificate")
	p.add_argument("--key-size", type=int, default=2048, choices=(2048, 3072, 4096), help="RSA key size")
	p.add_argument("--ca-key", default="certs/ca.key.pem", help="Path to CA private key")
	p.add_argument("--ca-cert", default="certs/ca.cert.pem", help="Path to CA certificate")
	p.add_argument("--out-dir", default="certs", help="Output directory for issued key/cert")
	p.add_argument("--force", action="store_true", help="Overwrite existing files if present")
	return p


def _load_ca(ca_key_path: Path, ca_crt_path: Path):
	from cryptography.hazmat.primitives.serialization import load_pem_private_key

	with open(ca_key_path, "rb") as f:
		ca_key = load_pem_private_key(f.read(), password=None)
	with open(ca_crt_path, "rb") as f:
		ca_cert = x509.load_pem_x509_certificate(f.read())
	return ca_key, ca_cert


def main(argv: list[str] | None = None) -> int:
	args = build_parser().parse_args(argv)

	out_dir = Path(args.out_dir)
	out_dir.mkdir(parents=True, exist_ok=True)

	ca_key_path = Path(args.ca_key)
	ca_crt_path = Path(args.ca_cert)
	if not ca_key_path.exists() or not ca_crt_path.exists():
		print(f"[!] CA files not found: {ca_key_path} or {ca_crt_path}. Run scripts/gen_ca.py first.")
		return 2

	role = args.role
	default_cn = "SecureChat Server" if role == "server" else "SecureChat Client"
	cn = args.cn or default_cn

	# Output filenames by role
	key_path = out_dir / ("server-key.pem" if role == "server" else "client-key.pem")
	crt_path = out_dir / ("server-cert.pem" if role == "server" else "client-cert.pem")
	if not args.force and (key_path.exists() or crt_path.exists()):
		print(f"[!] Refusing to overwrite existing files without --force: {key_path}, {crt_path}")
		return 2

	print(f"[*] Loading CA from {ca_key_path} and {ca_crt_path} ...")
	ca_key, ca_cert = _load_ca(ca_key_path, ca_crt_path)

	print(f"[*] Generating RSA-{args.key_size} key for {role} ...")
	leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)

	subject = x509.Name(
		[
			x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.org),
			x509.NameAttribute(NameOID.COMMON_NAME, cn),
		]
	)

	now = dt.datetime.utcnow()
	not_before = now - dt.timedelta(days=1)
	not_after = now + dt.timedelta(days=args.days)

	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(ca_cert.subject)
		.public_key(leaf_key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(not_before)
		.not_valid_after(not_after)
		.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
		.add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
		.add_extension(
			x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
		)
	)

	if role == "server":
		# Server KeyUsage + EKU
		builder = builder.add_extension(
			x509.KeyUsage(
				digital_signature=True,
				content_commitment=False,
				key_encipherment=True,
				data_encipherment=False,
				key_agreement=False,
				key_cert_sign=False,
				crl_sign=False,
				encipher_only=False,
				decipher_only=False,
			),
			critical=True,
		).add_extension(
			x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
		)

		# SANs: DNS + IPs
		dns_names = [h.strip() for h in (args.hostnames or "").split(",") if h.strip()]
		ips = [ip.strip() for ip in (args.ips or "").split(",") if ip.strip()]
		san_entries = [DNSName(h) for h in dns_names]
		for ip in ips:
			try:
				san_entries.append(IPAddress(ipaddress.ip_address(ip)))
			except ValueError:
				print(f"[!] Skipping invalid IP in --ips: {ip}")
		if san_entries:
			builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
	else:
		# Client KeyUsage + EKU
		builder = builder.add_extension(
			x509.KeyUsage(
				digital_signature=True,
				content_commitment=False,
				key_encipherment=False,
				data_encipherment=False,
				key_agreement=False,
				key_cert_sign=False,
				crl_sign=False,
				encipher_only=False,
				decipher_only=False,
			),
			critical=True,
		).add_extension(
			x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
		)

	print("[*] Signing certificate with CA (SHA-256) ...")
	certificate = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

	print(f"[*] Writing key  -> {key_path}")
	with open(key_path, "wb") as f:
		f.write(
			leaf_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)
	_chmod_600(key_path)

	print(f"[*] Writing cert -> {crt_path}")
	with open(crt_path, "wb") as f:
		f.write(certificate.public_bytes(serialization.Encoding.PEM))

	print(f"[+] {role.capitalize()} certificate generated successfully!")

	# Short inspection
	print("\n--- Leaf Certificate Info ---")
	print(f"Subject: {certificate.subject.rfc4514_string()}")
	print(f"Issuer : {certificate.issuer.rfc4514_string()}")
	print(f"Serial : {hex(certificate.serial_number)}")
	try:
		print(f"Valid  : {certificate.not_valid_before_utc} -> {certificate.not_valid_after_utc}")
	except AttributeError:
		print(f"Valid  : {certificate.not_valid_before} -> {certificate.not_valid_after}")
	print("-----------------------------")

	return 0


if __name__ == "__main__":
	sys.exit(main())

