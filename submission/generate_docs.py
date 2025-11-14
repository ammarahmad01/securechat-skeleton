"""Generate placeholder .docx report templates for Assignment 2.

Usage:
  python submission/generate_docs.py --roll 1234 --name "Alice Example"

Creates:
  submission/RollNumber-FullName-Report-A02.docx
  submission/RollNumber-FullName-TestReport-A02.docx
"""
from __future__ import annotations

import argparse
from pathlib import Path

try:
    from docx import Document  # python-docx
except ImportError:
    raise SystemExit("python-docx not installed. Run: pip install python-docx")

SECTIONS_REPORT = [
    "1. Introduction",
    "2. System Architecture",
    "3. Certificate Hierarchy (PKI)",
    "4. Diffie-Hellman Key Establishment",
    "5. Encryption & Integrity (AES + RSA)",
    "6. Replay Protection Mechanism",
    "7. Non-Repudiation (Transcript & Receipt)",
    "8. Security Analysis & Threats",
    "9. Testing Methodology",
    "10. Wireshark / PCAP Evidence",
    "11. Conclusion",
]

SECTIONS_TEST = [
    "1. Test Matrix Overview",
    "2. Normal Chat (Encryption Evidence)",
    "3. Invalid Certificate Rejection",
    "4. Tampered Message Signature Failure",
    "5. Replay Attack Detection",
    "6. Non-Repudiation Verification",
    "7. Additional Edge Cases",
]


def build_doc(title: str, sections: list[str]) -> Document:
    doc = Document()
    doc.add_heading(title, level=0)
    doc.add_paragraph("Generated placeholder. Fill in details, screenshots, and analysis.")
    for s in sections:
        doc.add_heading(s, level=1)
        doc.add_paragraph("TODO: Write content.")
    return doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roll", required=True, help="Roll number")
    ap.add_argument("--name", required=True, help="Full name")
    args = ap.parse_args()

    subdir = Path(__file__).resolve().parent

    report_name = f"{args.roll}-{args.name.replace(' ', '-')}-Report-A02.docx"
    test_name = f"{args.roll}-{args.name.replace(' ', '-')}-TestReport-A02.docx"

    report_doc = build_doc("Secure Chat Assignment 2 – Final Report", SECTIONS_REPORT)
    test_doc = build_doc("Secure Chat Assignment 2 – Test Report", SECTIONS_TEST)

    report_doc.save(str(subdir / report_name))
    test_doc.save(str(subdir / test_name))

    print("[OK] Generated:")
    print(" -", report_name)
    print(" -", test_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
