"""Verification side of Module 2. Needs only the PUBLIC key.

Usage:
    python -m sealing.verify <report-file> [<seal.json>] [--pubkey public.pem]
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from sealing.sealer import DEFAULT_KEYSTORE, build_message


def load_public_key(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def verify_seal(report_bytes, seal, public_key):
    """Return (ok, reason)."""
    try:
        digest = hashlib.sha256(report_bytes).hexdigest()
        if digest != seal["sha256"]:
            return False, "report does not match the sealed SHA-256"
        signature = base64.b64decode(seal["signature"])
        public_key.verify(signature, build_message(seal["sha256"], seal["sealed_at"]))
    except InvalidSignature:
        return False, "signature invalid (not issued by the trusted sealer)"
    except (KeyError, ValueError, TypeError):
        return False, "malformed seal"
    return True, "report matches sealed digest and signature is valid"


def naive_hash_check(report_bytes, stored_hash_hex):
    """The traditional check: compare against a hash stored next to the report."""
    return hashlib.sha256(report_bytes).hexdigest() == stored_hash_hex.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("seal", nargs="?")
    ap.add_argument("--pubkey", default=str(DEFAULT_KEYSTORE / "public.pem"))
    args = ap.parse_args()
    seal_path = Path(args.seal) if args.seal else Path(args.report + ".seal.json")
    seal = json.loads(seal_path.read_text())
    ok, reason = verify_seal(Path(args.report).read_bytes(), seal, load_public_key(args.pubkey))
    print(("VALID: " if ok else "INVALID: ") + reason)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
