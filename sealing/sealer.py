"""The 'HSM' side of Module 2: holds the private key and signs finished reports.

In a real deployment this runs on a separate device (hardware security module
or an isolated signing host). Here it is simulated by a class whose only public
operation is seal_bytes(); the private key never leaves the keystore folder.

The timestamp is the sealer's own UTC clock. For legal weight, replace it with
an RFC 3161 timestamp from a trusted timestamping authority (see README).
"""
import base64
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SEAL_VERSION = "FTP-SEAL-V1"
DEFAULT_KEYSTORE = Path(__file__).resolve().parent / "hsm_keystore"


def build_message(sha256_hex, sealed_at):
    return f"{SEAL_VERSION}|{sha256_hex}|{sealed_at}".encode()


def fingerprint(public_key):
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


class Sealer:
    def __init__(self, keystore_dir=DEFAULT_KEYSTORE):
        self._dir = Path(keystore_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        priv_path = self._dir / "private.pem"
        self.public_key_path = self._dir / "public.pem"
        if priv_path.exists():
            self._private = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        else:
            self._private = Ed25519PrivateKey.generate()
            priv_path.write_bytes(
                self._private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            try:
                os.chmod(priv_path, 0o600)
            except OSError:
                pass
        self.public_key_path.write_bytes(
            self._private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    def seal_bytes(self, report_bytes):
        digest = hashlib.sha256(report_bytes).hexdigest()
        sealed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        signature = self._private.sign(build_message(digest, sealed_at))
        return {
            "version": SEAL_VERSION,
            "sha256": digest,
            "sealed_at": sealed_at,
            "signature": base64.b64encode(signature).decode(),
            "key_fingerprint": fingerprint(self._private.public_key()),
        }


def seal_file(report_path, sealer=None):
    import json

    sealer = sealer or Sealer()
    report_path = Path(report_path)
    seal = sealer.seal_bytes(report_path.read_bytes())
    seal["report_file"] = report_path.name
    out = report_path.with_name(report_path.name + ".seal.json")
    out.write_text(json.dumps(seal, indent=2))
    return out, seal


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m sealing.sealer <report-file>")
        sys.exit(1)
    path, seal = seal_file(sys.argv[1])
    print(f"Sealed {sys.argv[1]} -> {path}")
    print(f"  sha256   : {seal['sha256']}")
    print(f"  sealed_at: {seal['sealed_at']}")
