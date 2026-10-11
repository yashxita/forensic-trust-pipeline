"""Module 2 demo: why a hash computed on the workstation proves nothing,
and why an out-of-band signature does (report Sections 5.3 and 10.3).

Scenario: malicious code is running on the forensic workstation and edits a
finished report. We compare two integrity checks:
  1. Plain SHA-256 stored next to the report (what the workstation can rewrite)
  2. A signature issued by a separate sealer holding a key the workstation never sees
"""
import copy
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

import ui
from sealing.sealer import Sealer, build_message, fingerprint
from sealing.verify import load_public_key, naive_hash_check, verify_seal

WORKDIR = Path(__file__).resolve().parent.parent / "results" / "demo_sealing"

REPORT = """EXTRACTION REPORT
Case: CASE-2026-014
Examiner: A. Examiner (demo)
Device: sample phone (fictional data)
Messages recovered: 300

Message 0042 | 2026-03-02T09:14 | +91-90000-01037 -> +91-90000-00000 | "Meet at the station at 6"
Message 0043 | 2026-03-02T09:31 | +91-90000-00000 -> +91-90000-01037 | "Ok, see you there"
"""
EDITED = REPORT.replace('"Meet at the station at 6"', '"Nothing planned for tonight"')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ui.banner("MODULE 2: OUT-OF-BAND SEALING (report Sections 5.3, 10.3)")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    sealer = Sealer()  # the separate 'HSM'
    pub = load_public_key(sealer.public_key_path)
    ui.info(f"Trusted sealer public key fingerprint: {fingerprint(pub)}")

    original = REPORT.encode()
    edited = EDITED.encode()
    (WORKDIR / "report.txt").write_bytes(original)
    stored_hash = sha(original)
    (WORKDIR / "report.txt.sha256").write_text(stored_hash)
    seal = sealer.seal_bytes(original)
    ui.info(f"Report sealed. sha256 = {seal['sha256'][:32]}...  at {seal['sealed_at']}")

    rows = []

    # A: nothing touched
    n = naive_hash_check(original, stored_hash)
    s, _ = verify_seal(original, seal, pub)
    rows.append(("A. Report untouched", n, s, True, True))

    # B: attacker edits report and recomputes the plain hash on the workstation
    forged_hash = sha(edited)
    n = naive_hash_check(edited, forged_hash)
    s, why_b = verify_seal(edited, seal, pub)
    rows.append(("B. Edit + recompute plain hash", n, s, True, False))

    # C: attacker also rewrites the digest inside the seal file
    seal_c = copy.deepcopy(seal)
    seal_c["sha256"] = sha(edited)
    n = naive_hash_check(edited, sha(edited))
    s, why_c = verify_seal(edited, seal_c, pub)
    rows.append(("C. Edit + rewrite seal digest", n, s, True, False))

    # D: attacker signs with their own key
    attacker = Ed25519PrivateKey.generate()
    seal_d = copy.deepcopy(seal)
    seal_d["sha256"] = sha(edited)
    seal_d["signature"] = base64.b64encode(
        attacker.sign(build_message(seal_d["sha256"], seal_d["sealed_at"]))
    ).decode()
    seal_d["key_fingerprint"] = fingerprint(attacker.public_key())
    n = naive_hash_check(edited, sha(edited))
    s, why_d = verify_seal(edited, seal_d, pub)
    rows.append(("D. Edit + re-sign with own key", n, s, True, False))

    ui.section("Results (PASS means the check accepted the report)")
    ui.table(
        ["Scenario", "Plain hash check", "Sealed check"],
        [[name, "PASS" if n else "FAIL", "PASS" if s else "FAIL"] for name, n, s, _, _ in rows],
    )
    ui.info(f"B reason: {why_b}")
    ui.info(f"C reason: {why_c}")
    ui.info(f"D reason: {why_d}")

    expected_ok = all(n == en and s == es for _, n, s, en, es in rows)
    ui.section("Conclusion")
    if expected_ok:
        ui.ok("The plain hash accepted every tampered report (B, C, D).")
        ui.ok("The sealed check rejected all of them, without needing to trust the workstation.")
        return 0
    ui.fail("Demo did not behave as expected.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
