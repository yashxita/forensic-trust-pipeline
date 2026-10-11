"""Module 3 demo: tamper-evident workstation state ledger (report Section 9.2).

Phases:
  1. Four extractions are logged; the extraction tool changes between #2 and #3
     and the ledger flags the drift automatically.
  2. An attacker hides the drift by editing entry #3 -> chain verification fails.
  3. The attacker fixes entry #3's own hash -> the link from entry #4 breaks.
  4. The attacker recomputes the whole chain -> the chain is internally valid,
     but the head hash no longer matches the one sealed by the external sealer
     (Module 2). This is why the head must be anchored out of band.
"""
import copy
import sys
from pathlib import Path

import ui
from ledger.state_logger import append_entry, default_tracked, entry_digest, rechain, read_ledger
from ledger.verify_chain import verify_entries, verify_ledger
from sealing.sealer import Sealer
from sealing.verify import load_public_key, verify_seal

WORKDIR = Path(__file__).resolve().parent.parent / "results" / "demo_ledger"


def show(problems):
    if not problems:
        ui.ok("Ledger verification: INTACT")
    for idx, msg in problems:
        ui.fail(f"Ledger verification: entry {idx}: {msg}")


def main():
    ui.banner("MODULE 3: WORKSTATION STATE LEDGER (report Section 9.2)")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    ledger = WORKDIR / "ledger.jsonl"
    if ledger.exists():
        ledger.unlink()
    tool = WORKDIR / "extraction_tool.bin"
    tool.write_bytes(b"extraction tool build 1.0 (trusted)")
    tracked = default_tracked()
    tracked["extraction_tool.bin"] = tool

    ui.section("Phase 1: log four extractions; the tool changes after the second")
    for n in range(1, 5):
        if n == 3:
            tool.write_bytes(b"extraction tool build 1.0 (MODIFIED by malicious code)")
        e = append_entry(ledger, f"CASE-00{n}", tracked_files=tracked)
        ui.info(f"entry {e['index']}  CASE-00{n}  hash {e['entry_hash'][:16]}...  drift: {e['drift'] or 'none'}")
    entries = read_ledger(ledger)
    problems = verify_entries(entries)
    show(problems)
    phase1_ok = not problems and entries[2]["drift"] == ["file changed: extraction_tool.bin"]
    if phase1_ok:
        ui.ok("Drift on entry 2 flagged automatically: cases 3 and 4 ran on a changed tool.")

    # Anchor the head hash with the external sealer (Module 2)
    sealer = Sealer()
    pub = load_public_key(sealer.public_key_path)
    head = entries[-1]["entry_hash"]
    anchor = sealer.seal_bytes(head.encode())
    ui.info(f"Head hash sealed out-of-band: {head[:16]}... at {anchor['sealed_at']}")

    ui.section("Phase 2: attacker hides the drift in entry 2 (no re-hashing)")
    forged = copy.deepcopy(entries)
    forged[2]["drift"] = []
    forged[2]["state"]["files"]["extraction_tool.bin"] = forged[1]["state"]["files"]["extraction_tool.bin"]
    p2 = verify_entries(forged)
    show(p2)

    ui.section("Phase 3: attacker also recomputes entry 2's own hash")
    forged[2]["entry_hash"] = entry_digest(forged[2])
    p3 = verify_entries(forged)
    show(p3)

    ui.section("Phase 4: attacker recomputes the entire chain")
    rechain(forged, start=2)
    p4 = verify_entries(forged)
    show(p4)
    new_head = forged[-1]["entry_hash"]
    anchored_ok, reason = verify_seal(new_head.encode(), anchor, pub)
    if anchored_ok:
        ui.fail("External anchor accepted the forged head (unexpected).")
    else:
        ui.ok(f"External anchor check FAILED as it should: {reason}")
    p4b = verify_entries(forged, anchored_head=head)
    show(p4b)

    ui.section("Result")
    ui.table(
        ["Attack", "Chain check alone", "Chain + external anchor"],
        [
            ["Edit entry, keep old hashes", "DETECTED" if p2 else "missed", "DETECTED"],
            ["Edit entry, fix its own hash", "DETECTED" if p3 else "missed", "DETECTED"],
            ["Recompute whole chain", "DETECTED" if p4 else "MISSED", "DETECTED" if (p4b and not anchored_ok) else "missed"],
        ],
    )
    ui.warn("Limitation shown by phase 4: a hash chain alone cannot stop a full rewrite.")
    ui.info("Fix: anchor the head hash with the external sealer after each extraction.")
    passed = phase1_ok and bool(p2) and bool(p3) and not p4 and not anchored_ok and bool(p4b)
    if passed:
        ui.ok("Demo behaved as expected.")
        return 0
    ui.fail("Demo did not behave as expected.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
