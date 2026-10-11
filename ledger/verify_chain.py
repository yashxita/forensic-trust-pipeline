"""Verify the integrity of a state ledger.

Usage:
    python -m ledger.verify_chain results/ledger.jsonl [--anchor <head-hash>]
"""
import argparse
import sys

from ledger.state_logger import GENESIS, entry_digest, read_ledger


def verify_entries(entries, anchored_head=None):
    """Return a list of (entry index, problem). Empty list means the chain is intact."""
    problems = []
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("index") != i:
            problems.append((i, "index out of sequence"))
        if e.get("prev_hash") != prev:
            problems.append((i, "prev_hash does not match the previous entry"))
        if entry_digest(e) != e.get("entry_hash"):
            problems.append((i, "entry content does not match its entry_hash"))
        prev = e.get("entry_hash")
    if anchored_head is not None:
        if not entries:
            problems.append((0, "ledger is empty but a head hash was anchored"))
        elif entries[-1].get("entry_hash") != anchored_head:
            problems.append((len(entries) - 1, "head hash differs from the externally anchored head"))
    return problems


def verify_ledger(path, anchored_head=None):
    return verify_entries(read_ledger(path), anchored_head)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ledger")
    ap.add_argument("--anchor", help="externally anchored head hash")
    args = ap.parse_args()
    problems = verify_ledger(args.ledger, args.anchor)
    if not problems:
        print("LEDGER INTACT")
        return 0
    for idx, msg in problems:
        print(f"PROBLEM at entry {idx}: {msg}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
