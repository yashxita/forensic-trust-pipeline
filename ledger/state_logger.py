"""Module 3 core: record workstation software state in a hash-chained ledger.

Each entry captures the OS, interpreter, key package versions and SHA-256 hashes
of the extraction tooling just before an extraction. Every entry includes the
hash of the previous one, so editing history breaks the chain (report Sec 9.2).
"""
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENESIS = "0" * 64
DEFAULT_TRACKED = [
    "comparator/parser_a.py",
    "comparator/parser_b.py",
    "comparator/compare.py",
    "sealing/sealer.py",
    "sealing/verify.py",
    "ledger/state_logger.py",
]
TRACKED_PACKAGES = ["cryptography"]


def sha256_file(path):
    path = Path(path)
    if not path.exists():
        return "MISSING"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def default_tracked():
    tracked = {p: REPO_ROOT / p for p in DEFAULT_TRACKED}
    tracked["python_interpreter"] = Path(sys.executable)
    return tracked


def collect_state(tracked_files=None):
    tracked = tracked_files if tracked_files is not None else default_tracked()
    packages = {}
    for name in TRACKED_PACKAGES:
        try:
            packages[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            packages[name] = "not installed"
    return {
        "host_id": hashlib.sha256(platform.node().encode()).hexdigest()[:12],
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "packages": packages,
        "files": {label: sha256_file(p) for label, p in sorted(tracked.items())},
    }


def diff_states(prev, cur):
    changes = []
    for key in ("host_id", "os", "python"):
        if prev.get(key) != cur.get(key):
            changes.append(f"{key} changed")
    for name in sorted(set(prev["packages"]) | set(cur["packages"])):
        if prev["packages"].get(name) != cur["packages"].get(name):
            changes.append(f"package changed: {name}")
    for label in sorted(set(prev["files"]) | set(cur["files"])):
        if prev["files"].get(label) != cur["files"].get(label):
            changes.append(f"file changed: {label}")
    return changes


def read_ledger(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_ledger(path, entries):
    Path(path).write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))


def entry_digest(entry):
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


def append_entry(ledger_path, case_id, event="pre-extraction", tracked_files=None):
    entries = read_ledger(ledger_path)
    prev_hash = entries[-1]["entry_hash"] if entries else GENESIS
    state = collect_state(tracked_files)
    drift = diff_states(entries[-1]["state"], state) if entries else []
    entry = {
        "index": len(entries),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "case_id": case_id,
        "event": event,
        "state": state,
        "drift": drift,
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = entry_digest(entry)
    entries.append(entry)
    write_ledger(ledger_path, entries)
    return entry


def rechain(entries, start=0):
    """Recompute links and hashes from index `start` (what an attacker with write access can do)."""
    for i in range(start, len(entries)):
        entries[i]["prev_hash"] = entries[i - 1]["entry_hash"] if i > 0 else GENESIS
        entries[i]["entry_hash"] = entry_digest(entries[i])
    return entries


if __name__ == "__main__":
    ledger = REPO_ROOT / "results" / "ledger.jsonl"
    case = sys.argv[1] if len(sys.argv) > 1 else "CASE-DEMO"
    e = append_entry(ledger, case)
    print(f"Entry {e['index']} appended to {ledger}")
    print(f"  entry_hash: {e['entry_hash']}")
    print(f"  drift     : {e['drift'] or 'none'}")
