"""Run every demo in order and save each output to results/<name>.txt."""
import os
import subprocess
import sys
from pathlib import Path

import ui

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

STEPS = [
    ("00_sample_data", ["-m", "data.make_sample_db"]),
    ("01_comparator", ["-m", "comparator.compare", "--demo"]),
    ("02_sealing", ["-m", "sealing.attack_demo"]),
    ("03_ledger", ["-m", "ledger.tamper_demo"]),
    ("04_fuzzing", ["-m", "sandbox.fuzz_parser_b", "--iterations", "3000"]),
]


def main():
    RESULTS.mkdir(exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    summary = []
    for name, args in STEPS:
        proc = subprocess.run([sys.executable] + args, cwd=ROOT, capture_output=True, text=True, env=env)
        output = proc.stdout + proc.stderr
        (RESULTS / f"{name}.txt").write_text(output, encoding="utf-8")
        print(output)
        summary.append((name, "PASS" if proc.returncode == 0 else "FAIL"))
    ui.banner("SUMMARY")
    ui.table(["Step", "Status"], summary)
    return 0 if all(s == "PASS" for _, s in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
