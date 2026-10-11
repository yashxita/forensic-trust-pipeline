"""Module 4 (lightweight): mutation fuzzing of Parser B (report Section 10.4).

Takes a valid database as a seed, applies random structural and byte-level
mutations, and feeds each mutant to the parser. Outcomes:
  ok        parsed without error
  rejected  raised ParseError (the desired behaviour for malformed input)
  crash     raised any other exception (a robustness bug a real attacker could probe)
  slow      took longer than 1 second

Run inside the container (see run_sandboxed.sh) or directly:
    python -m sandbox.fuzz_parser_b --iterations 3000
For coverage-guided fuzzing use Atheris (see fuzz_plan.md).
"""
import argparse
import random
import sys
import time
import traceback
from pathlib import Path

import ui
from comparator.parser_b import MiniSQLite, ParseError

ROOT = Path(__file__).resolve().parent.parent
PAGE = 4096
INTERESTING16 = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF, 0x1000, 0x0FFF]


def mutate(seed_bytes, rng):
    data = bytearray(seed_bytes)
    strategy = rng.choice(["bitflip", "bytes", "truncate", "header", "pagehdr", "interesting", "splice"])
    n = len(data)
    if strategy == "bitflip":
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(n)] ^= 1 << rng.randrange(8)
    elif strategy == "bytes":
        for _ in range(rng.randint(1, 16)):
            data[rng.randrange(n)] = rng.randrange(256)
    elif strategy == "truncate":
        data = data[: rng.randint(1, n - 1)]
    elif strategy == "header":
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(min(100, n))] = rng.randrange(256)
    elif strategy == "pagehdr":
        page = rng.randrange(max(1, n // PAGE))
        base = page * PAGE + (100 if page == 0 else 0)
        for _ in range(rng.randint(1, 4)):
            pos = base + rng.randrange(12)
            if pos < n:
                data[pos] = rng.randrange(256)
    elif strategy == "interesting":
        pos = rng.randrange(n - 1)
        v = rng.choice(INTERESTING16)
        data[pos], data[pos + 1] = v >> 8, v & 0xFF
    else:  # splice
        size = rng.randint(4, 256)
        src = rng.randrange(max(1, n - size))
        dst = rng.randrange(max(1, n - size))
        data[dst:dst + size] = data[src:src + size]
    return bytes(data), strategy


def run_one(data):
    start = time.perf_counter()
    try:
        MiniSQLite(data).read_table("messages")
        outcome, exc = "ok", None
    except ParseError:
        outcome, exc = "rejected", None
    except Exception as e:  # any other exception is a parser robustness bug
        outcome, exc = "crash", e
    return outcome, exc, time.perf_counter() - start


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(ROOT / "data" / "sample_messages.db"))
    ap.add_argument("--iterations", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default=str(ROOT / "results" / "crashes"))
    ap.add_argument("--fail-on-crash", action="store_true")
    args = ap.parse_args()

    seed_path = Path(args.input)
    if not seed_path.exists():
        from data.make_sample_db import build
        build(seed_path)
    seed_bytes = seed_path.read_bytes()
    rng = random.Random(args.seed)
    out_dir = Path(args.out)

    ui.banner("MODULE 4: PARSER FUZZING HARNESS (report Sections 10.1, 10.4)")
    ui.info(f"Seed file: {seed_path.name} ({len(seed_bytes)} bytes), iterations: {args.iterations}, rng seed: {args.seed}")

    counts = {"ok": 0, "rejected": 0, "crash": 0, "slow": 0}
    signatures = {}
    total_time = 0.0
    started = time.perf_counter()
    for i in range(args.iterations):
        mutant, strategy = mutate(seed_bytes, rng)
        outcome, exc, elapsed = run_one(mutant)
        total_time += elapsed
        counts[outcome] += 1
        if elapsed > 1.0:
            counts["slow"] += 1
        if outcome == "crash":
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            sig = f"{type(exc).__name__} at {Path(frame.filename).name}:{frame.lineno}"
            if sig not in signatures:
                signatures[sig] = (strategy, i)
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / f"crash_{len(signatures):02d}.bin").write_bytes(mutant)
    wall = time.perf_counter() - started

    ui.section("Results")
    ui.table(
        ["Metric", "Value"],
        [
            ["Mutated inputs tested", args.iterations],
            ["Parsed without error", counts["ok"]],
            ["Rejected cleanly (ParseError)", counts["rejected"]],
            ["Unexpected crashes", counts["crash"]],
            ["Distinct crash signatures", len(signatures)],
            ["Slow inputs (> 1 s)", counts["slow"]],
            ["Mean time per input", f"{1000 * total_time / args.iterations:.2f} ms"],
            ["Total wall time", f"{wall:.1f} s"],
        ],
    )
    for sig, (strategy, idx) in signatures.items():
        ui.warn(f"{sig} (first seen at iteration {idx}, strategy: {strategy})")
    if counts["crash"] == 0:
        ui.ok("No unexpected exceptions: every malformed input was parsed or rejected cleanly.")
    else:
        ui.warn(f"Crashing inputs saved to {out_dir}")
    return 1 if (args.fail_on_crash and counts["crash"]) else 0


if __name__ == "__main__":
    sys.exit(main())
