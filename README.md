# forensic-trust-pipeline

A small, defensive prototype that turns four controls proposed in the case study
*"When the Evidence Attacks Back: The 2021 Cellebrite Vulnerability and the Limits of
Forensic Tool Validation"* into working code. It does not touch or reproduce any
Cellebrite software, and it contains no exploit code. All data is fictional.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run_all.py                                    # runs every demo, saves output to results/
```

Each demo can also be run on its own (outputs are screenshot-friendly):

```bash
python -m comparator.compare --demo        # Module 1
python -m sealing.attack_demo              # Module 2
python -m ledger.tamper_demo               # Module 3
python -m sandbox.fuzz_parser_b            # Module 4 (lightweight fuzzing)
bash sandbox/run_sandboxed.sh              # Module 4 inside Docker (needs Docker)
```

Requires Python 3.9+ and the `cryptography` package.

## What each module proves

| Module | Folder | Report section | Claim demonstrated |
|---|---|---|---|
| 1. Dual-parser comparator | `comparator/` | 10.2 | A compromised parser cannot silently change results, because an independent second parser disagrees. Parser A uses Python's `sqlite3`; Parser B is a pure-Python reader of the SQLite file format that shares no code with it. |
| 2. Out-of-band sealing | `sealing/` | 5.3, 10.3 | A SHA-256 computed on the workstation can be recomputed by an attacker (accepts tampered report), but an Ed25519 signature from a separate sealer cannot be forged. |
| 3. State ledger | `ledger/` | 9.2 | Workstation software state (OS, packages, tool hashes) becomes part of chain of custody; edits to history break a hash chain, and anchoring the head hash with the sealer catches a full rewrite. |
| 4. Sandbox and fuzzing | `sandbox/` | 10.1, 10.4 | Locked-down single-use container design, plus a mutation fuzzer that feeds malformed databases to Parser B and counts clean rejections versus unexpected crashes. |

## Sample results (from `run_all.py`)

- **Comparator:** 300 rows parsed identically by both parsers. After simulated tampering (one record hidden, one timestamp altered, one fake record injected) the row counts still matched at 300, but the comparator flagged 3 differences.
- **Sealing:** the plain hash accepted 4 of 4 reports including 3 tampered ones; the signature check rejected all 3 tampered reports.
- **Ledger:** tool change flagged automatically; 3 tampering attempts detected, the third only with the external anchor.
- **Fuzzing:** 3000 mutated inputs, 1927 rejected cleanly, 1073 parsed, 0 unexpected crashes, 0 slow inputs (seed 1337).

## Layout

```
data/        sample SQLite database generator (fictional messages)
comparator/  parser_a.py, parser_b.py, compare.py
sealing/     sealer.py (the simulated HSM), verify.py, attack_demo.py
ledger/      state_logger.py, verify_chain.py, tamper_demo.py
sandbox/     Dockerfile, run_sandboxed.sh, fuzz_plan.md, fuzz_parser_b.py
results/     saved output of each demo
run_all.py   runs everything in order
ui.py        console formatting helpers
```

## Limitations (stated honestly)

- **Simulation, not a deployment.** The "HSM" is a folder holding a key on the same machine. A real deployment needs a separate device or hardware security module so the workstation never touches the private key.
- **Timestamps** come from the sealer's own clock. For legal weight, use an RFC 3161 timestamp from a trusted timestamping authority.
- **Parser B is minimal.** It supports UTF-8 table b-trees and single-page records only, and rejects everything else. It is a research prototype, not a forensic tool.
- **Fuzzing scope.** Parser B is pure Python, so it cannot show memory-corruption bugs like the 2021 class; the fuzzer demonstrates the testing workflow and robustness against malformed input. Coverage-guided fuzzing (Atheris, AFL++) of native parsers is described in `sandbox/fuzz_plan.md` but not run here.
- **Dual-tool value depends on independence.** Two parsers that share a library or a bug would agree on a wrong answer.
- **The ledger** detects change, not intent, and a full rewrite is only caught when the head hash is anchored externally (shown in `ledger/tamper_demo.py`).
- Not evaluated against any real forensic tool or real casework.

## Security note

`sealing/hsm_keystore/` holds demo private keys and is git-ignored. Never commit keys.
