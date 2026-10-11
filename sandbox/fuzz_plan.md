# Sandbox and fuzzing plan (design, report Sections 10.1 and 10.4)

## Sandbox controls (see `Dockerfile` and `run_sandboxed.sh`)

| Control | Docker setting | Threat it limits |
|---|---|---|
| Single-use environment | `--rm`, fresh container per extraction | Persistence of malicious code (prospective impact, Sec 9.1) |
| No network | `--network none` | Data exfiltration, command and control |
| Read-only root filesystem | `--read-only`, small `--tmpfs` | Modifying the tool or other cases' files |
| Evidence mounted read-only | `-v data:/input:ro` | Altering the evidence during parsing |
| Least privilege | non-root user, `--cap-drop ALL`, `no-new-privileges` | Privilege escalation after code execution |
| Resource limits | `--memory`, `--cpus`, `--pids-limit` | Denial of service, fork bombs |
| Output channel | one writable mount (`/out`) | Everything leaving the sandbox goes through one place |

Behavioural monitoring (design only): record system calls with `strace -f` or a
seccomp audit profile during extraction, and flag spawned processes, writes
outside `/out`, and outbound connection attempts. A flagged run forces manual
review before the report is accepted.

## Fuzzing plan

1. **Lightweight mutation fuzzing (implemented):** `fuzz_parser_b.py` mutates a
   valid database (bit flips, byte overwrites, truncation, header and page-header
   corruption, boundary values, splices) and records clean rejections versus
   unexpected exceptions.
2. **Coverage-guided fuzzing (recommended extension):** wrap
   `MiniSQLite(data).read_table("messages")` in an Atheris harness, or fuzz a C
   media or archive library with AFL++ or libFuzzer, using the sample databases
   as the seed corpus.
3. **When to run:** before deployment, on every dependency update, and
   periodically even without updates, because the 2021 flaw sat in an old
   third-party library that was never re-tested (report Sec 10.4).
4. **Acceptance criterion:** zero unexpected exceptions and zero hangs over the
   agreed corpus and time budget; any crash blocks release of that parser build.
