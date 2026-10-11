#!/usr/bin/env bash
# Run the parser inside a locked-down, disposable container (report Section 10.1).
# Controls: no network, read-only root filesystem, evidence mounted read-only,
# all capabilities dropped, non-root user, memory/CPU/process limits, removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m data.make_sample_db
mkdir -p results/sandbox_out

docker build -f sandbox/Dockerfile -t forensic-trust-sandbox .

docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 256m \
  --cpus 1 \
  -v "$PWD/data:/input:ro" \
  -v "$PWD/results/sandbox_out:/out" \
  forensic-trust-sandbox
