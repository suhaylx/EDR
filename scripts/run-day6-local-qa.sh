#!/usr/bin/env bash
# TuranSec EDR laboratory QA runner. Safe, non-destructive, no service install.
# Execute as a non-root user on Ubuntu 24.04 x64 or a Linux build runner.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
out="$root/.qa-day6"
if [[ -L "$out" ]]; then
  echo "Refusing symlinked QA output directory." >&2
  exit 2
fi
mkdir -p "$out"
if [[ "$(id -u)" == "0" ]]; then
  echo "Run QA as an unprivileged user, not root." >&2
  exit 2
fi
for cmd in go cargo node npm curl jq openssl sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing prerequisite: $cmd" >&2
    exit 2
  fi
done
if [[ ! -d frontend/node_modules ]]; then
  echo "Missing frontend/node_modules; install approved dependencies first." >&2
  echo "No package-lock.json exists; source dependency installation is not reproducible." >&2
  exit 2
fi
echo "TuranSec EDR - isolated lab Day 6 QA"
echo "Source branch: $(git branch --show-current 2>/dev/null || echo unknown)"
echo "Source SHA: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "Go backend tests (all + race + vet)..."
(cd backend && go test ./... && go test -race -count=1 ./... && go vet ./...)
echo "Rust lab agent unit tests on this Linux machine..."
(cd agent && cargo test)
echo "React source tests, privacy checks, typecheck and Vite build..."
(cd frontend && npm test && npm run typecheck && npm run build)
echo "Go API binary and real loopback HTTP smoke..."
(cd backend && CGO_ENABLED=0 go build -trimpath -o "$out/turansec-edr-api" ./cmd/server)
bash scripts/smoke-ubuntu-lab-api.sh "$out/turansec-edr-api"
sha256sum "$out/turansec-edr-api" >"$out/GO_BINARY_SHA256SUMS.txt"
(cd "$out" && sha256sum -c GO_BINARY_SHA256SUMS.txt)
echo "PASS: local Go/Rust/React source QA, binary loopback smoke and SHA-256 check."
echo "NOT RUN: Windows-native EXE, genuine Windows Sysmon, Linux audit/eBPF, ClamAV daemon/EICAR, production mTLS, durable telemetry, signed installer and host rollback."
echo "Local QA PASS does not authorize deployment, merge or production release."
