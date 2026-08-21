#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ROOT}/test-artifacts"
mkdir -p "$OUT"

cd "$ROOT"
go test \
  -race \
  -count=1 \
  -run '^TestHMACIngestionHighConcurrencyUniqueAndReplay$' \
  -v ./... \
  | tee "$OUT/hmac-concurrency-load-test.log"

echo "HMAC concurrent load test passed: 500 unique signed events + 500 concurrent replay attempts."
