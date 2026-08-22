#!/usr/bin/env bash
set -euo pipefail

: "${LEDGER_OUTBOX_BENCHMARK_DATABASE_URL:?Set an isolated PostgreSQL database URL; never run this benchmark against production.}"
: "${LEDGER_OUTBOX_BENCHMARK_OUTPUT:=./outbox-benchmark-metrics.json}"

case "$LEDGER_OUTBOX_BENCHMARK_DATABASE_URL" in
  *sslmode=verify-full*|*sslmode=disable*) ;;
  *) echo "LEDGER_OUTBOX_BENCHMARK_DATABASE_URL must explicitly specify sslmode" >&2; exit 2 ;;
esac

if [[ "${LEDGER_OUTBOX_BENCHMARK_ALLOW_PRODUCTION:-}" == "true" ]]; then
  echo "Refusing production override: benchmark execution against production is prohibited." >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="$LEDGER_OUTBOX_BENCHMARK_OUTPUT"
if [[ "$OUTPUT_PATH" != /* ]]; then
  OUTPUT_PATH="$PWD/$OUTPUT_PATH"
fi
mkdir -p "$(dirname "$OUTPUT_PATH")"

export LEDGER_OUTBOX_BENCHMARK_OUTPUT="$OUTPUT_PATH"
cd "$ROOT"
go test -count=1 -run '^TestSettlementOutboxBenchmark$' -v ./...
printf '\nBenchmark telemetry: %s\n' "$OUTPUT_PATH"
jq . "$OUTPUT_PATH"
