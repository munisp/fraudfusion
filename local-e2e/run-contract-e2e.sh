#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${ROOT}/../FRAUD_FUSION_COMPLETE_UNIFIED"
REPORTER="${PROJECT_ROOT}/observability/release-gate-metrics/report-e2e-result.sh"
REQUEST_ID="mobile-e2e-$(date +%s)"
TOKEN="local-contract-token"
LOG_DIR="${ROOT}/artifacts"
CURRENT_SCENARIO=""
mkdir -p "${LOG_DIR}"

cleanup() {
  docker compose -f "${ROOT}/docker-compose.yml" down -v --remove-orphans
}

report_scenario() {
  local scenario="$1"
  local result="$2"
  if [[ -n "${RELEASE_GATE_METRICS_URL:-}" && -n "${RELEASE_GATE_INGEST_HMAC_SECRET:-}" ]]; then
    FRAUDFUSION_E2E_RUN_ID="${REQUEST_ID}" "$REPORTER" "$scenario" "$result"
  fi
}

on_error() {
  local exit_code=$?
  if [[ -n "${CURRENT_SCENARIO}" ]]; then
    report_scenario "${CURRENT_SCENARIO}" failure || true
  fi
  exit "$exit_code"
}

trap cleanup EXIT
trap on_error ERR

docker compose -f "${ROOT}/docker-compose.yml" up --build --wait
curl --fail --retry 10 --retry-connrefused "http://127.0.0.1:8088/healthz" | tee "${LOG_DIR}/health.json"

CURRENT_SCENARIO="dashboard-unauthorized"
unauthorized_code="$(curl -sS -o "${LOG_DIR}/dashboard-unauthorized.json" -w '%{http_code}' \
  -H "X-Request-ID: ${REQUEST_ID}-unauthorized" \
  http://127.0.0.1:8088/api/v1/mobile/dashboard)"
test "${unauthorized_code}" = "401"
report_scenario "${CURRENT_SCENARIO}" success

CURRENT_SCENARIO="dashboard-authorized"
curl --fail -sS \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Request-ID: ${REQUEST_ID}-dashboard" \
  http://127.0.0.1:8088/api/v1/mobile/dashboard | tee "${LOG_DIR}/dashboard.json"
report_scenario "${CURRENT_SCENARIO}" success

CURRENT_SCENARIO="kyc-session-create"
curl --fail -sS -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Request-ID: ${REQUEST_ID}-kyc" \
  http://127.0.0.1:8088/api/v1/kyc/sessions | tee "${LOG_DIR}/kyc-session.json"
report_scenario "${CURRENT_SCENARIO}" success

CURRENT_SCENARIO=""
docker compose -f "${ROOT}/docker-compose.yml" logs --no-color go-mobile-mock > "${LOG_DIR}/go-mobile-mock.log"
grep -F "${REQUEST_ID}" "${LOG_DIR}/go-mobile-mock.log" > "${LOG_DIR}/correlated-requests.log"
test "$(wc -l < "${LOG_DIR}/correlated-requests.log")" = "3"
if grep -Fq "${TOKEN}" "${LOG_DIR}/go-mobile-mock.log"; then
  echo "token leakage detected in mock logs" >&2
  exit 1
fi
printf 'E2E contract test passed; inspect %s\n' "${LOG_DIR}"
