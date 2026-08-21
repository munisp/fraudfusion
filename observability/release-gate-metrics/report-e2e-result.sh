#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: report-e2e-result.sh <scenario> <success|failure>" >&2
  exit 2
fi

scenario="$1"
result="$2"
case "$scenario" in
  dashboard-authorized|dashboard-unauthorized|kyc-session-create|tenant-isolation|token-revocation|document-malware-block) ;;
  *) echo "unsupported E2E scenario" >&2; exit 2 ;;
esac
case "$result" in success|failure) ;; *) echo "invalid E2E result" >&2; exit 2 ;; esac

: "${RELEASE_GATE_METRICS_URL:?RELEASE_GATE_METRICS_URL is required}"
: "${RELEASE_GATE_INGEST_HMAC_SECRET:?RELEASE_GATE_INGEST_HMAC_SECRET is required}"
: "${FRAUDFUSION_E2E_RUN_ID:?FRAUDFUSION_E2E_RUN_ID is required}"
RELEASE_GATE_HMAC_KEY_ID="${RELEASE_GATE_HMAC_KEY_ID:-current}"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
payload="$(jq -cn \
  --arg event "e2e_scenario" \
  --arg scenario "$scenario" \
  --arg result "$result" \
  --arg run_id "$FRAUDFUSION_E2E_RUN_ID" \
  '{event:$event,scenario:$scenario,result:$result,run_id:$run_id}')"
signature="$(printf '%s\n%s\n%s' "$RELEASE_GATE_HMAC_KEY_ID" "$timestamp" "$payload" | openssl dgst -sha256 -hmac "$RELEASE_GATE_INGEST_HMAC_SECRET" -binary | xxd -p -c 256)"

curl --fail --silent --show-error --retry 3 --connect-timeout 5 --max-time 15 \
  -H 'Content-Type: application/json' \
  -H "X-FraudFusion-Timestamp: ${timestamp}" \
  -H "X-FraudFusion-Key-ID: ${RELEASE_GATE_HMAC_KEY_ID}" \
  -H "X-FraudFusion-Signature: ${signature}" \
  --data "$payload" \
  "${RELEASE_GATE_METRICS_URL%/}/ingest" >/dev/null
