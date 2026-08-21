#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_GATE_METRICS_URL:?RELEASE_GATE_METRICS_URL is required}"
: "${RELEASE_GATE_INGEST_HMAC_SECRET:?RELEASE_GATE_INGEST_HMAC_SECRET is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
RELEASE_GATE_HMAC_KEY_ID="${RELEASE_GATE_HMAC_KEY_ID:-current}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${MOBILE_QUALITY_RESULT:?MOBILE_QUALITY_RESULT is required}"
: "${CONTRACT_RESULT:?CONTRACT_RESULT is required}"
: "${GO_RACE_RESULT:?GO_RACE_RESULT is required}"
: "${DEPENDENCY_SECURITY_RESULT:?DEPENDENCY_SECURITY_RESULT is required}"

emit_ci_gate() {
  local gate="$1"
  local result="$2"
  local timestamp payload signature

  case "$result" in
    success|failure) ;;
    *) echo "invalid result for $gate" >&2; return 2 ;;
  esac

  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  payload="$(jq -cn \
    --arg event "ci_gate" \
    --arg gate "$gate" \
    --arg result "$result" \
    --arg run_id "${GITHUB_RUN_ID}" \
    --arg sha "${GITHUB_SHA}" \
    '{event:$event,gate:$gate,result:$result,run_id:$run_id,sha:$sha}')"
  signature="$(printf '%s\n%s\n%s' "$RELEASE_GATE_HMAC_KEY_ID" "$timestamp" "$payload" | openssl dgst -sha256 -hmac "$RELEASE_GATE_INGEST_HMAC_SECRET" -binary | xxd -p -c 256)"

  curl --fail --silent --show-error --retry 3 --connect-timeout 5 --max-time 15 \
    -H 'Content-Type: application/json' \
    -H "X-FraudFusion-Timestamp: ${timestamp}" \
    -H "X-FraudFusion-Key-ID: ${RELEASE_GATE_HMAC_KEY_ID}" \
    -H "X-FraudFusion-Signature: ${signature}" \
    --data "$payload" \
    "${RELEASE_GATE_METRICS_URL%/}/ingest" >/dev/null
}

emit_ci_gate mobile-quality "$MOBILE_QUALITY_RESULT"
emit_ci_gate local-contract-smoke "$CONTRACT_RESULT"
emit_ci_gate go-race "$GO_RACE_RESULT"
emit_ci_gate dependency-security "$DEPENDENCY_SECURITY_RESULT"
