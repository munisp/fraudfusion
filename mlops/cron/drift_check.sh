#!/usr/bin/env bash
# Drift check + drift-triggered retrain (complements cron-only retrain.sh).
#
# Runs the drift monitor over the latest lakehouse window, persists the
# status JSON, then lets mlops/monitor/drift_trigger.py decide whether the
# alert is sustained (>=2 consecutive checks, 24h cooldown) and invoke the
# SAME retrain pipeline (mlops/cron/retrain.sh).
#
# Cron example (hourly):
#   0 * * * * cd /opt/fraudfusion && mlops/cron/drift_check.sh >> /var/log/drift.log 2>&1
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

LAKEHOUSE_DIR="${LAKEHOUSE_DIR:-mlops/data/lakehouse}"
STATUS_FILE="${DRIFT_STATUS_FILE:-mlops/data/drift_status.json}"
TEXTFILE_DIR="${DRIFT_TEXTFILE_DIR:-mlops/monitor}"

# Reference: 7-day window ending 8 days ago; current: yesterday + today.
END_REF="${DRIFT_REF_END:-$(date -d '8 days ago' +%F 2>/dev/null || date -v-8d +%F)}"
START_REF="${DRIFT_REF_START:-$(date -d '14 days ago' +%F 2>/dev/null || date -v-14d +%F)}"
END_CUR="${DRIFT_CUR_END:-$(date +%F)}"
START_CUR="${DRIFT_CUR_START:-$(date -d '1 day ago' +%F 2>/dev/null || date -v-1d +%F)}"

echo "[$(date -Is)] drift check: ref=$START_REF:$END_REF cur=$START_CUR:$END_CUR"
# drift.py exits 2 on alert — that is the signal, not a failure.
python mlops/monitoring/drift.py \
  --lakehouse-dir "$LAKEHOUSE_DIR" \
  --reference "$START_REF:$END_REF" --current "$START_CUR:$END_CUR" \
  --output "$STATUS_FILE" --textfile "$TEXTFILE_DIR/drift.prom" || true

python mlops/monitor/drift_trigger.py --status-file "$STATUS_FILE"
