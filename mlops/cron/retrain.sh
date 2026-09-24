#!/usr/bin/env bash
# Continuous-training loop (see mlops/continuous_training.md).
#
#   export lakehouse -> ingest labels -> ml/train/continuous.py (champion vs
#   challenger) -> registry update -> router config reload
#
# Cron example (daily 02:00):
#   0 2 * * * cd /opt/fraudfusion && mlops/cron/retrain.sh >> /var/log/retrain.log 2>&1
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

export LAKEHOUSE_DIR="${LAKEHOUSE_DIR:-mlops/data/lakehouse}"
export MLFLOW_TRACKING_URI="${MLFLOW_TRACKING_URI:-http://localhost:5000}"
EXPERIMENT_CONFIG="${EXPERIMENT_CONFIG:-mlops/experiments/champion_challenger.yaml}"
ROUTER_RELOAD_URL="${ROUTER_RELOAD_URL:-http://localhost:8200/v1/route/reload}"
RETRAIN_THRESHOLD="${RETRAIN_THRESHOLD:-2000}"
RETRAIN_EPOCHS="${RETRAIN_EPOCHS:-8}"
CHAMPION_VERSION="${CHAMPION_VERSION:-v1}"
DECISION_FILE="$LAKEHOUSE_DIR/promotion_decision.json"

log() { echo "[$(date -Is)] $*"; }

log "STEP 1/5: export production DB -> lakehouse ($LAKEHOUSE_DIR/transactions)"
START_DATE="${EXPORT_START:-$(date -d '14 days ago' +%F 2>/dev/null || date -v-14d +%F)}"
END_DATE="${EXPORT_END:-$(date +%F)}"
python mlops/lakehouse/export.py --start "$START_DATE" --end "$END_DATE" --lakehouse-dir "$LAKEHOUSE_DIR"

log "STEP 2/5: ingest investigator labels"
if [[ -n "${LABELS_FILE:-}" ]]; then
  python mlops/lakehouse/ingest_labels.py --file "$LABELS_FILE" --lakehouse-dir "$LAKEHOUSE_DIR"
elif [[ -n "${DATABASE_URL:-}" ]]; then
  python mlops/lakehouse/ingest_labels.py --from-db --lakehouse-dir "$LAKEHOUSE_DIR" || log "WARN: label ingest from DB failed; continuing"
fi

log "STEP 3/5: train challenger + promotion decision (ml lane: ml/train/continuous.py)"
python ml/train/continuous.py --threshold "$RETRAIN_THRESHOLD" --epochs "$RETRAIN_EPOCHS" \
  --champion-version "$CHAMPION_VERSION"

if [[ ! -f "$DECISION_FILE" ]]; then
  log "no promotion decision written (below data threshold or no new partitions); exiting cleanly"
  exit 0
fi

read -r PROMOTED PROMOTED_PATH CHALLENGER_VERSION < <(python - "$DECISION_FILE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(str(d.get("promoted", False)).lower(), d.get("promoted_path") or "-", d.get("challenger_version") or "-")
PY
)
log "STEP 4/5: promotion decision -> promoted=$PROMOTED challenger=$CHALLENGER_VERSION path=$PROMOTED_PATH"

if [[ "$PROMOTED" == "true" ]]; then
  log "STEP 5/5: registry update + router config reload"
  python ml/registry/register.py --model fraud_net --artifact-dir "$PROMOTED_PATH" \
    --params "{\"source\": \"continuous_training\", \"champion_version\": \"$CHAMPION_VERSION\"}"
  # Point the router's challenger arm at the promoted version, then hot-reload.
  python - "$EXPERIMENT_CONFIG" "$CHALLENGER_VERSION" <<'PY'
import re, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path).read()
text = re.sub(r"(challenger:\n(?:  .*\n)*?  model_version: )\S+", rf"\g<1>{version}", text)
open(path, "w").write(text)
print(f"router config: challenger -> {version}")
PY
  curl -sf -X POST "$ROUTER_RELOAD_URL" || log "WARN: router reload failed; apply manually"
else
  log "STEP 5/5: skipped (challenger not promoted; champion $CHAMPION_VERSION retained)"
fi

log "continuous-training loop complete"
