#!/usr/bin/env bash
# Bootstrap the MLflow tracking stack and verify it is reachable.
set -euo pipefail

cd "$(dirname "$0")"

echo "Starting MLflow + Postgres..."
docker compose up -d

echo "Waiting for MLflow to become healthy..."
for i in $(seq 1 60); do
  if curl -sf http://localhost:5000/health >/dev/null 2>&1; then
    echo "MLflow is up at http://localhost:5000"
    break
  fi
  if [[ "$i" == "60" ]]; then
    echo "ERROR: MLflow did not become healthy in time" >&2
    exit 1
  fi
  sleep 2
done

cat <<'EOF'

Wiring for the ml lane (ml/train, ml/registry/register.py):
  export MLFLOW_TRACKING_URI=http://localhost:5000

register.py should:
  1. log params/metrics to the active run (mlflow.log_param / log_metric)
  2. mlflow.register_model("runs:/<run_id>/fraud_net", "fraud_net")
  3. transition to stage/alias "champion" on promotion

Artifacts live in the mlflow-artifacts volume; backend store is Postgres
(service mlflow-db, database mlflow).
EOF
