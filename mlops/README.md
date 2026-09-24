# MLOps — model serving, A/B routing, monitoring, retraining

## A/B routing path (champion/challenger)

```
aml-monitor (Go detector)                    deploy/kubernetes/model-router.yaml
  |  POST AML_ML_SERVICE_URL                 ConfigMap model-router-config
  v                                          (experiment: fraud_net_v2_vs_v3)
model-router :8200  (mlops/serving/model_router.py)
  |  sha256(experiment_id:customer_id) % 100 < challenger_traffic_pct (10%)
  |--> champion arm  -> aml-ml-service    :8100 (fraud_net v2)
  |--> challenger arm-> aml-ml-service-v2 :8100 (fraud_net v3)
  |
  +--> parquet/jsonl event log (ROUTER_LOG_DIR, dt= partitions)
       + /v1/route/outcome attaches confirmed labels by request_id
```

1. `aml-monitor` posts scoring requests to the router (`/v1/route/score`),
   never directly to a model service. Set `AML_ML_SERVICE_URL=http://model-router:8200/v1/route/score`.
2. The router deterministically buckets customers, forwards to the arm URL,
   and logs (request_id, arm, model_version, score, customer hash).
3. `aml-ml-service` (champion) and `aml-ml-service-v2` (challenger) are two
   Deployments of the same image pinned to different model versions via
   `AML_MODEL_VERSION`. The k8s ConfigMap in
   `deploy/kubernetes/model-router.yaml` points each arm at its Service.
4. Investigator outcomes arrive at `/v1/route/outcome` (or via
   `mlops/lakehouse/ingest_labels.py`).

## Experiment analysis + promotion runbook

```bash
python mlops/experiments/analyze.py \
    --log-dir mlops/data/router_log --experiment fraud_net_v2_vs_v3
```

- Promotion gate: challenger fraud-capture recall >= champion AND flag-rate
  inflation < 20% (two-proportion z-test, p < 0.05).
- On pass: `python -m ml.registry.register promote --model fraud_net \
  --version v3 --stage Production --alias champion`, then update the router
  ConfigMap (champion -> v3) and `POST /v1/route/reload` (hot reload).
- On fail: keep champion serving; no rollback needed (champion untouched).
- `mlops/cron/retrain.sh` automates export -> labels -> retrain -> gate ->
  reload with fail-safe (champion keeps serving on any step failure).

## Monitoring

- `mlops/monitoring/drift.py` — PSI/KS vs reference window, Prometheus
  textfile gauges (`fraudfusion_drift_*`), exit 2 on alert.
- `mlops/monitoring/performance.py` — rolling precision/recall/F1 on labeled
  outcomes (`fraudfusion_model_*` gauges).
- Prometheus alert rules: `observability/prometheus/fraudfusion-model.rules.yml`;
  Alertmanager routes: `observability/alertmanager/fraudfusion-alertmanager.yml`
  (team="ml" routes).

## Registry

`ml/registry/register.py` logs runs to MLflow (`MLFLOW_TRACKING_URI`) with a
local-file fallback (`ml/registry/local_registry.json`) and supports
stage/alias promotion in both modes (`register.py promote --model ... --version
... --stage Production --alias champion`). k8s manifests for the tracking
server: `deploy/kubernetes/mlflow.yaml`; compose: `mlops/mlflow/docker-compose.yml`.

## Lakehouse

`mlops/lakehouse/export.py` (Postgres -> partitioned parquet, NDPA
pseudonymisation) and `ingest_labels.py` (CSV/JSON/Postgres labels ->
partition rewrite). See `mlops/lakehouse/README.md` for the schema.
