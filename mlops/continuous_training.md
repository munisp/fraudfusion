# Continuous Training Loop

Automated loop that keeps the fraud model fresh as new labeled outcomes
arrive from investigators.

## Stages

1. **Export** — `mlops/lakehouse/export.py` pulls newly scored transactions
   from Postgres (`DATABASE_URL`) into
   `LAKEHOUSE_DIR/transactions/dt=YYYY-MM-DD/` parquet partitions (snappy).
   Demo without DB: `--synthetic`.
2. **Label ingest** — `mlops/lakehouse/ingest_labels.py` merges investigator
   feedback (`is_fraud` ∈ {0,1}) into partitions by `transaction_id`.
3. **Train + compare** — `python ml/train/continuous.py --threshold N
   --epochs E --champion-version v1` (ml lane) reads unread lakehouse
   partitions, fine-tunes a challenger from the champion weights, evaluates
   champion vs challenger on a held-out slice (AUC-PR), writes artifacts for
   the challenger when it wins, and records `LAKEHOUSE_DIR/promotion_decision.json`.
   Distributed variant for full retraining: `mlops/ray/ray_train.py --num-workers N`.
4. **Promotion decision** — driven by the ml lane's decision JSON
   (`promoted`, `promoted_path`, champion/challenger metrics). Belt-and-braces
   production check: `mlops/monitoring/performance.py` tracks the live model's
   rolling F1 and pages when degraded.
5. **Registry + reload** — on promotion, `python ml/registry/register.py
   --model fraud_net --artifact-dir <promoted_path>` (ml lane; honors
   `MLFLOW_TRACKING_URI`, local fallback) registers the run; the router's
   experiment YAML (`mlops/experiments/champion_challenger.yaml`) challenger
   arm is bumped to the new version and `POST /v1/route/reload` hot-reloads
   the running router so A/B traffic validates the promoted model before a
   future full champion swap.

## Orchestration

`mlops/cron/retrain.sh` runs all five stages; install as a cron job:

```
0 2 * * * cd /opt/fraudfusion && mlops/cron/retrain.sh >> /var/log/retrain.log 2>&1
```

Required env: `DATABASE_URL` (production read replica recommended).
Optional: `LAKEHOUSE_DIR`, `MLFLOW_TRACKING_URI`, `RETRAIN_THRESHOLD`,
`RETRAIN_EPOCHS`, `CHAMPION_VERSION`, `EXPORT_START`, `EXPORT_END`,
`ROUTER_RELOAD_URL`, `EXPERIMENT_CONFIG`, `LABELS_FILE`.

## Failure handling

- Any step failure aborts the loop (`set -euo pipefail`); the previous
  champion keeps serving — promotion is the only mutating step.
- Router reload failure is non-fatal but logged loudly; re-run
  `curl -X POST http://localhost:8200/v1/route/reload` manually.
- Drift (`mlops/monitoring/drift.py`) and performance alerts feed the
  retraining trigger: a `degraded` performance report or PSI alert should
  page and/or kick off retrain.sh ahead of schedule.
