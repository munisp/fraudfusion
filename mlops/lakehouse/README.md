# FraudFusion Lakehouse

Partitioned parquet lakehouse bridging production databases and ML training.

## Layout (matches the ml lane contract in ml/train/continuous.py)

```
$LAKEHOUSE_DIR/                       (env LAKEHOUSE_DIR, default mlops/data/lakehouse)
  transactions/
    dt=YYYY-MM-DD/                    # one partition per UTC day
      part-<hash>.parquet             # snappy-compressed
  promotion_decision.json             # written by ml/train/continuous.py
  .continuous_state.json              # partitions already consumed by retraining
```

## Schema

Feature columns are the raw ml lane contract
(`ml/data/synthetic_nigeria.py: NUMERIC_FEATURES / CATEGORICAL_FEATURES`); the
serving stack (`mlops/serving/aml_service.py`) encodes them at request time
with `vocab.json` + `preprocess.npz` from the artifact dir.

| column | type | source | notes |
|---|---|---|---|
| transaction_id | string | DB / scoring | unique transaction key |
| customer_id | string | DB / scoring | routing/bucketing key; salted-SHA256 pseudonym (`pii_*`) by default |
| ts | timestamp (UTC) | DB | transaction time |
| amount | double | DB | NGN amount |
| currency, country_code, transaction_type | string | DB | lineage |
| log_amount, hour, dow, is_month_end, is_market_day, amount_vs_sender_avg, sender_txns_24h, sender_unique_receivers_72h, receiver_fanin_72h, mins_since_last_txn, device_emulator, sim_swap_7d, new_device, cross_state, cross_bank, is_night | double | feature pipeline | NUMERIC_FEATURES (raw, unscaled) |
| channel, sender_bank, receiver_bank, sender_state, device_os | string | feature pipeline | CATEGORICAL_FEATURES (raw strings; vocab-encoded at train/serve time) |
| risk_score | double | scoring service | model output probability in [0,1] |
| is_fraud | int (nullable) | investigators | 1 = confirmed fraud, 0 = legit, NULL = unlabeled |
| label_source | string (nullable) | investigators | e.g. `investigator`, `chargeback`, `synthetic_demo` |
| processing_purpose | string | export.py | purpose-limitation metadata (default `fraud_detection_model_training`) |
| lawful_basis | string | export.py | NDPA lawful-basis metadata (default `legitimate_interest`) |
| pii_redacted | bool | export.py | true when direct identifiers were pseudonymized |

## NDPA / PII controls

`export.py` pseudonymizes direct customer identifiers (`customer_id`) by
default with a salted SHA-256 (`LAKEHOUSE_PII_SALT` env, default
`fraudfusion-lakehouse-v1` — set a real secret in shared environments) and
stamps every row with `processing_purpose` / `lawful_basis` / `pii_redacted`
metadata for purpose-limitation enforcement (NDPA). Raw identifiers are
written only with the explicit opt-in:

```bash
python mlops/lakehouse/export.py --start 2026-01-01 --end 2026-01-07 \
    --include-pii --purpose fraud_investigation --lawful-basis legal_obligation
```

`--include-pii` logs a loud WARNING; use it only with a documented lawful
basis and restrict access to the resulting partitions.

## Writers / readers

- `export.py` — extracts `aml_scored_transactions` from Postgres
  (`DATABASE_URL`, query overridable via `EXPORT_QUERY`) into daily
  partitions, or `--synthetic` demo mode with no DB.
- `ingest_labels.py` — merges investigator feedback (CSV/JSON file or
  `LABEL_QUERY` against Postgres) into partitions by `transaction_id`
  (fills `is_fraud`).
- `mlops/monitoring/drift.py` — PSI/KS per numeric feature + `risk_score`
  vs a reference window.
- `mlops/monitoring/performance.py` — rolling precision/recall/F1 on labeled rows.
- `ml/train/continuous.py` (ml lane) — consumes `transactions/dt=*` for
  retraining; writes `promotion_decision.json`.
- `mlops/ray/ray_train.py` — distributed training over the same layout.

Labels lag scores; unlabeled rows keep `is_fraud = NULL` until investigator
feedback arrives via `ingest_labels.py`.
