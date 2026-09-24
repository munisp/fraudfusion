# Feeding real Nigerian transaction data into the FraudFusion ML pipeline

This document is the end-to-end recipe for validating and retraining the ML
models on **real** data instead of the shipped synthetic generator
(`ml/data/synthetic_nigeria.py`).

## 1. Canonical transaction schema

All training/validation code consumes this schema (parquet or CSV):

| Column | Type | Required | Notes |
|---|---|---|---|
| `ts` | datetime64 | yes | transaction timestamp (UTC) |
| `sender_id` / `receiver_id` | str | yes | **pseudonymised** account IDs (see §3) |
| `amount_ngn` | float (2dp) | yes | kobo-rounded NGN amount |
| `channel` | str | yes | one of `ussd, pos, mobile_app, web, nip, agent` |
| `sender_bank` / `receiver_bank` | str | yes | bank name (must match model vocab or map to `unknown`) |
| `sender_state` / `receiver_state` | str | yes | Nigerian state |
| `device_os` | str | yes | `android, ios, feature_phone, web_browser, pos_terminal` |
| `is_fraud` | 0/1 | yes | confirmed label (investigator outcome / chargeback) |
| `fraud_typology` | str | recommended | free text (`mule_fanin`, `sim_swap_ato`, …) |
| `fee_ngn` | float | optional | ₦50 EMT levy on ≥₦10,000; POS 0.5% capped ₦2,000 |
| `agent_id` / `cash_direction` / `agent_float_after` | — | optional | agent-banking semantics |
| `ussd_session_id` / `session_duration_s` / `failed_pin_attempts` | — | optional | USSD session semantics |
| `label_available_at` | datetime64 | recommended | when the label was confirmed; training must exclude rows whose label is not yet available |

Behavioural features (`log_amount`, `sender_txns_24h`, …) are recomputed by
`ml.data.synthetic_nigeria.add_behavioral_features` — do not precompute them.

## 2. NDPA pseudonymisation requirement (non-negotiable)

Real customer identifiers (account numbers, BVN, NIN, phone) **must not**
enter the ML training path. Follow the existing lakehouse pattern
(`mlops/lakehouse/export.py`):

- `customer_id`/sender/receiver = salted SHA-256 (`pii_<hash>`) with the salt
  kept in the secrets manager, never in the repo or the training data dir.
- Stamp every export with `processing_purpose`, `lawful_basis`,
  `pii_redacted=true` per NDPA.
- Raw names/phones/BVNs stay in the operational DB; only pseudonyms and
  coarse attributes (state, age band) cross into the lakehouse.

## 3. Ingestion paths

### 3a. Production Postgres → lakehouse (preferred)

```bash
export LAKEHOUSE_DIR=mlops/data/lakehouse
python -m mlops.lakehouse.export --pg-dsn "$PG_DSN" --from 2024-01-01 --to 2024-06-30
# labels (investigator outcomes), honouring label lag:
python -m mlops.lakehouse.ingest_labels --labels-csv confirmed_labels.csv
```

### 3b. Public datasets (schema-compatibility checks)

PaySim and IEEE-CIS require a Kaggle account and are **not** auto-downloaded.
Exact instructions are printed by the adapters when the file is missing:

```bash
python -m ml.validation.backtest --dataset paysim  --file /path/PS_20174392719_1491204439457_log.csv
python -m ml.validation.backtest --dataset ieee-cis --file /path/train_transaction.csv
```

Caveat: public datasets lack most Nigerian/behavioural features (mapped as
`unknown`/zeros). Metrics from them are plumbing checks only.

## 4. Validate (temporal replay)

```bash
python -m ml.validation.validation_report \
    --dataset synthetic --file mlops/data/lakehouse/transactions \
    --model-version v3 --window 7D --cost-fp 500 \
    --out validation_report.md
```

This replays windows in time order, tunes the alert threshold on the earliest
windows (cost model: ₦500 per false alert vs median fraud amount per missed
fraud), freezes it, and reports per-window precision/recall/alert volume.

## 5. Retrain + promote

```bash
export FRAUDFUSION_DATA=<parquet dir with the schema above>
python -m ml.train.train_fraud --version v4
python -m ml.inference.export_onnx            # refresh ONNX
python -m ml.registry.register register --model fraud_net --artifact-dir ml/artifacts/fraud_net/v4
python -m ml.registry.register promote --model fraud_net --version v4 --stage Staging --alias challenger
# A/B test via mlops/serving/model_router.py, then:
python -m ml.registry.register promote --model fraud_net --version v4 --stage Production --alias champion
```

## 6. Graph / Neo4j (mule detection)

```bash
docker compose -f ml/graph/neo4j.compose.yml up -d   # dev-only fragment
pip install neo4j
NEO4J_PASSWORD=... python -m ml.graph.neo4j_export --data-dir $FRAUDFUSION_DATA
NEO4J_PASSWORD=... python -m ml.graph.neo4j_train --version v3
```

Graph snapshots are built split-aware (train/val/test windows) to avoid
node-feature leakage across time.
