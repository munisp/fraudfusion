# Model Card: fraud_net (v3)

- **Training data**: synthetic_nigeria transactions (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| auc_pr | 0.4006 |
| auc_roc | 0.7742 |
| f1 | 0.4773 |
| base_rate | 0.0298 |
| recall_at_fpr_0.01 | 0.3734 |
| val_auc_pr | 0.4848 |
| temperature | 0.4339 |
| epochs_trained | 19 |
| seed | 42 |
| backend | torch |
| n_train | 47543 |
| n_test | 10339 |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready.
## Version comparison (all versions re-evaluated on the dataset-v2 test split)

| Version | Training data | AUC-PR | AUC-ROC | F1 | recall@1% FPR |
|---|---|---|---|---|---|
| v1 | dataset v1 | 0.329 | 0.696 | 0.383 | 0.318 |
| v2 | v1 + drift-slice finetune | 0.387 | 0.744 | 0.451 | 0.357 |
| **v3** | **dataset v2 (agent float / POS fees / USSD sessions / salary-day / label lag)** | **0.401** | **0.774** | **0.477** | **0.373** |

Notes: v1/v2 were originally evaluated on dataset v1 (metrics in their own
metrics.json); the numbers above are re-computed on the v2 test split for a
like-for-like comparison. Base rate 2.98%; ~2% label noise by design caps
achievable precision.
