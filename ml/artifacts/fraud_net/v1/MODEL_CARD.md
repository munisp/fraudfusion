# Model Card: fraud_net (v1)

- **Training data**: synthetic_nigeria transactions (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| auc_pr | 0.4211 |
| auc_roc | 0.7147 |
| f1 | 0.4900 |
| base_rate | 0.0389 |
| recall_at_fpr_0.01 | 0.4162 |
| val_auc_pr | 0.4462 |
| temperature | 0.4543 |
| epochs_trained | 15 |
| seed | 42 |
| backend | torch |
| n_train | 42891 |
| n_test | 9205 |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready.
