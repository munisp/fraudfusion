# Model Card: autoencoder (v1)

- **Training data**: synthetic_nigeria legit-only transactions (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| auc_pr | 0.2608 |
| auc_roc | 0.6928 |
| f1 | 0.0932 |
| base_rate | 0.0389 |
| recall_at_fpr_0.01 | 0.2542 |
| epochs_trained | 11 |
| seed | 42 |
| note | trained on legitimate transactions only; score=MSE recon error |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready.
