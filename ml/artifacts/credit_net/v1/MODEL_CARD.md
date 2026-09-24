# Model Card: credit_net (v1)

- **Training data**: synthetic_nigeria credit bureau-style data (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| auc_pr | 0.6494 |
| auc_roc | 0.7503 |
| f1 | 0.5646 |
| base_rate | 0.2883 |
| recall_at_fpr_0.01 | 0.2197 |
| epochs_trained | 16 |
| seed | 42 |
| score_example | 495.9000 |
| bust_out_capture_at_20pct_review | 0.0000 |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready.
