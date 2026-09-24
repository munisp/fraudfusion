# Model Card: fraud_net (v2)

- **Training data**: synthetic drift slice (post-period simulation) (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| champion_auc_pr | 0.7164 |
| champion_auc_roc | 0.8943 |
| champion_f1 | 0.6468 |
| champion_base_rate | 0.0608 |
| champion_recall_at_fpr_0.01 | 0.6471 |
| finetuned_auc_pr | 0.7374 |
| finetuned_auc_roc | 0.8862 |
| finetuned_f1 | 0.6800 |
| finetuned_base_rate | 0.0608 |
| finetuned_recall_at_fpr_0.01 | 0.6863 |
| base_version | v1 |
| out_version | v2 |
| drift_slice_size | 12579 |
| seed | 42 |
| improved | True |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready. Fine-tuned from v1 champion weights.
