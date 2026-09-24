# Model Card: gnn_mule (v2)

- **Training data**: synthetic_nigeria account-transaction graph (split-aware snapshots) (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| auc_pr | 1.0000 |
| auc_roc | 1.0000 |
| f1 | 0.1758 |
| base_rate | 0.0133 |
| recall_at_fpr_0.01 | 1.0000 |
| backend | pure-torch SAGELayer |
| epochs_trained | 40 |
| seed | 42 |
| n_nodes | 4000 |
| n_edges_train | 47543 |
| n_edges_test | 68166 |
| mule_prevalence | 0.0133 |
| n_train_nodes | 2800 |
| n_test_nodes | 600 |
| leakage_fix | split-aware graph snapshots (edges+features masked by split cutoff) + node-level label holdout 70/15/15 + scaler fit on train-window train nodes only |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready. Backend: pure-torch SAGELayer (weights.pt loads WITHOUT torch_geometric). Trained on train-window graph only; scaler in preprocess.npz applied at inference.
