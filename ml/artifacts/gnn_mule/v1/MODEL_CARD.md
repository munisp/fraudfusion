# Model Card: gnn_mule (v1)

- **Training data**: synthetic_nigeria account-transaction graph (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| auc_pr | 0.9944 |
| auc_roc | 0.9999 |
| f1 | 0.9043 |
| base_rate | 0.0130 |
| recall_at_fpr_0.01 | 1.0000 |
| backend | torch_geometric.SAGEConv |
| epochs_trained | 56 |
| seed | 42 |
| n_nodes | 4000 |
| n_edges | 61220 |
| mule_prevalence | 0.0130 |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready. Backend: torch_geometric.SAGEConv.
