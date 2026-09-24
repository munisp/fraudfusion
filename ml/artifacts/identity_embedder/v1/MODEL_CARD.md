# Model Card: identity_embedder (v1)

- **Training data**: synthetic identity capture pairs (contrastive metric learning) (provenance: **synthetic** — no real fraud data)
- **Framework**: PyTorch 2.8.0+cu128 (CPU)

## Metrics (held-out test split)

| Metric | Value |
|---|---|
| eer | 0.0668 |
| eer_threshold | 0.2360 |
| genuine_mean_sim | 0.5002 |
| impostor_mean_sim | 0.0104 |
| sim_gap | 0.4898 |
| tar_at_far_0.1 | 0.9533 |
| tar_at_far_0.01 | 0.7930 |
| tar_at_far_0.001 | 0.5886 |
| epochs_trained | 21 |
| seed | 42 |
| objective | normalized_softmax |
| proxy_scale | 16.0000 |
| margin | 1.2000 |
| in_dim | 128 |
| embed_dim | 128 |
| n_train_identities | 15000 |
| n_eval_identities | 5000 |
| eval_pairs | 20000 |
| provenance | synthetic |

## Limitations

- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Model is a baseline, not production-ready. Synthetic biometric templates are separable by construction; EER/TAR numbers validate plumbing only. TorchScript model.pt is the drop-in artifact for identity-theft-detector (IDENTITY_MODEL_PATH).
