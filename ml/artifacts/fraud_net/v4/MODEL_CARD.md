# Model Card: fraud_net (v4) — adversarially trained

- **Training data**: synthetic_nigeria transactions (provenance: **synthetic** — no real fraud data)
- **Init**: fraud_net `v3` weights (same architecture, vocab, scaler — drop-in compatible artifact contract)
- **Method**: constrained PGD adversarial training (eps_train=1.0 z-score L_inf, 5 steps, adv_weight=0.5), temperature re-fit on val
- **Framework**: PyTorch 2.8.0+cu128 (CPU), 6 epochs, runtime 16.3s

## Clean metrics (held-out test split)

| Metric | Value |
|---|---|
| AUC-PR | 0.3727 |
| AUC-ROC | 0.7582 |
| F1 | 0.3098 |
| recall@FPR=1% | 0.3377 |
| temperature | 0.4243 |

## Evasion robustness (existing harness, constrained PGD, eps=1.0)

| Metric | Value |
|---|---|
| AUC-PR under attack | 0.1128 |
| evasion@0.3 (review) | 64.3% |
| evasion@0.8 (block) | 25.0% |

Full grid: `ml/adversarial/reports/evasion_report_v4.md`; v3-vs-v4 comparison + BPDA/EOT gradient-masking checks: `docs/ADVERSARIAL_TRAINING.md`.

## Limitations / residual risk

- Measured outcome is MIXED, not a blanket improvement: vs v3, block-threshold evasion at eps=1.0 dropped (61.1% -> 25.0%) and under-attack AUC-PR rose (0.0811 -> 0.1128), but review-threshold evasion ROSE (51.3% -> 64.3%, on small counts) and clean AUC-PR dipped (0.4329 -> 0.4157 on the eval subset; full-test 0.4006 -> 0.3727). See docs/ADVERSARIAL_TRAINING.md for the full table.
- An adaptive attacker with a larger budget or a different attack (e.g. behaviour-level feature mimicry) is out of scope.
- Trained exclusively on synthetic data; performance on real Nigerian production traffic is unvalidated.
- Fraud labels contain ~2% injected noise by design.
- Gradient-masking defenses (smoothing) evaluated separately with BPDA-lite/EOT — see docs/ADVERSARIAL_TRAINING.md.
