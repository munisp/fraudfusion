# fraud_net post-defense evasion report

- Attack: constrained PGD (steps=20), torch engine — L_inf in standardized (z-score) feature space
- Eval set: held-out test split, n=4000, base rate=0.0275
- Ensemble blend: 0.5*model + 0.5*rules
- Smoothing: 25 draws, sigma=0.1

## Defenses evaluated

- **none** — undefended baseline (PGD, constrained)
- **clip_quantize** — clamp +/-5 sigma, quantize to 0.05-sigma grid, snap binary flags
- **ensemble_rules** — blend: 0.5*model + 0.5*rule_score (non-differentiable rules)
- **smoothing** — mean prob over 25 N(0, 0.1) noise draws (smoothing-lite)
- **adversarial_training** — *not executed here* (retraining lives in `ml/train`, outside this module's scope). Recommended: augment fraud_net training with PGD-generated examples using the exact constraint projection in `evasion_eval.project_constraints` so the model sees only physically plausible adversarial transactions.

## Results (AUC-PR / evasion success under constrained PGD)

| defense | eps | AUC-PR | AUC-ROC | evasion@0.3 | evasion@0.8 |
|---|---|---|---|---|---|
| none | 0.0 | 0.4329 | 0.7960 | 0.000 (0/39) | 0.000 (0/18) |
| none | 0.25 | 0.3397 | 0.6731 | 0.077 (3/39) | 0.056 (1/18) |
| none | 0.5 | 0.2298 | 0.5559 | 0.231 (9/39) | 0.333 (6/18) |
| none | 1.0 | 0.0813 | 0.3387 | 0.513 (20/39) | 0.611 (11/18) |
| clip_quantize | 0.0 | 0.4052 | 0.7902 | 0.000 (0/36) | 0.000 (0/11) |
| clip_quantize | 0.25 | 0.2843 | 0.6628 | 0.139 (5/36) | 0.091 (1/11) |
| clip_quantize | 0.5 | 0.1440 | 0.5371 | 0.361 (13/36) | 0.545 (6/11) |
| clip_quantize | 1.0 | 0.0197 | 0.2922 | 0.694 (25/36) | 0.909 (10/11) |
| ensemble_rules | 0.0 | 0.4257 | 0.7930 | 0.000 (0/37) | 0.000 (0/4) |
| ensemble_rules | 0.25 | 0.3462 | 0.6707 | 0.189 (7/37) | 0.000 (0/4) |
| ensemble_rules | 0.5 | 0.2477 | 0.5536 | 0.324 (12/37) | 0.000 (0/4) |
| ensemble_rules | 1.0 | 0.0914 | 0.3484 | 0.676 (25/37) | 0.000 (0/4) |
| smoothing | 0.0 | 0.4323 | 0.7961 | 0.000 (0/39) | 0.000 (0/18) |
| smoothing | 0.25 | 0.3414 | 0.6737 | 0.077 (3/39) | 0.056 (1/18) |
| smoothing | 0.5 | 0.2302 | 0.5541 | 0.205 (8/39) | 0.333 (6/18) |
| smoothing | 1.0 | 0.0817 | 0.3401 | 0.513 (20/39) | 0.611 (11/18) |

## Residual risk

- Undefended worst-case evasion@0.3: **51.3%** at eps=1.0 (AUC-PR 0.0813).
- eps=0.0: best defense = **clip_quantize**, residual evasion@0.3 = 0.0%, AUC-PR 0.4052.
- eps=0.25: best defense = **smoothing**, residual evasion@0.3 = 7.7%, AUC-PR 0.3414.
- eps=0.5: best defense = **smoothing**, residual evasion@0.3 = 20.5%, AUC-PR 0.2302.
- eps=1.0: best defense = **smoothing**, residual evasion@0.3 = 51.3%, AUC-PR 0.0817.

Residual-risk notes:

1. **Adaptive attackers remain.** All defenses except the rule ensemble are differentiable or noise-averaged; BPDA/Expectation-over-Transformation attacks can partially bypass gradient masking. The rule ensemble is gradient-free but its thresholds are probed easily — treat it as a cost-raiser, not a guarantee.
2. **Clean-accuracy cost.** Quantization and smoothing degrade clean AUC-PR; the tables above quantify the trade-off per defense.
3. **Feature-recapture risk.** A fraudster who cannot perturb features enough may instead change behaviour so the *raw* features look benign (low velocity, aged devices, no fan-in). Defenses here only cover numeric perturbation, not behavioural mimicry; that is covered by the velocity/rule layer and GNN mule detection.
4. **Next steps.** Adversarial training with the constrained PGD above; certify with randomized smoothing at the review threshold; re-run this evaluation on every model promotion (wire into registry promotion gates).
