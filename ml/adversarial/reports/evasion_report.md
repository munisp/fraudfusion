# fraud_net evasion robustness report

- Model: `fraud_net` `v3` (artifact `ml/artifacts/fraud_net/v3`)
- Eval set: held-out test split, n=4000, fraud base rate=0.0275
- Perturbation budget: L_inf in standardized (z-score) feature space; categorical features held fixed
- Feature-space constraints enforced: per-feature plausibility box (amounts stay positive, hour in [0,23], velocities non-negative), binary flags snapped to {0,1} (see `FEATURE_BOUNDS_RAW` in `ml/adversarial/evasion_eval.py`)
- ART engine: available — torch hand-roll cross-checked against ART FastGradientMethod / ProjectedGradientDescent

## Clean baseline

- AUC-PR: **0.4329** | AUC-ROC: 0.7960
- Fraud txns scoring >= review threshold (0.3): 39
- Fraud txns scoring >= block threshold (0.8): 18

## Adversarial results

| engine | attack | eps | AUC-PR | AUC-ROC | evasion@0.3 | evasion@0.8 | mean Linf (z) |
|---|---|---|---|---|---|---|---|
| torch | fgsm | 0.0 | 0.4329 | 0.7960 | 0.000 (0/39) | 0.000 (0/18) | 0.000 |
| torch | fgsm | 0.1 | 0.3931 | 0.7474 | 0.000 (0/39) | 0.056 (1/18) | 0.100 |
| torch | fgsm | 0.25 | 0.3404 | 0.6755 | 0.077 (3/39) | 0.056 (1/18) | 0.250 |
| torch | fgsm | 0.5 | 0.2345 | 0.5633 | 0.231 (9/39) | 0.333 (6/18) | 0.500 |
| torch | fgsm | 1.0 | 0.0870 | 0.3846 | 0.513 (20/39) | 0.611 (11/18) | 1.000 |
| torch | pgd | 0.0 | 0.4329 | 0.7960 | 0.000 (0/39) | 0.000 (0/18) | 0.000 |
| torch | pgd | 0.1 | 0.3930 | 0.7470 | 0.000 (0/39) | 0.056 (1/18) | 0.100 |
| torch | pgd | 0.25 | 0.3396 | 0.6734 | 0.077 (3/39) | 0.056 (1/18) | 0.250 |
| torch | pgd | 0.5 | 0.2289 | 0.5541 | 0.231 (9/39) | 0.333 (6/18) | 0.500 |
| torch | pgd | 1.0 | 0.0811 | 0.3397 | 0.513 (20/39) | 0.611 (11/18) | 1.000 |
| art | fgsm | 0.0 | 0.4329 | 0.7960 | 0.000 (0/39) | 0.000 (0/18) | 0.000 |
| art | fgsm | 0.1 | 0.4312 | 0.7980 | 0.000 (0/39) | 0.056 (1/18) | 0.100 |
| art | fgsm | 0.25 | 0.3671 | 0.7970 | 0.103 (4/39) | 0.278 (5/18) | 0.250 |
| art | fgsm | 0.5 | 0.2027 | 0.7465 | 0.410 (16/39) | 0.556 (10/18) | 0.500 |
| art | fgsm | 1.0 | 0.1166 | 0.5589 | 0.769 (30/39) | 0.667 (12/18) | 1.000 |
| art | pgd | 0.0 | 0.4329 | 0.7960 | 0.000 (0/39) | 0.000 (0/18) | 0.000 |
| art | pgd | 0.1 | 0.4311 | 0.7980 | 0.000 (0/39) | 0.056 (1/18) | 0.100 |
| art | pgd | 0.25 | 0.3634 | 0.7968 | 0.128 (5/39) | 0.278 (5/18) | 0.250 |
| art | pgd | 0.5 | 0.1865 | 0.7382 | 0.462 (18/39) | 0.611 (11/18) | 0.500 |
| art | pgd | 1.0 | 0.1094 | 0.5016 | 0.795 (31/39) | 0.667 (12/18) | 1.000 |

## Reading

- `evasion@0.3` = fraction of fraud transactions that were flagged for review/block on clean features but dropped below the review threshold after perturbation (successful evasions).
- AUC-PR under attack is computed over the full test set with every example adversarially perturbed (worst-case evaluation).
- **Worst case observed**: art/pgd at eps=1.0 evaded 79.5% of flagged fraud and cut AUC-PR from 0.4329 to 0.1094.

Post-defense re-evaluation and residual risk: see `ml/adversarial/reports/defenses_report.md`.
