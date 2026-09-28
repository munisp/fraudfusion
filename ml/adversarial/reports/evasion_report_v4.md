# fraud_net evasion robustness report

- Model: `fraud_net` `v4` (artifact `ml/artifacts/fraud_net/v4`)
- Eval set: held-out test split, n=4000, fraud base rate=0.0275
- Perturbation budget: L_inf in standardized (z-score) feature space; categorical features held fixed
- Feature-space constraints enforced: per-feature plausibility box (amounts stay positive, hour in [0,23], velocities non-negative), binary flags snapped to {0,1} (see `FEATURE_BOUNDS_RAW` in `ml/adversarial/evasion_eval.py`)
- ART engine: not installed — torch hand-rolled reference implementation used (ART adapter ships in this module as an optional engine)

## Clean baseline

- AUC-PR: **0.4157** | AUC-ROC: 0.7848
- Fraud txns scoring >= review threshold (0.3): 28
- Fraud txns scoring >= block threshold (0.8): 8

## Adversarial results

| engine | attack | eps | AUC-PR | AUC-ROC | evasion@0.3 | evasion@0.8 | mean Linf (z) |
|---|---|---|---|---|---|---|---|
| torch | fgsm | 0.0 | 0.4157 | 0.7848 | 0.000 (0/28) | 0.000 (0/8) | 0.000 |
| torch | fgsm | 0.1 | 0.3936 | 0.7619 | 0.107 (3/28) | 0.125 (1/8) | 0.100 |
| torch | fgsm | 0.25 | 0.3484 | 0.7296 | 0.214 (6/28) | 0.125 (1/8) | 0.250 |
| torch | fgsm | 0.5 | 0.2615 | 0.6785 | 0.321 (9/28) | 0.250 (2/8) | 0.500 |
| torch | fgsm | 1.0 | 0.1237 | 0.5868 | 0.643 (18/28) | 0.250 (2/8) | 1.000 |
| torch | pgd | 0.0 | 0.4157 | 0.7848 | 0.000 (0/28) | 0.000 (0/8) | 0.000 |
| torch | pgd | 0.1 | 0.3935 | 0.7616 | 0.107 (3/28) | 0.125 (1/8) | 0.100 |
| torch | pgd | 0.25 | 0.3466 | 0.7279 | 0.214 (6/28) | 0.125 (1/8) | 0.250 |
| torch | pgd | 0.5 | 0.2559 | 0.6720 | 0.321 (9/28) | 0.250 (2/8) | 0.500 |
| torch | pgd | 1.0 | 0.1128 | 0.5513 | 0.643 (18/28) | 0.250 (2/8) | 0.999 |

## Reading

- `evasion@0.3` = fraction of fraud transactions that were flagged for review/block on clean features but dropped below the review threshold after perturbation (successful evasions).
- AUC-PR under attack is computed over the full test set with every example adversarially perturbed (worst-case evaluation).
- **Worst case observed**: torch/fgsm at eps=1.0 evaded 64.3% of flagged fraud and cut AUC-PR from 0.4157 to 0.1237.

Post-defense re-evaluation and residual risk: see `ml/adversarial/reports/defenses_report.md`.
