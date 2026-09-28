# Adversarial Training — fraud_net v4

Remediation of the audited caveat "adversarial training documented but not
executed". This document records the method, the **measured** v3-vs-v4
numbers (nothing hand-edited), the gradient-masking (BPDA/EOT) checks, and
the residual risk.

## Method

`ml/adversarial/adv_train.py` performs Madry-style PGD adversarial training:

- **Init**: shipped fraud_net v3 weights (identical architecture, vocab and
  scaler — v4 is a drop-in artifact under the same serving contract).
- **Attack in the loop**: constrained PGD, eps_train=1.0 (L_inf in
  standardized z-score units), 5 steps, generated against the *eval-mode*
  model and projected with the exact plausibility constraints of
  `ml/adversarial/evasion_eval.py` (per-feature raw bounds, binary flags
  snapped to {0,1}).
- **Loss**: `FocalLoss(clean) + 0.5 * FocalLoss(adversarial)`, AdamW
  lr=1e-3, batch 2048, 6 epochs (early stop), seed 42. Training runtime:
  **16 s** (CPU). Temperature re-fit on the validation split after training
  (calibration is part of the deployed score).
- A milder config (eps_train=0.5) was also trained and measured: it kept
  clean AUC-PR (0.4298) but was *more* evadable at eps=1.0 (72.2%) — a
  known property of small-budget robustness — so the eps_train=1.0 model
  was shipped as v4. (Config discarded; numbers here for the record.)

Artifacts: `ml/artifacts/fraud_net/v4/` (weights.pt, model.onnx, vocab.json,
preprocess.npz, metrics.json, MODEL_CARD.md). Eval harness: the pre-existing
`ml/adversarial/evasion_eval.py`, torch engine, held-out test split,
n=4000 subset (same as the v3 report).

## Measured results (v3 vs v4)

Clean (full test split, n=10339):

| metric | v3 | v4 | delta |
|---|---|---|---|
| AUC-PR | 0.4006 | 0.3727 | **-0.028** |
| AUC-ROC | 0.7742 | 0.7582 | -0.016 |
| recall@FPR=1% | 0.3734 | 0.3377 | -0.036 |
| temperature | 0.4339 | 0.4243 | — |

Constrained PGD evasion (eval subset n=4000, torch engine; the 79.5% figure
from the v3 audit was the ART engine row — ART not installed here):

| attack | metric | v3 | v4 |
|---|---|---|---|
| PGD eps=1.0 | AUC-PR under attack | 0.0811 | **0.1128** |
| PGD eps=1.0 | evasion@0.3 (review) | 51.3% (20/39) | **64.3% (18/28)** — worse |
| PGD eps=1.0 | evasion@0.8 (block) | 61.1% (11/18) | **25.0% (2/8)** — better |
| PGD eps=0.5 | AUC-PR under attack | 0.2289 | **0.2559** |
| PGD eps=0.5 | evasion@0.3 | 23.1% (9/39) | 32.1% (9/28) — worse |
| PGD eps=0.25 | evasion@0.3 | 7.7% (3/39) | 21.4% (6/28) — worse |

Full grids: `ml/adversarial/reports/evasion_report.md` (v3) and
`evasion_report_v4.md` (v4).

### Honest reading

Adversarial training **hardened the high-confidence region**: at the block
threshold (0.8) evasion fell from 61% to 25%, and ranking under attack
(under-attack AUC-PR) improved at every epsilon. But it **did not lower —
and at the review threshold (0.3) raised — the evasion rate**, partly
because v4 flags fewer fraud transactions clean at 0.3 (28 vs 39), and
clean AUC-PR dipped ~0.02-0.03. On this synthetic, weak-base-rate problem,
PGD-eps=1.0 adversarial training is **not a clear win**; treat v4 as a
hardened-block candidate behind the registry's champion/challenger gate,
not an automatic promotion.

## Gradient masking: BPDA-lite and EOT

The smoothing defense (mean of 25 noisy forward passes, sigma=0.1, from
`ml/adversarial/defenses.py`) was re-checked with adaptive attacks
(`evaluate_gradient_masking`, n=2000):

- **BPDA-lite**: identity-approximation gradient — the perturbation is plain
  PGD (gradient through the raw model), success measured against the
  smoothed score.
- **EOT** (implemented, small-sample): differentiates through the mean of
  10 noisy forward passes per PGD step — the correct adaptive gradient for
  the randomized transform.

| model | eps | BPDA-lite evasion@0.3 | EOT evasion@0.3 |
|---|---|---|---|
| v3 | 0.5 | 21.7% | 21.7% |
| v3 | 1.0 | 52.2% | 52.2% |
| v4 | 0.5 | 20.0% | 20.0% |
| v4 | 1.0 | 60.0% | 60.0% |

EOT == BPDA-lite == oblivious PGD everywhere: at sigma=0.1 the smoothing
transform is so mild that its gradient is essentially the raw gradient, so
**the defense provides no gradient-masking advantage to exploit — and also
little real protection**. If sigma is ever raised, EOT must be re-run (that
is where masking would appear). EOT is therefore not "N/A" — it is
implemented (`defenses.eot_pgd`) and shows the masking gap is ~0 at the
shipped noise level.

## Residual risk

1. **Evasion is reduced at the block threshold, not eliminated, and worse
   at the review threshold.** An adaptive fraudster with eps>=1.0 still
   evades a quarter of block-level fraud and ~2/3 of review-level fraud.
2. **Clean-performance cost is real** (-0.028 AUC-PR): promotion of v4 must
   go through the champion/challenger experiment, not automatic rollout.
3. **Attack scope**: only numeric-feature perturbation within plausibility
   bounds, single attacker knowledge level (white-box). Behavioural mimicry
   (making raw features benign) remains covered by the velocity/rule layer
   and the GNN mule detector, not by this defense.
4. **Synthetic data only**: all numbers are on the synthetic_nigeria
   generator with ~2% label noise; real-traffic robustness is unvalidated.
5. **Re-run on every promotion**: `evasion_eval`, `defenses` (incl.
   BPDA/EOT) and `adv_train` are deterministic given seed; wire them into
   the registry promotion gate as a follow-up.

## Reproduce

```bash
python -m ml.adversarial.adv_train --epochs 6 --pgd-steps 5 --eps-train 1.0
python -m ml.adversarial.evasion_eval --version v4 --engine torch
python - <<'EOF'
from ml.adversarial.defenses import evaluate_gradient_masking
evaluate_gradient_masking("v4", max_samples=2000, epsilon_grid=(0.5, 1.0))
EOF
```
