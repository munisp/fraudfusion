# Model Card: mule_ring_posterior (v1)

Bayesian logistic posterior over "account belongs to an active mule ring",
combining `gnn_mule/v2` node scores with graph topology statistics
(fan-in, incident count, pass-through balance). Every account gets a
probability plus a 95% credible interval.

- **Fit data**: full synthetic graph snapshot (4000 accounts,
  54 mules) — provenance: **synthetic**.
- **Inference**: nuts_lite (ml.bayesian.mcmc), 4 chains ×
  3000 samples. Production may swap in NumPyro.
- **Priors**: b0 ~ N(logit(base_rate), 1), w_gnn ~ N(1, 0.5),
  w_topo ~ N(0, 0.5); logit(s_gnn) capped at ±6 (quasi-separation guard).

## Posterior over weights

| Param | Mean | SD | R-hat | ESS |
|---|---|---|---|---|
| b0 | -8.2553 | 0.7015 | 1.0280 | 168 |
| w_gnn | 1.2709 | 0.1408 | 1.0077 | 407 |
| w_fanin | 0.2840 | 0.3457 | 1.0192 | 326 |
| w_incident_count | 0.3246 | 0.3646 | 1.0171 | 316 |
| w_passthrough | 0.2881 | 0.2721 | 1.0008 | 1015 |

## Discrimination (in-sample, synthetic labels)

| Metric | GNN score only | Posterior mean |
|---|---|---|
| AUC-ROC | 0.9998 | 0.9990 |
| AUC-PR | 0.9867 | 0.9119 |

Mean 95% CI width: 0.0109 overall,
0.3808 on true mules.

## Limitations

- Fit on synthetic ground truth; on production data labels are delayed and
  noisy — recalibrate before acting on the credible intervals.
- In-sample discrimination metrics; the GNN base score already encodes most
  of the signal, so gains are expected to be modest — the value is the
  uncertainty quantification, not AUC.
