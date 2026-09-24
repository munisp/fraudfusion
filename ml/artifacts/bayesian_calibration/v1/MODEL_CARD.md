# Model Card: bayesian_calibration (v1)

Bayesian logistic recalibration of `fraud_net/v3` raw fraud scores.

- **Fit data**: validation split of synthetic_nigeria transactions
  (n=10284, base rate 0.0344) — provenance: **synthetic**.
- **Model**: logit(p_cal) = a·logit(s_raw) + b; priors a~N(1,1), b~N(0,1).
- **Inference**: nuts_lite (ml.bayesian.mcmc, 4 chains ×
  2000 samples, burn 1000).
  Production may swap in NumPyro; artifact contract = posterior.npz samples.

## Posterior

| Param | Mean | SD | 95% CI | R-hat | ESS |
|---|---|---|---|---|---|
| a | 1.0970 | 0.0480 | [1.0046, 1.1914] | 1.0044 | 883 |
| b | 0.3555 | 0.1540 | [0.0567, 0.6617] | 1.0061 | 688 |

## Calibration metrics (in-sample on validation split)

| Metric | Before | After |
|---|---|---|
| ECE (15 bins) | 0.0026 | 0.0024 |
| Brier | 0.0218 | 0.0216 |
| NLL | 0.1015 | 0.1013 |

## Limitations

- Fit on synthetic data only; recalibrate on real labelled traffic before
  production use.
- Metrics above are in-sample (same validation split used for fitting);
  expect mild optimism.
- Credible intervals reflect parameter uncertainty only, not model
  misspecification.
