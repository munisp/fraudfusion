# Model Card: insider_risk (v1)

Hierarchical Bayesian estimate of monthly insider-event rates by department,
with partial pooling (small departments shrink toward the population rate).

- **Data**: synthetic seeded insider-event ledger (8
  departments, one month) — provenance: **synthetic**, no real HR data.
- **Model**: y_d ~ Binomial(n_d, theta_d); logit(theta_d) = alpha + sigma·z_d,
  z_d ~ N(0, 1) (non-centered logit-normal hierarchy); alpha ~ N(-3, 1.5);
  log(sigma) ~ N(-0.5, 0.75).
- **Inference**: nuts_lite (ml.bayesian.mcmc), 4 chains ×
  3000 samples, burn 2500.
  max R-hat 1.0063, min ESS 1017.
  Production may swap in NumPyro; artifact contract = posterior.npz.

## Population

- Population rate sigmoid(alpha): posterior mean 0.0246,
  95% CI [0.0116, 0.0484]
- Dispersion sigma: posterior mean 0.63
  (smaller sigma = stronger pooling toward the population rate)

## Raw vs shrunk rates

| Department | Staff | Events | Raw rate | Posterior mean | 95% CI |
|---|---|---|---|---|---|
| fraud_ops | 120 | 3 | 0.0250 | 0.0245 | [0.0092, 0.0523] |
| treasury | 40 | 1 | 0.0250 | 0.0255 | [0.0063, 0.0648] |
| agent_network | 800 | 13 | 0.0163 | 0.0177 | [0.0091, 0.0287] |
| customer_care | 300 | 5 | 0.0167 | 0.0194 | [0.0079, 0.0359] |
| engineering | 90 | 0 | 0.0000 | 0.0161 | [0.0023, 0.0363] |
| compliance | 25 | 3 | 0.1200 | 0.0506 | [0.0134, 0.1544] |
| field_sales | 12 | 1 | 0.0833 | 0.0357 | [0.0079, 0.1202] |
| executive | 6 | 1 | 0.1667 | 0.0434 | [0.0089, 0.1673] |

## Limitations

- One synthetic month; production use needs real labelled insider events and
  per-department exposure windows.
- Beta-binomial assumes exchangeability within department; role-level
  pooling can be added as another hierarchy level (same toolkit).
