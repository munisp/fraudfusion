# Model Card: national_intelligence (v1)

Hierarchical Bayesian (MCMC) aggregation of fraud signals into LOCAL and
NATIONAL fraud intelligence for Nigeria: 37-jurisdiction partial-pooling
fraud-rate model, LGA-level pooling for 3 pilot states, per-zone
Dirichlet-multinomial typology mixes, and a 52-week random-walk national
intensity with a 4-week posterior predictive forecast.

- **Data**: synthetic seeded Nigeria generator (seed=42, 52 weeks, national weekly txns ~3,000,000 platform-observable) — provenance: **synthetic** (no real NIBSS/NFIU feed).
- **Inference**: nuts_lite (ml.bayesian.mcmc), 4 chains x
  1200 kept samples per model. Total fit 244s.
- **Serving contract**: summaries.json aggregates only; intel-service
  suppresses cells with n<30 (k-anonymity); no PII anywhere in the pipeline.

## Convergence diagnostics

| Sub-model | max R-hat | min ESS | fit time |
|---|---|---|---|
| state_model | 1.0031 | 2238 | 52s |
| lga_model | 1.0021 | 2197 | 66s |
| typology_model | 1.0032 | 1658 | 66s |
| temporal_model | 1.0021 | 2345 | 60s |

## National estimate

- Annual-average weekly fraud rate (state hierarchy): posterior mean
  0.0087, 95% CI
  [0.0078, 0.0096]
  (trend: rising; the current week runs hotter
  than the annual average — see forecast below, which continues from the
  latest week of the temporal model)
- Top typologies nationally: mule_ring, account_takeover, investment, sim_swap

## Top-5 states by posterior mean fraud rate

| State | Posterior mean | 95% CI | P(above national) |
|---|---|---|---|
| rivers | 0.0181 | [0.0180, 0.0182] | 1.00 |
| lagos | 0.0148 | [0.0147, 0.0148] | 1.00 |
| edo | 0.0140 | [0.0139, 0.0141] | 1.00 |
| abuja_fct | 0.0134 | [0.0134, 0.0135] | 1.00 |
| bayelsa | 0.0116 | [0.0114, 0.0118] | 1.00 |

## 4-week forecast (national weekly fraud rate)

| Horizon | Mean | 95% CI |
|---|---|---|
| +1wk | 0.0167 | [0.0149, 0.0186] |
| +2wk | 0.0167 | [0.0143, 0.0194] |
| +3wk | 0.0167 | [0.0138, 0.0201] |
| +4wk | 0.0168 | [0.0134, 0.0206] |

## Limitations

- Trained on synthetic data with documented assumptions; absolute levels are
  NOT real-world Nigerian fraud rates until real feeds are wired in.
- Binomial likelihood assumes reported fraud; reporting bias (some states
  detect/report better) enters the estimates directly.
- State/zone aggregates must not be projected onto individuals
  (ecological fallacy).
