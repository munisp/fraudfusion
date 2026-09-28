# National Fraud Intelligence — hierarchical Bayesian aggregation for Nigeria

**Question answered:** *"Using MCMC, can we build local intelligence of the
country Nigeria?"* — Yes. This layer aggregates weekly fraud signals from
every state into **local** (state/LGA) and **national** intelligence with
honest uncertainty, served by `intel-service` (:8500) and archived in the
`intel_*` tables.

## Why MCMC / hierarchical Bayes (and not dashboards of raw rates)

1. **Partial pooling beats raw rates.** A raw fraud rate for a small
   northern LGA ("3 frauds of 90 transactions = 3.3%") is statistically
   meaningless. A hierarchical Bayesian model lets every state/LGA borrow
   strength from the national and state averages: sparse jurisdictions are
   pulled (shrunk) toward the parent mean, and their credible intervals
   **widen honestly** instead of pretending precision. Dense jurisdictions
   (Lagos, Abuja, Rivers, Kano) are informed by millions of transactions
   and barely move — the data, not the prior, decides.
2. **Intervals instead of point lies.** Every number the API serves is a
   posterior distribution: mean + 95% credible interval, plus direct
   probability statements a regulator actually asks for, e.g.
   *P(Rivers' fraud rate exceeds the national mean) = 1.00*.
3. **MCMC = full posterior, diagnostics included.** We sample the exact
   posterior with NUTS-lite (dual-averaging HMC in `ml/bayesian/mcmc.py`),
   in a Laplace-whitened parameterisation, and ship split R-hat and ESS
   convergence diagnostics in `metrics.json` (shipped v1: max R-hat ≤ 1.004
   on all four sub-models, min ESS ≥ 1400). If the sampler had not
   converged, the artifact would say so — that is the point of MCMC done
   properly.
4. **Regulator-grade aggregation without PII (NDPA-safe by construction).**
   The model only ever sees weekly *counts* per state/LGA/zone. No customer
   record enters the pipeline. The serving layer additionally suppresses any
   aggregate cell with fewer than 30 weekly transactions
   (`suppressed: true`, k-anonymity style).

## The four coupled models

| # | Model | Question it answers |
|---|---|---|
| 1 | Hierarchical per-state fraud-rate model (37 jurisdictions: 36 states + FCT, centered logit-normal partial pooling) | How hot is each state, with honest intervals? |
| 2 | LGA-level partial pooling (pilots: Lagos 20 LGAs, Kano 44, FCT 6 area councils) | Which LGAs drive a state — and which are too sparse to tell? |
| 3 | Typology-mix model (Dirichlet-multinomial per geopolitical zone, 8 typologies) | Is the North-West really sim-swap/agent-fraud heavy while the South-West runs ATO/crypto? |
| 4 | Temporal national intensity (52-week random walk + 4-week posterior predictive forecast) | Is national fraud rising, and what do next month's weekly rates look like, with intervals? |

Training: `python -m ml.train.train_national_intel --version v1`
(~4 minutes on CPU). Artifacts: `ml/artifacts/national_intelligence/v1/`
(posterior.npz + per-submodel npz + summaries.json + metrics.json +
MODEL_CARD.md).

## Serving

`services/python/intel-service` (FastAPI, port 8500) loads the artifact and
serves:

- `GET /v1/intel/national/summary` — national fraud-rate posterior mean + 95% CI, week trend, top typologies, 4-week forecast
- `GET /v1/intel/states` — all 37 states ranked, credible intervals, P(above national)
- `GET /v1/intel/states/{code}` — state detail incl. LGA table for pilot states (sparse cells suppressed)
- `GET /v1/intel/hotspots?k=10` — posterior-ranked hotspots with P(exceeds threshold)
- `GET /v1/intel/typology-mix` — per-zone mix with intervals
- `GET /v1/intel/brief` — markdown National Fraud Intelligence Brief

**Fail-closed:** if the artifact is missing, `/health` is 503 and every
endpoint is 503 — intelligence consumers never unknowingly read fabricated
numbers.

## Who consumes it

- **Regulators / law enforcement** (CBN, NFIU, EFCC): the weekly brief —
  national estimate, hotspots, zone typology shifts, forecast — with
  intervals they can defend.
- **Bank CROs**: benchmark their own state-level fraud mix against the
  national posterior; spot zone-level typology shifts early.
- **Tenant risk teams**: hotspot ranking with P(exceeds threshold) to focus
  investigator queues where the posterior — not a noisy raw rate — says
  risk is elevated.

## Refresh cadence

Weekly refit via continuous training (`ml/train/continuous.py`):
`intel_state_weekly` / `intel_lga_weekly` / `intel_typology_weekly` are
appended from the streaming layer, the four models refit end-to-end
(~4 min), diagnostics are re-validated, and the new artifact version is
promoted. Each brief is archived in `intel_briefs` for audit.

## Limitations (honest)

- **Synthetic training data.** Until real feeds land in the `intel_*`
  tables, the generator (`synth_nigeria`, seeded, assumptions documented in
  code and MODEL_CARD.md) stands in. Absolute levels are **not** observed
  Nigerian fraud rates. Regional patterns (urban-south ATO/investment skew,
  rural-north agent/USSD skew) are documented modelling assumptions, not
  measured facts.
- **Reporting bias.** The model estimates *reported/detected* fraud.
  States with weaker detection look safer than they are; the posterior
  cannot fix blind spots in the feeds.
- **Ecological fallacy.** State/zone/LGA aggregates describe regions, not
  people. Never use them to score an individual customer.
- **Suppression hides sparse cells.** A suppressed LGA is not a safe LGA —
  it is an unknown one. Treat `suppressed: true` as "insufficient data".
