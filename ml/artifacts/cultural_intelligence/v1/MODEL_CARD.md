# Model Card: cultural_intelligence (v1)

MCMC posteriors over Nigeria's culturally-patterned legitimate financial
rhythms — ajo/esusu rotating savings, festive spending calendar, market-week
cycles, weekly religious-giving rhythm — plus per-zone base rates of
culturally-specific fraud typologies. Purpose: stop false-flagging communal
finance as structuring, and stop missing fraud hidden inside cultural
patterns. Companion to `national_intelligence`.

- **Data**: synthetic seeded cultural generator (seed=42, reference year 2026, 6 zones, 365 days, 400 ajo/fraud group summaries) — provenance: **synthetic** (no real feeds).
- **Inference**: nuts_lite (Laplace-whitened where dim>=12), 4 chains x
  1000 kept samples per model. Total fit 684s.
- **Ethics guardrail**: pattern-level features only; no per-individual ethnicity/religion/tribe/language attributes anywhere; zone-level aggregate priors only. Enforced by a meta-test
  (`test_no_sensitive_attributes_anywhere`) that scans every feature schema
  in this pipeline for religion/ethnicity/tribe/language terms.

## Convergence diagnostics

| Sub-model | max R-hat | min ESS | fit time |
|---|---|---|---|
| ajo_model | 1.0096 | 382 | 258s |
| calendar_model | 1.0034 | 1228 | 50s |
| market_model | 1.0036 | 1406 | 203s |
| giving_model | 1.0025 | 2290 | 84s |
| affinity_model | 1.0024 | 1222 | 90s |

## Ajo/esusu legitimacy posterior

Held-out discrimination (synthetic): **AUC 0.997**
(n=120; legit rotating clubs vs fake-ajo ponzi rings and
structuring rings). Assessment is three-way: `likely_legitimate_ajo` /
`likely_fraud` / **`uncertain`** — the uncertain zone is explicit (95% CI
straddling 0.5), never forced into a binary call.

| Coefficient | Posterior mean | 95% CI |
|---|---|---|
| intercept | -2.19 | [-3.89, -0.61] |
| log_n_members | +1.31 | [+0.10, +2.77] |
| contribution_cv | -3.23 | [-5.85, -0.86] |
| cadence_cv | -1.28 | [-3.44, +0.46] |
| rotation_coverage | +4.70 | [+2.83, +6.79] |
| payout_ratio | -0.86 | [-3.04, +1.17] |
| log_tenure_days | +2.24 | [+0.72, +4.03] |

## Cultural calendar uplift (national posterior)

| Event | 2026 window | Lunar approx | Uplift mean | 95% CI |
|---|---|---|---|---|
| New Year | 2026-01-01 → 2026-01-02 | no | 1.93× | [1.87, 1.99] |
| Eid al-Fitr (Sallah) | 2026-03-20 → 2026-03-22 | yes (approx) | 1.47× | [1.44, 1.51] |
| Easter (Good Friday–Easter Monday) | 2026-04-03 → 2026-04-06 | no | 1.49× | [1.46, 1.52] |
| Eid al-Adha (Big Sallah) | 2026-05-27 → 2026-05-29 | yes (approx) | 1.61× | [1.57, 1.65] |
| Independence Day | 2026-10-01 → 2026-10-02 | no | 1.83× | [1.78, 1.89] |
| Detty December season | 2026-12-15 → 2026-12-31 | no | 1.69× | [1.67, 1.71] |
| Christmas | 2026-12-24 → 2026-12-26 | no | 2.39× | [2.33, 2.45] |
| Salary week (month-end ±3d, recurring) | monthly →  | no | 1.43× | [1.42, 1.44] |

## Market-week cycles

Per-zone cyclic harmonic posteriors: South East / South South 4-day
(Eke/Orie/Afo/Nkwo), South West 5-day, northern zones 7-day. NOTE: for
7-day zones the market rhythm and Gregorian weekly seasonality share
period 7 and partially alias — the served curve is the honest combined
rhythm.

## Limitations

- Trained on synthetic data with documented assumptions; absolute levels
  are NOT measured Nigerian cultural patterns until real feeds land.
- Calendar model is two-stage (fit after the market model on
  market-corrected volumes); the market plug-in's uncertainty is propagated
  by recomputing window ratios over market posterior draws, and residual
  day-level dispersion (incl. unmodelled weekly seasonality) enters the
  observation noise. Residual *bias* of the market fit is not fully
  captured — treat intervals as honest-but-not-conservative.
- Lunar dates (Eid al-Fitr ~2026-03-20, Eid al-Adha ~2026-05-27) are
  approximations, flagged `lunar_approx`; re-seed when official dates are
  announced.
- Culture varies WITHIN zones; intervals carry that uncertainty honestly —
  a wide interval is a statement of ignorance, not of uniformity.
- Statistical descriptions of aggregates must never be read as judgments
  of groups or applied to individuals (stereotype risk; see
  docs/CULTURAL_INTELLIGENCE.md).
