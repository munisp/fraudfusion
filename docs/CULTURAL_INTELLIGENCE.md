# Cultural Intelligence for Nigeria (MCMC)

**Status**: shipped (v1, synthetic-trained) · **Artifact**:
`ml/artifacts/cultural_intelligence/v1/` · **Service**: intel-service
`:8500` under `/v1/intel/cultural/` · **Model code**:
`ml/bayesian/cultural_intelligence.py` · **Companion**:
[docs/NATIONAL_INTELLIGENCE.md](NATIONAL_INTELLIGENCE.md) · **Domain
sources** (uploaded): `NIGERIAN_CULTURAL_FRAUD_PATTERNS_DETAILED_ANALYSIS`,
`NIGERIAN_CULTURAL_FRAUD_PATTERNS_METHODOLOGY_DETAILED`,
`NIGERIAN_CULTURAL_FRAUD_PATTERNS_SPECIFIC_EXAMPLES`,
`NIGERIAN_CULTURAL_FRAUD_ML_MODELS_DETAILED_ANALYSIS`,
`NIGERIA_FRAUD_DETECTION_STRATEGIES`.

## What this is

Nigeria's legitimate financial life is **culturally patterned**: rotating
savings clubs (ajo/esusu/adashe) move equal contributions to a different
member each cycle; spending surges around Eid al-Fitr, Eid al-Adha, Easter,
Christmas, Detty December, Independence Day and salary week; market weeks
run on 4-day (South East: Eke/Orie/Afo/Nkwo), 5-day (South West) and 7-day
(northern) cycles; giving concentrates on Fridays (Jumu'ah) and Sundays
(services/tithes). A fraud platform without this context does two kinds of
harm:

1. **False-flags legitimate communal finance.** An ajo cycle is literally
   *n people sending equal amounts on a regular cadence to a rotating
   recipient* — indistinguishable from structuring/smurfing for any
   detector that only sees amounts and cadence.
2. **Misses fraud hidden inside cultural patterns.** The five documented
   cultural masquerade typologies (below) deliberately wear the clothing of
   weddings, church/mosque obligations, family duty, apprenticeships and
   traditional authority.

Cultural Intelligence is the layer that carries this context as **MCMC
posteriors with honest uncertainty**, so every adjustment ships with a
credible interval instead of a point guess.

## Why MCMC (not a point-estimate ML model)

Cultural patterns are **sparse, seasonal, and unevenly evidenced** — a
4-day market cycle in Enugu has a different evidence base than Lagos salary
week. Gradient-boosted point estimates cannot express "we barely know this
uplift". Bayesian posteriors can: **the interval width IS the product**.
Wide interval → analysts keep raw scores; tight interval → adjust. Full
split R-hat / ESS diagnostics are in `metrics.json` for every sub-model.

## The five models

1. **Ajo/esusu legitimacy posterior** — Bayesian logistic regression for
   P(legitimate rotating club | pattern summary: group size, contribution
   CV, cadence CV, **rotation coverage** (each member receives exactly
   once), payout ratio, tenure). The honest discriminator is *rotation
   reciprocity vs fan-out*: legit ajo have coverage ≈ 1 and payout ≈
   n×contribution; structuring rings fan out with no return; fake-ajo
   ponzi pay inflated early slots. Held-out synthetic **AUC 0.997**
   (reported honestly — the generator includes deliberate overlap:
   young clubs mid-rotation, ponzi rings faking rotation with wash
   transfers, automated smurfing with regular cadence; ~10% of held-out
   patterns land in the `uncertain` zone). Assessments are three-way:
   `likely_legitimate_ajo` / `likely_fraud` / **`uncertain`** (95% CI
   straddling 0.5) — ambiguity is declared, never forced.
2. **Cultural calendar uplift** — per-event posterior uplift multipliers
   on volume, hierarchical partial pooling across the six geopolitical
   zones. Events: New Year, Eid al-Fitr (~2026-03-20, **lunar
   approximation — flagged**), Easter, Eid al-Adha (~2026-05-27, **lunar
   approximation**), Independence Day, Detty December (Dec 15–31),
   Christmas, salary week (month-end ±3d, recurring). Priors carry
   documented zone-composition assumptions (wide); likelihood dominates.
   Overlapping windows resolve by documented precedence — the applied
   event's uplift *absorbs* overlaps (e.g. New Year includes its salary-week
   component) and the API never double-counts. Truth-in-CI95 calibration on
   synthetic ground truth: **97.9%** (nominal 95%).
3. **Market-week cycles** — per-zone cyclic harmonic posteriors (4-day SE
   / South South, 5-day South West, 7-day north). For 7-day zones the
   market rhythm and Gregorian weekly seasonality share period 7 and
   partially alias — the served curve is the honest combined rhythm.
4. **Religious giving rhythm** — saturated day-of-week posterior on
   giving-type transfers with zone partial pooling: Friday peak in
   northern zones, Sunday peak in southern zones, Friday+Sunday double
   peak in North Central. (Saturated, not pure-harmonic: a Fri+Sun double
   peak with a Saturday lull is not representable by weekly cosines —
   verified empirically.)
5. **Culturally-specific fraud-typology base rates** — per-zone posterior
   base rates (logit-normal partial pooling) for the five documented
   masquerade typologies: `ceremony_exploitation`, `religious_manipulation`,
   `family_obligation_abuse`, `business_practice_abuse`,
   `authority_status_abuse`. These feed the investment-fraud detector's
   priors (see `ml/train/train_investment_fraud.py` consumers) and the
   `/v1/intel/cultural/typologies` endpoint.

Plus a deterministic **weighted cultural-fraud score**
(`cultural_fraud_score`, served at `POST /v1/intel/cultural/score`):
canonical indicator weights distilled from the domain documents —
temporal 0.20, network 0.25, cultural-inconsistency 0.20, amount 0.15,
communication 0.10, urgency 0.10 — with risk bands (critical ≥ 0.8, high
≥ 0.6, medium ≥ 0.4, low < 0.4) and a **cultural authenticity check** that
*discounts* the score (max −0.15) when the claimed event matches the
calendar, the network structure is consistent with the claimed norm, or a
claimed ajo rotation passes the legitimacy posterior. Legitimate cultural
context is evidence *against* fraud, never for it.

## The ajo false-positive problem, quantified

In the synthetic generator, a 10-member weekly ajo club produces ~90
equal-amount transfers to rotating recipients per cycle — structurally
identical to a smurfing ring's fan pattern on amount/cadence features
alone. Without rotation-coverage context, every legit club is a structuring
alert. The legitimacy posterior separates them on synthetic data at AUC
0.997 (see caveat: synthetic), and declared groups in the `ajo_groups`
table get **monitored-not-whitelisted** treatment: declaration adjusts
anomaly context; it never exempts anyone from monitoring.

## Endpoints (intel-service :8500)

| Endpoint | Purpose |
|---|---|
| `GET /v1/intel/cultural/calendar?date=&state=` | active events + uplift with CI (precedence-resolved) |
| `POST /v1/intel/cultural/ajo/assess` | legitimacy posterior + CI + uncertain zone + top discriminating features |
| `GET /v1/intel/cultural/adjustment?date=&state=&channel=` | anomaly-score adjustment factor (divide raw z-score by it) + human-readable reason; **every call audited** |
| `GET /v1/intel/cultural/typologies?zone=` | masquerade typology base rates with CIs |
| `GET /v1/intel/cultural/giving-rhythm?zone=` | weekly giving rhythm curve |
| `POST /v1/intel/cultural/score` | weighted cultural-fraud score + band + authenticity discount |

**Auditability**: every `/adjustment` writes `cultural_adjustment_audit`
(Postgres when `INTEL_AUDIT_DSN` is set, else a loud in-memory fallback
exposed for tests). No silent adjustments.

## Database

`database/20260902_cultural_intelligence.sql` (fresh-DB-safe, idempotent,
`to_regclass`-guarded): `cultural_calendar_events` (2026 seeded, lunar
flags), `ajo_groups` (opt-in declarations; status lifecycle
declared→monitoring→verified/flagged/closed), `cultural_adjustment_audit`.

## ETHICS GUARDRAIL (hard, tested)

These models adjust for transaction **patterns in cultural context — never
the person**. There are **no per-individual ethnicity, religion, tribe, or
language features anywhere** in this layer (enforced by meta-tests that
scan every feature schema, request/response model, generator column and
served summary for such terms). Geography enters only as the state/zone
the account already carries, and only as **zone-level aggregate priors**.
The language features described in the source documents may inform
zone-level/document-level aggregates only — never per-individual features.

**Stereotype-risk caveat**: the zone baselines are *statistical
descriptions with wide uncertainty*, not judgments of any group. A wide
interval is a statement of our ignorance, not of a group's uniformity.
Culture varies within zones; intervals carry that honestly. Fairness is
checked by a zone-parity test: zone-uniform events (Independence Day,
salary week) recover near-equal zone uplifts, and identical indicator
vectors score identically regardless of state (the scorer has no zone
dial). The source documents report per-group accuracy parity ~94.4–94.9%
and bias scores 0.018–0.031 for their reference system; our analogue is
the parity meta-test — and the hard guarantee that no sensitive attribute
exists to discriminate on in the first place.

## Who consumes this

- **Fraud analysts**: `/ajo/assess` before escalating a rotating-savings
  cluster; `/calendar` context on seasonal alerts.
- **Model calibration / scoring pipelines**: `/adjustment` divides raw
  z-scores by the expected cultural uplift (with CI; analysts may keep or
  override), `/typologies` supplies detector priors.
- **Product**: `ajo_groups` opt-in declarations (monitored-not-whitelisted)
  so cooperative savings features don't drown in false positives.

## Limitations (read before trusting numbers)

- **Synthetic priors until real data**: trained on a seeded synthetic
  generator with documented assumptions; absolute uplift levels are NOT
  measured Nigerian patterns. Refresh weekly/monthly from the cultural_*
  tables once real feeds land (same `train_cultural_intel` entrypoint).
- **Lunar dates are approximations** (flagged `lunar_approx`); re-seed
  `cultural_calendar_events` on official announcements.
- Calendar model is two-stage (market correction first); plug-in
  uncertainty is propagated via posterior-draw recomputation, but residual
  market-fit *bias* is not fully captured — treat intervals as
  honest-but-not-conservative (synthetic calibration: 97.9% coverage).
- Synthetic AUC (0.997) will not transfer verbatim to production; the
  uncertain zone is the safety mechanism that survives contact with real
  data.
- Northern 7-day market cycles alias with Gregorian weekly seasonality by
  construction; the served curve is the combined rhythm.
