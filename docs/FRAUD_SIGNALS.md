# Fraud Signals Service

Developing-market fraud detectors, exposed as a mesh service and implemented
in **four languages** (Python reference, TypeScript SDK, Go, Rust) pinned to
one parity contract.

## The eight detectors

| Detector | Endpoint | Pattern |
|---|---|---|
| `app_scam` | `POST /api/v1/signals/app_scam` | Authorized-push-payment / social-engineering scams (payee novelty, amount outlier, rushed session, new device, payee mule score) |
| `mule` | `POST /api/v1/signals/mule` | Money-mule behaviour (pass-through ratio, fan-in, dormancy burst, shared-device clusters) |
| `agent` | `POST /api/v1/signals/agent` | Agent-banking / mobile-money fraud (velocity spike, structuring below ₦50k, off-location, float diversion) |
| `loan_stacking` | `POST /api/v1/signals/loan_stacking` | Cross-lender stacking & bust-out (≥3 lenders in 14d, first-payment default, thin file, forged income docs) |
| `issuance` | `POST /api/v1/signals/issuance` | Insider-issued *genuine* documents (officer velocity z-score, after-hours issuance, sequence gaps, registry/survey mismatch) |
| `channel` | `POST /api/v1/signals/channel` | USSD / feature-phone fraud (SIM-swap recency, new IMEI high-value, fake-alert integrity, low phone tenure) |
| `ghost_payroll` | `POST /api/v1/signals/ghost_payroll` | Ghost workers (shared salary accounts, duplicate identities, salary-only accounts, deceased-registry hits) |
| `subsidy` | `POST /api/v1/signals/subsidy` | Phantom-farmer subsidy fraud (implausible ₦/ha, farm outside LGA, duplicate claimants, no field activity) |

## Contract

Every detector is a pure function `(payload, history) -> (score, verdict, factors)`:

- **score** 0..1, additive over explainable factors `{code, detail, weight}`
- **verdict** bands: `score >= 0.70 → "block"`, `>= 0.35 → "review"`, else `"clear"`
- **no fabrication**: missing history produces a `history_unavailable` factor
  note, never an assumed baseline

The API layer adds the stateful parts:

- `POST /api/v1/signals/events` — ingest facts (`{kind, subject_id, payload}`)
  that velocity/pattern detectors query as history windows
- `POST /api/v1/signals/{detector}` — evaluate; merges inline `events` with
  stored history for `subject_id`, records the triggering event, appends a
  **hash-chained** audit row, returns `{score, verdict, factors, audit_hash}`
- `GET /api/v1/signals/chain/{detector}` — verify the tamper-evident eval chain
- `GET /health`, `GET /api/v1/integrations/status`

## Cross-language parity

`fixtures/detector_cases.json` is generated from the Python reference
(`tests/generate_fixtures.py`) and consumed by all four ports:

| Language | Location | Test |
|---|---|---|
| Python (reference) | `services/python/fraud-signals/detectors.py` | `tests/test_fixture_parity.py` |
| TypeScript | `sdks/typescript/src/fraud-signals.ts` | `test/fraud-signals.test.ts` (`npm test`) |
| Go | `services/go/fraud-signals-detector/detectors.go` | `detectors_test.go` (`go test ./...`) |
| Rust | `services/rust/fraud-signals/src/lib.rs` | inline `parity_with_python_reference` (`cargo test`) |

**Any threshold change must land in all four ports and regenerate the fixture.**

## Mesh integration

Registered as `fraud_signals` (`FRAUD_SIGNALS_URL`) in
`services/python/integration/mesh.py`; typed flows in `flows.py`
(`fraud_signal_app_scam`, `fraud_signal_mule`, …). Current consumers:

- **kyc-api** `/risk/assess` — APP-scam advisory when transfer context is
  present; the payee's mule score feeds `payee_mule_score` into the app-scam
  detector (cross-detector composition through the mesh)
- **land-verification** `/due-diligence` — issuance-anomaly check on the
  registering officer; `review`/`block` verdicts land as scored factors
- **onboarding-service** KYB — loan-stacking advisory keyed by CAC number;
  document-forgery verdicts feed `document_authenticity_score`

All integrations are advisory and fail-closed: an unreachable fraud-signals
service yields `{"status": "unavailable", "reason": ...}` blocks and never
moves the caller's own score or verdict.

## Deployment

`deploy/docker-compose.platform.yml` includes `fraud-signals` on :8900 with
`FRAUD_SIGNALS_URL` in the shared env anchor. Postgres is the source of
record (`FRAUDFUSION_REQUIRE_POSTGRES=1`); SQLite only for dev/tests.
Schema: `database/20261030_fraud_signals.sql` (also self-applied at boot).

## Shadow mode & backtesting (accuracy measurement)

The detectors are heuristic — their real-world precision/recall is only
knowable by measurement. Two tools close that loop:

- **Shadow mode** — `POST /api/v1/signals/shadow/{detector}` runs the full
  evaluation and appends a tamper-evident audit row tagged `mode='shadow'`,
  but does NOT record the triggering event (live history stays clean).
  Run detectors on production traffic in shadow for 4–8 weeks, then pull
  `GET /api/v1/signals/scores/{detector}?mode=shadow` for the score
  distribution and tune thresholds from observed data.
  Migration: `database/20261031_fraud_signals_shadow.sql`.
- **Backtest harness** — `backtest.py` replays labeled JSONL cases
  (`{detector, label: fraud|legit, payload, history}`) and reports
  precision/recall/FPR at both bands, per detector and overall, with raw
  counts always shown. `fixtures/backtest_cases.jsonl` (32 synthetic labeled
  cases) gives the baseline: block-band recall 87.5%, review-band recall
  100%, 0% FPR — on synthetic data only; replace with real labeled cases.

## Evasion surface (red-team register)

`tests/test_redteam_evasion.py` attacks every detector with a source-reading
adversary and asserts the outcome in two classes:

- **Resisted** — evading one factor still lands in review/block because
  others fire (e.g. sub-₦45k structuring evades the structuring factor but
  velocity + off-location still catch it)
- **Known gaps** — evasions that succeed today, each documented with the
  compensating control that would close it (e.g. distributed ghost accounts
  → biometric dedup; plausible ₦/ha subsidy claims → satellite NDVI
  cross-check)

These tests are the honest evasion register: if a change closes a gap, the
test is *moved* to the resisted class, never weakened.

### Gap closures (Round 21)

Three of the original gaps were closed in the detectors (all four language
ports + parity fixture updated together):

1. **SIM-swap 24h cliff** → SIM-age step-up: high-value transactions (≥ ₦100k)
   within 168h of a SIM change escalate (`sim_age_high_value_stepup`, 0.30).
   Residual: sub-₦100k moves at 25h+ — needs cumulative-amount step-up.
2. **Under-threshold mule fan-in** → sender-risk propagation: events may carry
   `counterparty_risk` (the sender's own score, annotated via the mesh); ≥3
   risky senders fires `high_risk_fan_in` (0.30). Residual: unannotated
   senders — service-side self-enrichment is the roadmap.
3. **Slow insider issuance** → beneficiary-side + four-eyes:
   `beneficiary_issuance_burst` (≥3 certs to one beneficiary in 30d, 0.25) and
   `high_value_single_approval` (≥ ₦10M with one approver, 0.20). Residual:
   clean-beneficiary low-value dual-approved issuance — needs audit sampling.
