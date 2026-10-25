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
