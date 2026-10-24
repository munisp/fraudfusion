# FraudFusion Design-Partner Kit

Everything a prospective design partner needs to evaluate, integrate, and
procure FraudFusion. Branch `audit-remediation` is the integration surface.

## 1. Integration guide

| Step | What | Where |
|---|---|---|
| 1 | Get a `ffk_test_` key and point an SDK at the sandbox | `sdks/python`, `sdks/typescript` |
| 2 | Run the deterministic fixtures (BVN …000→approved …003→sanctions) | `services/python/sandbox` README |
| 3 | Register a webhook endpoint; verify signatures with the SDK helper | `sdks/*/README.md` |
| 4 | Dry-run registry wiring against the sandbox doubles | `docs/demo-script.md` §5 |
| 5 | Go live: swap to `ffk_live_` — same code, metered + scoped | billing-service |

Auth model: data-plane endpoints accept **either** staff Keycloak JWT **or**
`X-API-Key` (validated service-to-service against billing, scoped per
endpoint: `kyc_verify`, `aml_score`, `fraud_score`, `webhooks_manage`).
Mutating KYC endpoints accept `Idempotency-Key` (first-wins replay, 24h TTL).
Every verdict worth acting on also arrives as a **signed webhook**
(`X-FraudFusion-Signature`, HMAC-SHA256 with sha256-derived key, ±300s
tolerance — SDKs ship verifiers).

## 2. Security architecture (what exists in code today)

- **Fail-closed everywhere:** unconfigured auth provider → 503; unknown API
  key → 401; registry unreachable → honest `unavailable`, never a fabricated
  match. No codepath invents a verification result.
- **Hash-only PII posture (NDPA):** document bytes and registry subjects are
  never persisted — SHA-256 + verdict + provenance only. Exposure detection
  stores hashes, not identifiers.
- **Audit:** hash-chained webhook delivery ledger; append-only audit tables;
  every score carries per-layer provenance (`ran`/`unavailable` + reason).
- **Key management:** API keys hash-only at rest (`ffk_live_`/`ffk_test_`),
  shown once at creation; webhook signing secrets shown once, HMAC keys
  derived from the hash; internal service-to-service endpoints guarded by
  shared-token headers.
- **Tenant isolation:** API-key principals are pinned to their tenant;
  cross-tenant reads 404.

## 3. NDPA / DPIA mapping

| DPIA concern | Platform answer |
|---|---|
| Data minimization | Hash-only persistence; PII held in memory only during verification |
| Purpose limitation | Scope-enforced API keys; per-endpoint least privilege |
| Subject rights | Exposure-redress flow (FCCPC/NDPC 4-step guidance built in) |
| Cross-border | Self-hostable in-country; no required third-party cloud |
| Breach impact | Hashes without source data are non-identifying |
| Automated decisions | `manual_review` bands route borderline cases to humans; approve never hard-blocks on `manual_review` |

## 4. SOC 2–style gap analysis (honest)

| Control area | In code | Needs process evidence |
|---|---|---|
| Access control | fail-closed auth, scoped keys, tenant isolation | org policies, access reviews |
| Audit logging | hash-chained ledgers, provenance everywhere | log retention/review procedures |
| Change management | migration harness (30/30 idempotent), 600+ tests | SDLC policy, ticketing |
| Availability | health endpoints, rate limiting | uptime SLOs, incident history |
| Vendor/registry | plug-ready fail-closed adapters | NIBSS/NIMC contracts |
| PAD (biometrics) | local liveness + conformance suite (ISO 30107-3 mapping) | Fime/iBeta lab assessment |

## 5. Procurement FAQ

- **Where does our data go?** Nowhere, by default — self-hosted; document
  bytes never persisted. Optional remote IDV (OpenKYC-compatible) is your
  deployment choice.
- **What happens when NIBSS/NIMC is down?** Adapters report `unavailable`
  with the reason; KYC tiers decide per policy (manual_review paths exist).
- **Pricing model?** Flat tiers (₦50k/₦200k/₦5M per month), metered usage,
  test keys never bill.
- **What do we get that Smile ID doesn't give us?** Post-onboarding fraud
  intelligence (behavioral/cultural scoring, smishing lures, exposure
  detection), KYB content verification, Nigerian regulatory encoding, and
  self-hosting. See `docs/` positioning notes.
