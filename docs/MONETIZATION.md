# FraudFusion Monetization Model

FraudFusion is a B2B fraud-detection platform. **The paying customer is the
tenant fintech** (banks, PSPs, lenders, and other regulated institutions that
integrate FraudFusion into their own transaction flows) — never the tenant's
end users. The platform is monetized through three mechanics that compose
into one commercial offer:

1. **API keys** — identity, scope, and the metering anchor.
2. **Per-transaction / per-call metered billing** — metered usage events,
   rated per operation.
3. **Subscription tiers** — a monthly base fee that includes a volume
   allowance, with per-call overage beyond the allowance.

Implementation: `services/python/billing-service` (`/v1/billing/*`, :8400),
schema in `database/20260901_billing_monetization.sql`, manifest in
`deploy/kubernetes/billing-service.yaml`. All money is **integer kobo**
(1 NGN = 100 kobo); arithmetic is decimal-safe (`Decimal`, ROUND_HALF_UP) and
floats are never used for money.

---

## 1. API keys — identity + scope + metering anchor

Every tenant call carries an API key in the `X-API-Key` header:

```
ffk_live_<32 random hex chars>
```

- **Issued once, shown once.** `POST /v1/billing/api-keys` returns the
  plaintext exactly once. Only `SHA-256(plaintext)` plus a non-secret prefix
  (`ffk_live_ab12cd34`, the first 8 random chars) are persisted. Listing
  endpoints expose the prefix only.
- **Scoped.** A key carries a subset of operation scopes
  (`fraud_score`, `aml_score`, `kyc_verify`, `kgqa_query`,
  `land_verification`). Scopes may not exceed what the tenant's plan allows.
- **Rate limited.** Per-key sliding-window limit (requests/minute), backed by
  Redis when `REDIS_URL` is set, otherwise in-process — `/health` reports
  `rate_limit_backend: memory` loudly because in-memory limits are
  per-replica, not global.
- **Metering anchor.** Every authenticated call records a `usage_events` row
  (tenant, key, operation, units, idempotency key) through a buffered,
  asynchronously-flushed writer. Rotation and revocation are first-class
  (`/rotate` returns a new plaintext once; `/revoke` is idempotent).
- **Fail-closed.** Missing/invalid/expired key → `401`; revoked/suspended
  key or missing scope → `403`; over the rate limit → `429`.

### APISIX key-auth in front of existing services

The gateway (`deploy/kubernetes/apisix.yaml`) can front every billable
service with the standard `key-auth` plugin, so metering happens at the edge
before traffic reaches the detectors:

```yaml
plugins:
  key-auth:
    header: X-API-Key
```

Consumers are provisioned per tenant API key; APISIX validates the key and
injects the tenant identity upstream, while the billing service's
`require_api_key` FastAPI dependency performs the authoritative checks
(hash lookup, status, scope, expiry, rate limit) and records the metered
event. Defence in depth: APISIX rejects unknown keys cheaply at the edge;
the billing service enforces billing state (suspension, dunning) and scope.

## 2. Per-transaction metered billing

Usage is ingested as events (`POST /v1/billing/usage`), idempotent on
`(tenant_id, idempotency_key)` — a replayed event is acknowledged but never
double-counted. Events roll up monthly into `usage_rollups`
(tenant + period + operation).

At invoice time the **rating engine** (`app/rating.py`) prices each
operation:

1. **Included volume first** — units up to the plan's monthly allowance are
   covered by the subscription base fee.
2. **Tiered per-call overage** — units beyond inclusion are billed at the
   plan's per-operation rate, configurable per plan (and per tenant via
   subscription `overrides` for enterprise contracts).

### Price list (NGN, overage per call beyond inclusion)

| Operation           | What it bills                | Growth overage | Scale overage | Rationale |
|---------------------|------------------------------|----------------|---------------|-----------|
| `fraud_score`       | one transaction fraud score  | ₦0.40          | ₦0.30         | High-volume, low unit cost; priced below the ~₦1/call Nigerian market norm to win payment-screening volume. |
| `aml_score`         | one AML screening call       | ₦0.90          | ₦0.70         | Heavier compute (sanctions/PEP graph traversal) than fraud scoring. |
| `kyc_verify`        | one identity verification    | ₦120           | ₦100          | Pass-through of BVN/NIN verification-provider cost plus margin; low volume, high per-call cost. |
| `kgqa_query`        | one knowledge-graph QA query | ₦2.50          | ₦2.00         | Analyst tooling, medium volume, GPU-backed inference cost. |
| `land_verification` | one land-title case          | ₦5,000         | ₦4,500        | Case-based (includes human/registry steps); priced per case, not per call. |

### Subscription tiers

| Tier               | Monthly fee      | Included per month (fraud_score / aml_score / kyc_verify / kgqa_query / land_verification) | Rate limit |
|--------------------|------------------|---------------------------------------------------------------------------------------------|------------|
| `developer_sandbox`| Free             | 1,000 / 200 / 20 / 500 / 0                                                                  | 30 rpm     |
| `growth`           | ₦150,000         | 50,000 / 10,000 / 500 / 20,000 / 10                                                         | 120 rpm    |
| `scale`            | ₦600,000         | 300,000 / 60,000 / 3,000 / 120,000 / 60                                                     | 600 rpm    |
| `enterprise`       | Custom           | Negotiated via subscription `overrides`                                                     | 1,200 rpm  |

Sandbox has **no overage rates**: it is a hard-capped evaluation tier, so
bill shock is impossible while integrating. Growth → Scale roughly halves
the effective per-call cost at ~12× the included volume, which is the
upgrade incentive. Enterprise keeps list prices out of the database: the
plan row carries empty maps and every commercial term lives in the
subscription's `overrides` JSONB (audit-able per tenant).

## 3. Subscription mechanics and invoicing

A `billing_subscriptions` row ties a tenant to a plan for the current
billing period (calendar month). Invoices are generated monthly:

```
POST /v1/billing/invoices/generate?period=YYYY-MM     # admin: all tenants
POST /v1/billing/invoices/generate?period=YYYY-MM&tenant_id=...  # one tenant
```

Each invoice contains line items built from the rollups — one
`subscription` line (base fee) plus one `overage` line per operation that
exceeded inclusion — a subtotal, **7.5% Nigerian VAT** (kobo, half-up), and
a total. State machine:

```
draft --issue--> issued --pay--> paid
  |                |
  +--void--> void  +--void--> void
```

Drafts may be regenerated freely (late-arriving usage is picked up); once
issued, regeneration skips the invoice. Issue sets `due_date` (default
issue + 14 days, `BILLING_INVOICE_DUE_DAYS`).

### Settlement through the double-entry ledger

Paying an invoice records `settlement_journal_id` on
`billing_invoices` — the UUID of the journal posted into the existing
double-entry ledger (`ledger_journals` / `ledger_postings`, see
`database/20260822_double_entry_ledger_settlement_reconciliation.sql` and
`docs/DOUBLE_ENTRY_LEDGER_SETTLEMENT_RECONCILIATION_ARCHITECTURE.md`):

```
DR  tenant accounts-receivable (clearing)   total_kobo
CR  platform revenue (revenue)              total_kobo
```

The ledger's `journal_type='settlement'`, balanced-posting constraint, and
append-only triggers apply unchanged; the billing migration deliberately
uses a **plain UUID column (no hard FK)** so it is safe on databases where
the ledger tables are not yet created.

### Dunning / suspension flow

`POST /v1/billing/dunning/run` (admin, typically a daily cronjob):

1. Issued invoice past `due_date` → subscription `past_due`, reminder
   recorded in `billing_dunning_events`. **Keys keep working** (grace).
2. Still unpaid after `BILLING_DUNNING_GRACE_DAYS` (default 7) →
   subscription `suspended`, all tenant keys `suspended` → data plane
   returns `403 API key suspended (billing)`.
3. Payment clears the invoice (`paid`) and resumes the subscription;
   keys can be re-activated by rotation or support.

### NDPA note

Billing events carry **no PII**: `usage_events` records tenant ID, key ID,
service, operation, unit counts, and timestamps — never customer names,
BVN/NIN, account numbers, or transaction payloads. This keeps the billing
pipeline outside NDPA scope for personal-data processing (it processes
corporate usage telemetry), and lets metering data be replicated to
analytics without privacy controls beyond standard tenant isolation.

---

## Example flows (curl)

```bash
B=http://localhost:8400
TOKEN=...        # Keycloak bearer for a tenant user or billing_admin

# 1. Put a tenant on the Growth plan
curl -X POST $B/v1/billing/subscriptions -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id": "tenant-1", "plan_id": "growth"}'

# 2. Issue an API key — plaintext returned exactly once
curl -X POST $B/v1/billing/api-keys -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id": "tenant-1", "name": "production", "scopes": ["fraud_score", "aml_score"]}'
# => {"plaintext_key": "ffk_live_9f...", "key_prefix": "ffk_live_9f12ab34", ...}

# 3. Metered data-plane call (as routed from APISIX)
curl -X POST $B/v1/billing/meter/fraud_score -H "X-API-Key: ffk_live_9f..."

# 4. Idempotent usage ingestion (batch path)
curl -X POST "$B/v1/billing/usage" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id": "tenant-1", "service": "fraud-scoring", "operation": "fraud_score",
       "units": 50100, "idempotency_key": "aug-batch-1", "occurred_at": "2026-08-15T10:00:00+00:00"}'

# 5. Current usage + estimated bill
curl "$B/v1/billing/usage/current?tenant_id=tenant-1" -H "Authorization: Bearer $TOKEN"

# 6. Generate the August invoice, issue it, settle it through the ledger
curl -X POST "$B/v1/billing/invoices/generate?period=2026-08" -H "Authorization: Bearer $TOKEN"
curl -X POST "$B/v1/billing/invoices/<invoice_id>/issue" -H "Authorization: Bearer $TOKEN"
curl -X POST "$B/v1/billing/invoices/<invoice_id>/pay" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"settlement_journal_id": "11111111-2222-3333-4444-555555555555"}'

# 7. Rotate / revoke a key
curl -X POST "$B/v1/billing/api-keys/<key_id>/rotate" -H "Authorization: Bearer $TOKEN"
curl -X POST "$B/v1/billing/api-keys/<key_id>/revoke" -H "Authorization: Bearer $TOKEN"
```
