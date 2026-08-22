# Double-Entry Ledger, Settlement, and Reconciliation Architecture

## Objective

Fraud decisions must never directly alter a customer balance or payment state. A production release requires a dedicated **ledger boundary** that accepts authenticated, tenant-scoped commands, creates immutable balanced journal entries, records settlement-provider events idempotently, and continuously reconciles internal records against provider statements.

## Control boundary

```text
Mobile / API client
  -> Keycloak token introspection
  -> tenant_id and subject binding
  -> Payment command service (idempotency key + authorization)
  -> PostgreSQL transaction
       -> immutable ledger_journal
       -> balanced ledger_posting rows
       -> settlement instruction / provider outbox record
  -> Provider adapter (asynchronous)
  -> provider event inbox (idempotent, hashed payload)
  -> settlement state transition
  -> reconciliation run / exception queue
```

A fraud-risk outcome is an input to payment authorization policy. It can block, hold, require review, or permit a command; it must not act as the accounting source of truth. A single database transaction records the journal and outbox event. External provider calls occur only after commit, and incoming provider events are deduplicated before changing settlement state.

## Invariants

| Invariant | Enforcement point |
|---|---|
| Every posted journal balances per currency: total debit equals total credit. | Deferred PostgreSQL constraint trigger. |
| A journal contains at least two postings. | Deferred PostgreSQL constraint trigger. |
| Journal entries and postings are append-only. Corrections use a new reversal journal. | `BEFORE UPDATE OR DELETE` triggers reject mutation. |
| A payment command is idempotent within a tenant. | Unique `(tenant_id, idempotency_key)` on journals. |
| A provider event cannot be processed twice. | Unique `(tenant_id, provider, provider_event_id)` in the inbox. |
| A settlement item cannot cross tenants, currencies, or account identities. | Composite tenant foreign keys and check constraints. |
| Settlement transitions are monotonic and explicitly allowed. | State-transition trigger. |
| Every unresolved provider/internal variance becomes a reconciliation break. | Reconciliation workflow and immutable break record. |
| Tenant identity is token-derived, not client-supplied. | Keycloak claim is bound to request context; header/body tenant values must equal it. |

## Command flow

A caller presents a bearer token and a client-generated idempotency key. The API derives `tenant_id` and `actor_id` from the validated token, validates permission and risk policy, and inserts one `ledger_journals` record plus its debit and credit lines in a PostgreSQL transaction. The deferred trigger checks the completed journal at commit. The same transaction inserts an outbox row or settlement item. A retry returns the original journal if its command hash is identical; a retry with the same key and different payload is rejected.

For an outbound settlement, the journal first moves funds from an available-liability account to a clearing-liability account. When a provider confirms settlement, a second journal moves clearing to settled. A provider rejection creates a reversal journal rather than updating existing postings. For an inbound payment, the mirrored sequence applies. This preserves a complete trace and makes any balance derivable from immutable postings.

## Settlement and reconciliation flow

A dispatcher reads committed outbox rows and invokes the provider with a provider-side idempotency key. Provider callbacks are stored in `provider_settlement_events` before transition logic runs. The stored `payload_sha256` identifies same-event payload tampering. A reconciliation job imports a signed provider statement, matches each provider reference to a settlement item, and creates an immutable `reconciliation_breaks` record when amount, currency, state, or timing differs. No settlement can be treated as final while a high-severity unresolved break exists.

## Required service interfaces

| Interface | Required behavior |
|---|---|
| `POST /ledger/journals` | Token-bound tenant; idempotency key; command hash; atomic journal/posting/outbox transaction. |
| `GET /ledger/journals/{id}` | Tenant-scoped immutable audit view. |
| `POST /settlements` | Creates a clearing journal and settlement item; never calls provider inside the database transaction. |
| `POST /provider-events/{provider}` | Verifies provider signature, records inbox event idempotently, then applies permitted settlement transition. |
| `POST /reconciliation-runs` | Imports a provider statement with source hash; produces matched, unmatched, and mismatch results. |
| `GET /reconciliation-breaks` | Tenant-scoped operational queue; access is role-gated and fully audited. |

## Operational release gates

The migration and verification suite must run on a restored staging database. The service must have database migration checks, provider signature verification tests, transaction rollback tests, race tests, outage/retry tests, reconciliation mismatch tests, and an approved finance-control review before production payment traffic.
