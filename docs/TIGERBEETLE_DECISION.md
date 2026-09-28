# TigerBeetle adoption decision

**Status:** DECIDED — 2026-09-01 (audit remediation, lane O)
**Decision:** **Remove TigerBeetle from the default build.** Archive all
references as *evaluated, deferred*. The Postgres double-entry ledger
(`ledger-command`) remains the single hot ledger path.

## Background

A TigerBeetle client was introduced in Round 1 as a candidate hot-path ledger
for high-volume double-entry posting. Since Round 1 the shipped client has
been a stub: the default build compiles `client_stub.go`, which returns
`ErrUnavailable` for every operation; the real client behind
`-tags tigerbeetle` requires the TigerBeetle native (cgo) library and has
never been exercised in CI, e2e, or any stress run. Every deployment to date
has therefore run — and been validated — purely on the Postgres ledger.

## Options considered

1. **Commit to TigerBeetle for the hot ledger path.** Stand up a TigerBeetle
   cluster, finish the real client, migrate posting from Postgres, run
   dual-write + reconciliation while confidence is built.
2. **Remove TigerBeetle from the default build** and keep the Postgres
   ledger-command as the only ledger, archiving TigerBeetle as "evaluated,
   deferred" with explicit re-adoption criteria.

## Evaluation

| Criterion | Postgres ledger-command (incumbent) | TigerBeetle (candidate) |
| --- | --- | --- |
| Proven correctness | Double-entry invariant enforced in SQL (`database/20260822_double_entry_ledger_settlement_reconciliation.sql`), verification suites `database/tests/20260822_ledger_integrity_verification.sql` / `20260822_financial_close_verification.sql`, and the multi-tenant stress transaction (`database/tests/20260822_ledger_stress_transaction.sql`) all run green in the embedded-PG migration harness (double-apply + stress pass). | Real client never built in CI; zero stress evidence; stub returns `ErrUnavailable` on every call. |
| Migrations & ops | Migration chain proven idempotent (harness applies every `database/*.sql` twice). Runbooks, backup/PITR (`deploy/kubernetes/backup-pitr.yaml`) exist. | New stateful cluster to provision, back up, monitor, and run disaster recovery for; none of that exists. |
| Failure modes | Known: same Postgres HA/backup story as the rest of the platform. | Unknown in our hands: consensus cluster, native client pinning, version upgrades. |
| Team cost | Zero incremental. | Ongoing: cgo build tag matrix, native library availability in every build environment (the stated reason the stub exists). |
| Performance | Meets current latency budget (`perf/LATENCY_BUDGET.md`) at proven stress levels. | Faster in principle (purpose-built ledger), but unmeasured here and not required by any current SLO (`observability/slo.md`). |

The deciding factor is evidence asymmetry: the Postgres path is proven under
stress and migration-idempotency testing, while TigerBeetle has spent every
round as a permanently-degraded stub. Shipping a stub client behind a build
tag is strictly worse than not shipping it — it implies a capability that
does not exist.

## DECISION

**Remove TigerBeetle from the default build; archive as "evaluated,
deferred".**

### Scope note (Go code ownership)

The stub and its call sites live in Go code owned by the Go lane, so this
lane does not edit them. The removal pointer list for the Go lane / lead is:

- `orchestrator/go/internal/tigerbeetle/client_stub.go` — default-build stub
  (`ErrUnavailable`); delete together with `client_stub_test.go`.
- `orchestrator/go/internal/tigerbeetle/client_tigerbeetle.go` — real client
  behind `//go:build tigerbeetle`; delete or move to `docs/archive/`.
- `orchestrator/go/internal/tigerbeetle/ids.go` (+ `ids_test.go`) — account-ID
  mapping helpers; delete with the package.
- `orchestrator/go/cmd/orchestrator/main.go` — wiring: import, `tigerbeetle`
  field on the orchestrator struct, init step "8. TigerBeetle"
  (`tigerbeetle.NewClient`, lines ~154–161), and `ensureLedgerAccount`
  (lines ~258–264) which creates TigerBeetle settlement accounts.
- `perf/LATENCY_BUDGET.md` — TigerBeetle mention; reword as deferred.

Until that removal lands, the stub's contract stands: `ErrUnavailable` is
"ledger disabled", never success.

### Archive classification

All TigerBeetle material is classified **"evaluated, deferred"** — not
rejected. The evaluation above is the archive record.

## Re-adoption criteria

Revisit TigerBeetle (or another dedicated ledger) only when ALL hold:

1. Postgres ledger posting demonstrably misses its SLO
   (`observability/slo.md`: ledger post p95 ≤ 100 ms) under production load,
   with pprof/EXPLAIN evidence that the ledger write path — not an index or
   lock issue — is the cause.
2. A load model shows headroom exhaustion (e.g. sustained > 70% of proven
   stress throughput with growth commitments above it).
3. The build environment constraint is solved (native library available in
   CI and release builds without a stub fallback).
4. A staffed migration plan exists: dual-write period, reconciliation against
   the Postgres ledger, and a rollback path.
