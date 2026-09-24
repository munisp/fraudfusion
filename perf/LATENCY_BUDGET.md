# Latency Budgets (Lane B2)

Targets per endpoint class (from the audit, §9). Budgets assume warm caches,
tuned pools, and the indexes in `database/20260826_performance_indexes.sql`.

| Endpoint class | Example | p50 | p95 | p99 | How the budget is met |
|---|---|---|---|---|---|
| Auth check (cached) | any middleware | <2ms | <10ms | <20ms | Token-hash TTL cache (45s) + singleflight + 5s negative cache in all Go detectors, ledger-command, orchestrator, and Python services; introspection fallback <50ms p95 |
| Fraud score (rules + cache) | detector `/analyze` | <20ms | <50ms | <100ms | ≤2 indexed DB round trips (single-CTE queries), Redis wallet cache, bounded sql.DB pool (25/25) |
| Fraud score (ML/ONNX) | `/v1/aml/score` | <15ms | <50ms | <120ms | Model loaded at startup, inference in worker thread, batch endpoint `:batch` for >1 txn |
| Ledger post (journal) | `POST /api/v1/ledger/journals` | <30ms | <100ms | <250ms | ReadCommitted txn (≤4 statements), pgxpool MaxConns=20, 40001 retry (3, jittered) |
| Ledger read | `GET /api/v1/ledger/journals/:id` | <10ms | <30ms | <80ms | PK lookup |
| Journey execute (async accept) | `POST /api/v1/journey/execute` → 202 | <50ms | <150ms | <400ms | Cached Permify decision (10s), one batched Kafka publish (10ms window), APISIX/TigerBeetle provisioning memoized, result awaited in background |
| Journey result poll | `GET /api/v1/journey/executions/{id}` | <5ms | <20ms | <50ms | Redis GET |
| AML reads (cached) | risk-score GET | <5ms | <20ms | <50ms | Redis hit; DB fallback <30ms p95 |
| List/report endpoints | SAR list, daily report | <50ms | <200ms | <500ms | Indexed, LIMIT-bounded, daily-report aggregates run concurrently |
| Settlement dispatch (async) | outbox → provider | — | <2s enqueue-to-submit | <10s | Background dispatcher |
| Document verification (land) | `/api/v1/verify` | 202-style fast path | OCR off event loop | — | Pooled DB, OCR in worker thread, streamed uploads with 50MB cap |

## Key mechanisms

- **Auth caching**: SHA-256(token)-keyed TTL cache everywhere; positive 45s,
  negative 5s, singleflight dedup, bounded at 10k entries (fail-closed on
  miss; correctness never depends on the cache).
- **Connection hygiene**: all Go services set explicit pool limits; ledger
  uses pgxpool with MaxConns/MinConns/lifetime/idle; Python services share one
  pooled `httpx.AsyncClient`; pgbouncer manifest in `deploy/kubernetes/perf/`.
- **Async boundaries**: journey execution returns 202 immediately; model
  router parquet writes are buffered and flushed by a background thread
  (500 events / 5s trigger, final flush on shutdown).
