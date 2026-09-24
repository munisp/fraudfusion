# Benchmark Methodology & CI Regression Gate

## Harness
- `k6` scripts in `perf/k6/` (auth-check, fraud-score, ledger-post, journey).
- Run from a pod in the same cluster as the target service to eliminate WAN noise.
- Use staging with production-shaped data: seed ≥1M rows into
  `aml_transaction_analyses`, `crypto_transactions`, `ledger_postings`,
  `login_patterns` before measuring.

## Load shape
1. Warm-up: 60s, excluded from thresholds (each script tags warmup separately).
2. Baseline/target: expected peak (e.g. 200 RPS scoring, 50 RPS ledger) for 5–10 min.
3. Stress: ramp to 2x peak to expose pool exhaustion and retry storms.

## Traffic mix
~70% cached-auth reads, 20% scoring, 10% ledger writes; 1% cache-miss token
rotation; batch endpoints (n=100) exercised periodically.

## Metrics to capture
- Client-side p50/p95/p99 + error rate (k6 thresholds encode the budgets in
  `LATENCY_BUDGET.md`).
- PG `pg_stat_statements` top-20 before/after; pool stats (`pgxpool.Stat()`,
  `sql.DB.Stats()`); goroutine counts; uvicorn worker count and event-loop lag.

## Dependency-failure drills
Kill Keycloak/Permify/Redis mid-run: verify cached auth keeps p95 within
budget, negative cache (5s) limits revocation lag, and no request climbs to
the old retry-ladder ceilings (3.7–15s).

## CI regression gate
- Per-PR job: 3-minute k6 smoke per script against docker-compose; FAIL if any
  budget class p95 regresses >20% vs the recorded `main` baseline.
- Publish a `pg_stat_statements` diff on schema PRs (any new seq scan on a
  hot table fails review).
- Record baseline artifacts (`k6 run --out json`) per release in
  `perf/baselines/`.

## Post-change expectations (measured reasoning, not live cluster numbers)
- Auth check: uncached Keycloak introspection (~10–40ms p50) → in-process TTL
  cache hit (<0.1ms) ⇒ **auth p50 < 2ms**, Keycloak outage no longer adds the
  3-attempt retry ladder to every request.
- Crypto detector score: ~6 DB round trips → 2 (single-CTE consolidation) ⇒
  est. p95 150ms+ → **<50ms** with indexes applied.
- Batch analyze (aml-monitor/crypto): 100 serial items × (ML call + insert) →
  8–10 workers ⇒ **~10–12x wall-clock reduction** for batch=100.
- Ledger journal post: SERIALIZABLE + default pool (4 conns) → ReadCommitted +
  MaxConns 20 + 40001 retry ⇒ removes pool-acquisition queueing and spurious
  503s; **p95 < 100ms**.
- Journey execute: blocked on full workflow (minutes) → 202 + background
  completion ⇒ **accept p95 < 150ms**; 3 sync Kafka publishes (≤150ms batch
  wait) → one batched write (10ms window).
- Model router: per-request parquet write (5–30ms) → buffered background flush
  ⇒ **removes disk I/O from score hot path entirely**.
- Python services: per-call psycopg2/httpx connects (5–30ms each) → pooled ⇒
  login path 4 connects ≈ up to 120ms saved per login.
