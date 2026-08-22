# Redis-Backed Distributed Replay Architecture

## Objective

Replace the process-local replay map and global mutation lock with a **Redis-backed idempotency claim**. Multiple release-gate metric-producer replicas may now receive the same signed event, but only the first replica can claim it and emit the local Prometheus counter increment.

## Atomic Claim Contract

For every validated event, the producer computes a non-reversible Redis key:

```text
<REDIS_REPLAY_KEY_PREFIX><SHA-256(event + ":" + run_id + ":" + gate + ":" + scenario)>
```

It executes one atomic Redis operation:

```text
SET key 1 NX EX 86400
```

| Redis result | Handler result | Metric behavior |
|---|---|---|
| `OK` | HTTP 202 accepted | Emit exactly one local counter increment. Prometheus aggregates across replicas. |
| Nil reply | HTTP 202 idempotent duplicate | Emit no counter increment. |
| Redis error or deadline | HTTP 503 | Fail closed; emit no counter increment so a sender retry cannot create an unverified metric. |

The 24-hour TTL replaces the former in-process cleanup loop. Redis automatically expires replay keys; no request-path scan is required.

## Multi-Node Metrics Semantics

The producer owns no shared mutable replay state. Each replica maintains only lock-free local `atomic.Uint64` counters. Prometheus must aggregate the counter across instances when computing fleet totals. Because the Redis claim is global, exactly one replica increments for every accepted event.

## Security and Availability Controls

The production process requires a Redis address and validates the Redis connection at startup. Redis uses a configurable username/password and TLS setting. A per-operation timeout bounds the impact of degraded Redis. The deployment must restrict Redis egress to the producer namespace and source credentials from a Kubernetes Secret or ExternalSecret. There is intentionally **no in-memory fallback** in production: a fallback would reintroduce cross-node duplicate acceptance.

## Key Lifecycle

The replay-key prefix is versioned, for example `fraudfusion:release-gate:replay:v1:`. Changing the prefix deliberately starts a new replay namespace; do this only during an approved migration window. The event identity is hashed before being placed in Redis, so run IDs and workflow labels are not exposed as Redis key material.

## Operational Requirements

Redis must be deployed as a highly available service appropriate to the environment. For cross-zone resilience, use a Redis cluster or Sentinel-backed primary/replica topology and verify failover behavior in staging. The producer treats an unavailable Redis tier as a release-gate control-plane failure and returns HTTP 503 so clients retry rather than silently bypass replay protection.
