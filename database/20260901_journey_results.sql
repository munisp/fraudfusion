-- Durable storage for temporal-orchestrator journey outcomes.
--
-- Previously completed journey results lived only in Redis with a 1h TTL;
-- after expiry the outcome was unrecoverable. journey_results is now the
-- system of record (Redis remains a hot cache only).
--
-- Fresh-DB-safe and idempotent: CREATE TABLE IF NOT EXISTS + guarded index.

BEGIN;

CREATE TABLE IF NOT EXISTS journey_results (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    journey_id VARCHAR(255) NOT NULL,
    journey_type VARCHAR(100) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('completed','failed','compensated','timed_out')),
    outcome JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, journey_id)
);

CREATE INDEX IF NOT EXISTS journey_results_tenant_completed_idx
    ON journey_results (tenant_id, completed_at DESC);

COMMIT;
