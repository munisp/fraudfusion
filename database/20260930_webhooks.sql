-- 20260930_webhooks.sql
-- Webhook delivery platform (Round 9 Lane W): tenant webhook endpoints,
-- persisted event envelope log, and per-endpoint delivery rows with retry /
-- dead-letter state and a hash-chained audit trail (prev_hash/entry_hash,
-- following the backoffice_audit_ledger pattern from
-- 20260901_python_services_caveats.sql).
--
-- Signing scheme (shared Round-9 contract, verified by the SDKs):
--   X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
--   signed payload = "<t>.<raw request body>"
--   HMAC key = sha256(endpoint_signing_secret).hexdigest() (utf-8 bytes) —
--   the endpoint secret (whsec_<32hex>) is shown ONCE at creation and only
--   its sha256 hash is persisted; the hash hex is therefore the only key
--   material available to the delivery worker at signing time. Receivers
--   derive the same key from their copy of the whsec_ secret.
--
-- Fresh-DB-safe and idempotent: to_regclass-guarded DO blocks,
-- CREATE INDEX IF NOT EXISTS (matching 20260928_identity_exposure.sql /
-- 20260820_*_persistence_hardening.sql style).
--
-- The webhook-service ALSO mirrors this schema in SQLite
-- (services/python/webhook-service/app/db.py SQLITE_SCHEMA); the SQLite
-- mirror carries the same columns so dual-driver code paths stay identical.
-- JSON payloads are stored as TEXT in both drivers (no jsonb cast needed).

-- ---------------------------------------------------------------------------
-- 1. webhook_endpoints: one row per tenant-registered callback URL.
--    secret_hash = sha256(whsec_<32hex>); the raw secret is never persisted.
--    consecutive_failures feeds the per-endpoint circuit breaker (status
--    flips to 'disabled' after WEBHOOK_BREAKER_THRESHOLD consecutive
--    dead-lettered deliveries; disabled endpoints are skipped by fan-out
--    and the worker).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('webhook_endpoints') IS NULL THEN
        CREATE TABLE webhook_endpoints (
            id                   VARCHAR(64) PRIMARY KEY,
            tenant_id            VARCHAR(255) NOT NULL DEFAULT 'default',
            url                  TEXT NOT NULL,
            event_types          TEXT NOT NULL DEFAULT '[]',
            secret_hash          VARCHAR(64) NOT NULL,
            status               VARCHAR(16) NOT NULL DEFAULT 'active'
                                 CHECK (status IN ('active', 'disabled')),
            consecutive_failures INT NOT NULL DEFAULT 0,
            created_by           VARCHAR(255) NOT NULL DEFAULT '',
            created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    ELSE
        RAISE NOTICE 'webhook_endpoints already present; skipping create';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS webhook_endpoints_tenant_idx
    ON webhook_endpoints (tenant_id, status);

-- ---------------------------------------------------------------------------
-- 2. webhook_events: persisted event envelopes received at /internal/events
--    (envelope {"id","type","created_at","tenant_id","data"}; payload is the
--    exact JSON body delivered to endpoints, so signature verification by
--    receivers is over byte-identical content).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('webhook_events') IS NULL THEN
        CREATE TABLE webhook_events (
            id          VARCHAR(80) PRIMARY KEY,
            type        VARCHAR(128) NOT NULL,
            tenant_id   VARCHAR(255) NOT NULL DEFAULT 'default',
            payload     TEXT NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            received_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    ELSE
        RAISE NOTICE 'webhook_events already present; skipping create';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS webhook_events_tenant_type_idx
    ON webhook_events (tenant_id, type);

-- ---------------------------------------------------------------------------
-- 3. webhook_deliveries: one row per (event, endpoint) fan-out. The row is
--    updated in place across attempts (status, attempt_count,
--    next_attempt_at as unix seconds, attempts_json history); the
--    prev_hash/entry_hash chain is computed ONCE at creation over the
--    immutable creation fields
--      prev_hash|id|event_id|endpoint_id|tenant_id|created_at
--    so chain verification stays valid after in-place attempt updates.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('webhook_deliveries') IS NULL THEN
        CREATE TABLE webhook_deliveries (
            id                VARCHAR(64) PRIMARY KEY,
            event_id          VARCHAR(80) NOT NULL,
            endpoint_id       VARCHAR(64) NOT NULL,
            tenant_id         VARCHAR(255) NOT NULL DEFAULT 'default',
            status            VARCHAR(16) NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'success', 'failed',
                                                'dead_letter')),
            attempt_count     INT NOT NULL DEFAULT 0,
            next_attempt_at   DOUBLE PRECISION NOT NULL DEFAULT 0,
            attempts_json     TEXT NOT NULL DEFAULT '[]',
            last_status_code  INT,
            last_error        TEXT,
            prev_hash         VARCHAR(64) NOT NULL,
            entry_hash        VARCHAR(64) NOT NULL,
            created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
            completed_at      TIMESTAMPTZ
        );
    ELSE
        RAISE NOTICE 'webhook_deliveries already present; skipping create';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
    ON webhook_deliveries (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS webhook_deliveries_endpoint_idx
    ON webhook_deliveries (endpoint_id, created_at);
CREATE INDEX IF NOT EXISTS webhook_deliveries_tenant_idx
    ON webhook_deliveries (tenant_id, id);
