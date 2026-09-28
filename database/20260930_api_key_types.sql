-- 20260930_api_key_types.sql
-- API-key environment classes (lane A, round 9): billing-service mints and
-- meters ffk_live_ keys, but the data-plane services (kyc-api, intel-service)
-- now accept API keys via the new service-to-service introspection endpoint
-- (POST /internal/api-keys/introspect). This migration adds:
--
--   * api_keys.key_type      — 'live' | 'test'. Test keys (ffk_test_) get full
--                              data-plane access within their scopes but their
--                              usage is audit-only (never billed).
--   * usage_events.environment — 'live' | 'test' tag on each metered event;
--                              'test' rows are excluded from usage_rollups by
--                              the service (see billing-service app/keys.py).
--
-- Fresh-DB-safe and idempotent: to_regclass-guarded DO blocks,
-- ADD COLUMN IF NOT EXISTS (matching 20260928_identity_exposure.sql style).
-- The billing-service SQLite mirror carries the same columns
-- (services/python/billing-service/app/db.py).

DO $$
BEGIN
    IF to_regclass('api_keys') IS NOT NULL THEN
        ALTER TABLE api_keys
            ADD COLUMN IF NOT EXISTS key_type VARCHAR(8) NOT NULL DEFAULT 'live';
    ELSE
        RAISE NOTICE 'api_keys not present; skipping key_type column';
    END IF;
    IF to_regclass('usage_events') IS NOT NULL THEN
        ALTER TABLE usage_events
            ADD COLUMN IF NOT EXISTS environment VARCHAR(8) NOT NULL DEFAULT 'live';
    ELSE
        RAISE NOTICE 'usage_events not present; skipping environment column';
    END IF;
END $$;

-- CHECK constraints added separately so re-runs are idempotent on PG
-- (ADD CONSTRAINT has no IF NOT EXISTS).
DO $$
BEGIN
    IF to_regclass('api_keys') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'api_keys_key_type_check') THEN
        ALTER TABLE api_keys
            ADD CONSTRAINT api_keys_key_type_check
            CHECK (key_type IN ('live', 'test'));
    END IF;
    IF to_regclass('usage_events') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'usage_events_environment_check') THEN
        ALTER TABLE usage_events
            ADD CONSTRAINT usage_events_environment_check
            CHECK (environment IN ('live', 'test'));
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('api_keys') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS api_keys_tenant_type_idx
            ON api_keys (tenant_id, key_type)';
    END IF;
END $$;
