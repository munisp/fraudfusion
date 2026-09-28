-- 20260930_kyc_idempotency.sql
-- Idempotency + tenant isolation for the kyc-api data plane (lane A,
-- round 9):
--
--   * kyc_idempotency_keys — first-wins response replay for the
--     Idempotency-Key header on POST verify endpoints. Stores the key,
--     owning tenant, a sha256 request fingerprint, and the full response
--     payload; rows expire after 24h (enforced by the service). Same key +
--     same payload replays the stored response; same key + different
--     payload is rejected 409.
--   * kyc_requests.tenant_id — tenant that owns the request row. API-key
--     data-plane principals (ffk_* via billing introspection) write their
--     tenant here and can only read their own tenant's rows; staff JWT
--     principals keep the historical 'default' bucket and stay
--     cross-tenant.
--
-- Fresh-DB-safe and idempotent: to_regclass-guarded DO blocks,
-- CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS (matching
-- 20260928_identity_exposure.sql style). The kyc-api SQLite mirror carries
-- the same table/column (services/python/kyc-api/app/db.py).

DO $$
BEGIN
    IF to_regclass('kyc_idempotency_keys') IS NULL THEN
        CREATE TABLE kyc_idempotency_keys (
            id               BIGSERIAL PRIMARY KEY,
            key              VARCHAR(255) NOT NULL,
            tenant_id        VARCHAR(255) NOT NULL DEFAULT 'default',
            request_hash     CHAR(64) NOT NULL,
            response_payload JSONB NOT NULL,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, key)
        );
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('kyc_requests') IS NOT NULL THEN
        ALTER TABLE kyc_requests
            ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255) NOT NULL DEFAULT 'default';
        EXECUTE 'CREATE INDEX IF NOT EXISTS kyc_requests_tenant_idx
            ON kyc_requests (tenant_id, customer_id)';
    ELSE
        RAISE NOTICE 'kyc_requests not present; skipping tenant_id column';
    END IF;
END $$;
