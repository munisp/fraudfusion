-- 20260928_kyc_rigor_agents.sql
-- Round 7 Lane I2: KYC/onboarding rigor gaps from the NIN/BVN transcript.
--
--   1. counterparty_rigor_registry — admin-managed registry of counterparty
--      institutions' onboarding verification rigor (accounts opened at
--      institutions that skip CBN biometric BVN verification are higher
--      risk). Consumed by kyc-api (app/counterparty.py); lookups fail closed
--      to 'unknown' when no row exists.
--   2. agent_outcomes — post-onboarding outcomes (clean | flagged |
--      confirmed_fraud) for agent-enrolled customers; feeds the
--      onboarding-service Beta-Binomial agent integrity score.
--   3. kyc_requests address-verification columns — address evidence method +
--      verified_at. kyc-api Postgres tables DO exist in earlier migrations
--      (kyc_requests in 20260901_python_services_caveats.sql), so the columns
--      go on that table (guarded ALTERs) rather than a standalone table; the
--      SQLite mirror gains the same columns via KYC_REQUESTS_EXTRA_COLUMNS.
--
-- Fresh-DB-safe and idempotent: to_regclass / information_schema-guarded DO
-- blocks and CREATE TABLE IF NOT EXISTS, matching
-- 20260902_cultural_intelligence.sql style.

-- ---------------------------------------------------------------------------
-- 1. counterparty_rigor_registry
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('counterparty_rigor_registry') IS NULL THEN
        CREATE TABLE counterparty_rigor_registry (
            institution_code VARCHAR(50)  PRIMARY KEY,
            institution_name VARCHAR(255) NOT NULL,
            rigor_level      VARCHAR(32)  NOT NULL
                CHECK (rigor_level IN ('cbn_full_biometric', 'cbn_basic',
                                       'unverified', 'unknown')),
            source_note      TEXT         NOT NULL DEFAULT '',
            updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
        );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. agent_outcomes (index on agent_id for the integrity-score aggregation)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('agent_outcomes') IS NULL THEN
        CREATE TABLE agent_outcomes (
            id           VARCHAR(64)  PRIMARY KEY,
            agent_id     VARCHAR(255) NOT NULL,
            customer_ref VARCHAR(200) NOT NULL,
            outcome      VARCHAR(20)  NOT NULL
                CHECK (outcome IN ('clean', 'flagged', 'confirmed_fraud')),
            recorded_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS agent_outcomes_agent_idx ON agent_outcomes (agent_id);

-- ---------------------------------------------------------------------------
-- 3. kyc_requests address-verification columns (guarded: kyc_requests is
--    created by 20260901_python_services_caveats.sql; skip loudly-safe if a
--    deployment applies this file before that one).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('kyc_requests') IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'kyc_requests'
                         AND column_name = 'address_verification_method') THEN
            ALTER TABLE kyc_requests
                ADD COLUMN address_verification_method VARCHAR(32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'kyc_requests'
                         AND column_name = 'address_verified_at') THEN
            ALTER TABLE kyc_requests
                ADD COLUMN address_verified_at TIMESTAMPTZ;
        END IF;
    END IF;
END $$;

-- Address-verification method values are enforced in kyc-api
-- (app/tiers.py ADDRESS_VERIFICATION_METHODS: physical_visit | utility_bill |
-- agent_confirmation | electronic) rather than a CHECK constraint, so adding
-- a method never requires a schema migration.
