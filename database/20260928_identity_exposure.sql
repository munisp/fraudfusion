-- 20260928_identity_exposure.sql
-- Identity exposure + enrollment-source tracing (lane I1), closing the
-- NIN/BVN transcript gaps: (a) duplicate identities traceable to enrollment
-- source/agent, (b) proactive victim-exposure detection from lawfully
-- obtained breach/leak indicator batches, (c) redress guidance support.
--
-- Fresh-DB-safe and idempotent: to_regclass-guarded DO blocks,
-- CREATE TABLE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, CREATE INDEX IF NOT
-- EXISTS (matching 20260902_cultural_intelligence.sql /
-- 20260820_*_persistence_hardening.sql style).
--
-- Base tables come from earlier migrations:
--   * bvn_registry / nin_registry / customer_identifiers
--       (20260901_python_services_caveats.sql)
--   * identity_theft_alerts (20260827_service_base_tables.sql)
-- The identity-theft-detector service ALSO mirrors this schema in SQLite
-- (services/python/identity-theft-detector/identity_store.py SQLITE_SCHEMA);
-- the SQLite mirror carries the same columns/tables so dual-driver code paths
-- stay identical.
--
-- NDPA posture: exposure_indicators stores sha256 identifier hashes ONLY —
-- plaintext BVN/NIN/phone/email values are never persisted here.

-- ---------------------------------------------------------------------------
-- 1. Enrollment-source tracing columns on the identity tables.
--    "If someone has two BVNs there's a problem — it needs to be traced to
--    source." Every identifier row can now carry WHERE/HOW it was enrolled:
--    enrollment_source (bank_branch | sim_registration_agent | nimc_fep |
--    self_service | unknown), enrollment_agent_id, enrollment_channel,
--    enrolled_at. Existing rows keep working with source = 'unknown'.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('bvn_registry') IS NOT NULL THEN
        ALTER TABLE bvn_registry
            ADD COLUMN IF NOT EXISTS enrollment_source VARCHAR(64) NOT NULL DEFAULT 'unknown',
            ADD COLUMN IF NOT EXISTS enrollment_agent_id VARCHAR(255),
            ADD COLUMN IF NOT EXISTS enrollment_channel VARCHAR(64),
            ADD COLUMN IF NOT EXISTS enrolled_at TIMESTAMPTZ;
    ELSE
        RAISE NOTICE 'bvn_registry not present; skipping enrollment-source columns';
    END IF;
    IF to_regclass('nin_registry') IS NOT NULL THEN
        ALTER TABLE nin_registry
            ADD COLUMN IF NOT EXISTS enrollment_source VARCHAR(64) NOT NULL DEFAULT 'unknown',
            ADD COLUMN IF NOT EXISTS enrollment_agent_id VARCHAR(255),
            ADD COLUMN IF NOT EXISTS enrollment_channel VARCHAR(64),
            ADD COLUMN IF NOT EXISTS enrolled_at TIMESTAMPTZ;
    ELSE
        RAISE NOTICE 'nin_registry not present; skipping enrollment-source columns';
    END IF;
    IF to_regclass('customer_identifiers') IS NOT NULL THEN
        ALTER TABLE customer_identifiers
            ADD COLUMN IF NOT EXISTS enrollment_source VARCHAR(64) NOT NULL DEFAULT 'unknown',
            ADD COLUMN IF NOT EXISTS enrollment_agent_id VARCHAR(255),
            ADD COLUMN IF NOT EXISTS enrollment_channel VARCHAR(64),
            ADD COLUMN IF NOT EXISTS enrolled_at TIMESTAMPTZ;
    ELSE
        RAISE NOTICE 'customer_identifiers not present; skipping enrollment-source columns';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. exposure_import_batches: one row per admin-imported leak-indicator batch
--    (provenance: source_note, row/match counts, importing principal).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('exposure_import_batches') IS NULL THEN
        CREATE TABLE exposure_import_batches (
            id            BIGSERIAL PRIMARY KEY,
            tenant_id     VARCHAR(255) NOT NULL DEFAULT 'default',
            batch_id      VARCHAR(255) NOT NULL,
            source_note   TEXT,
            row_count     INT NOT NULL DEFAULT 0,
            matched_count INT NOT NULL DEFAULT 0,
            imported_by   VARCHAR(255),
            imported_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, batch_id)
        );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. exposure_indicators: the leaked-data indicators themselves.
--    identifier_hash = sha256 of the normalised identifier — plaintext
--    identifiers are NEVER persisted (NDPA pseudonymization posture).
--    UNIQUE(tenant_id, identifier_type, identifier_hash, breach_ref) makes
--    re-import of the same batch idempotent at the indicator level.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('exposure_indicators') IS NULL THEN
        CREATE TABLE exposure_indicators (
            id              BIGSERIAL PRIMARY KEY,
            tenant_id       VARCHAR(255) NOT NULL DEFAULT 'default',
            batch_id        VARCHAR(255) NOT NULL,
            identifier_type VARCHAR(20) NOT NULL
                CHECK (identifier_type IN ('phone', 'email', 'device', 'nin', 'bvn')),
            identifier_hash CHAR(64) NOT NULL,
            breach_ref      VARCHAR(255) NOT NULL,
            observed_at     TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, identifier_type, identifier_hash, breach_ref)
        );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. identity_theft_alerts dedupe support: exposure alerts are deduped on
--    customer_ref (user_id) + identifier_hash + breach_ref, both carried in
--    the details JSONB. The partial unique index enforces it at the database
--    level for the 'exposure_detected' alert type without constraining other
--    alert producers. Guarded: only when the base table exists.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('identity_theft_alerts') IS NOT NULL THEN
        EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS identity_theft_alerts_exposure_dedupe_uidx
            ON identity_theft_alerts (tenant_id, user_id,
                                      (details->>''identifier_hash''), (details->>''breach_ref''))
            WHERE alert_type = ''exposure_detected''';
    ELSE
        RAISE NOTICE 'identity_theft_alerts not present; skipping exposure dedupe index';
    END IF;
END $$;

-- Indexes for the new tables (guarded on table existence).
DO $$
BEGIN
    IF to_regclass('exposure_import_batches') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS exposure_import_batches_batch_idx
            ON exposure_import_batches (tenant_id, batch_id)';
    END IF;
    IF to_regclass('exposure_indicators') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS exposure_indicators_hash_idx
            ON exposure_indicators (tenant_id, identifier_type, identifier_hash)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS exposure_indicators_breach_idx
            ON exposure_indicators (tenant_id, breach_ref)';
    END IF;
    IF to_regclass('customer_identifiers') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS customer_identifiers_agent_idx
            ON customer_identifiers (tenant_id, enrollment_agent_id)
            WHERE enrollment_agent_id IS NOT NULL';
    END IF;
END $$;
