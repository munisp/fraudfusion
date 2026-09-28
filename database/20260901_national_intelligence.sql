-- 20260901_national_intelligence.sql
-- National Fraud Intelligence: aggregate-only weekly tables feeding the
-- hierarchical Bayesian layer (ml/bayesian/national_intelligence.py) and the
-- intel-service API. NO PII by construction: counts per state/LGA/zone-week
-- only. Fresh-DB-safe, idempotent, guarded DDL (to_regclass DO blocks,
-- matching 20260820_*_persistence_hardening.sql style).

-- intel_state_weekly: one row per state per ISO week (37 jurisdictions).
DO $$
BEGIN
    IF to_regclass('intel_state_weekly') IS NULL THEN
        CREATE TABLE intel_state_weekly (
            state_code      VARCHAR(32)  NOT NULL,
            week            DATE         NOT NULL,  -- ISO week start (Monday)
            txn_count       INTEGER      NOT NULL CHECK (txn_count >= 0),
            fraud_count     INTEGER      NOT NULL CHECK (fraud_count >= 0),
            created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            PRIMARY KEY (state_code, week),
            CHECK (fraud_count <= txn_count)
        );
    END IF;
END $$;

-- intel_lga_weekly: one row per LGA per week (pilot states: lagos, kano,
-- abuja_fct; other states may be onboarded later).
DO $$
BEGIN
    IF to_regclass('intel_lga_weekly') IS NULL THEN
        CREATE TABLE intel_lga_weekly (
            state_code      VARCHAR(32)  NOT NULL,
            lga_name        VARCHAR(128) NOT NULL,
            week            DATE         NOT NULL,
            txn_count       INTEGER      NOT NULL CHECK (txn_count >= 0),
            fraud_count     INTEGER      NOT NULL CHECK (fraud_count >= 0),
            created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            PRIMARY KEY (state_code, lga_name, week),
            CHECK (fraud_count <= txn_count)
        );
    END IF;
END $$;

-- intel_typology_weekly: fraud counts per geopolitical zone per typology
-- per week (feeds the Dirichlet-multinomial typology-mix model).
DO $$
BEGIN
    IF to_regclass('intel_typology_weekly') IS NULL THEN
        CREATE TABLE intel_typology_weekly (
            zone            VARCHAR(32)  NOT NULL,  -- e.g. south_west
            week            DATE         NOT NULL,
            typology        VARCHAR(64)  NOT NULL,  -- e.g. account_takeover
            fraud_count     INTEGER      NOT NULL CHECK (fraud_count >= 0),
            created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            PRIMARY KEY (zone, week, typology)
        );
    END IF;
END $$;

-- intel_briefs: archive of generated National Fraud Intelligence Briefs
-- (markdown), one per model refit, for regulator-grade audit trail.
DO $$
BEGIN
    IF to_regclass('intel_briefs') IS NULL THEN
        CREATE TABLE intel_briefs (
            id                     BIGSERIAL PRIMARY KEY,
            model_version          VARCHAR(32)  NOT NULL,  -- e.g. v1
            artifact_dir           TEXT         NOT NULL,
            week_start             DATE         NOT NULL,
            week_end               DATE         NOT NULL,
            national_rate_mean     DOUBLE PRECISION,
            national_rate_ci95_lo  DOUBLE PRECISION,
            national_rate_ci95_hi  DOUBLE PRECISION,
            brief_markdown         TEXT         NOT NULL,
            provenance             VARCHAR(32)  NOT NULL DEFAULT 'synthetic',
            generated_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
        );
    END IF;
END $$;

-- Indexes (guarded on table existence).
DO $$
BEGIN
    IF to_regclass('intel_state_weekly') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS intel_state_weekly_week_idx ON intel_state_weekly (week DESC);';
    END IF;
    IF to_regclass('intel_lga_weekly') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS intel_lga_weekly_state_week_idx ON intel_lga_weekly (state_code, week DESC);';
    END IF;
    IF to_regclass('intel_typology_weekly') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS intel_typology_weekly_week_idx ON intel_typology_weekly (week DESC);';
    END IF;
    IF to_regclass('intel_briefs') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS intel_briefs_generated_idx ON intel_briefs (generated_at DESC);';
    END IF;
END $$;
