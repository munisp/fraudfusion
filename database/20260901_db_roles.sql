-- ============================================================================
-- Per-service database roles (converts deploy/kubernetes/postgres-init.md
-- from a docs-only script into a real, idempotent migration).
--
-- Idempotent by construction: every CREATE ROLE is guarded with
-- IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = ...); GRANT/REVOKE are
-- naturally re-runnable in PostgreSQL; database-scoped statements are
-- guarded with pg_database existence checks so this file also applies
-- cleanly on the embedded-PG migration harness (which runs against the
-- default database, not necessarily "fraudfusion"). Safe to apply twice.
--
-- PASSWORDS: roles are created WITHOUT PASSWORD (psql :'var' substitution is
-- not portable across psql / migration runners / embedded-PG harnesses).
-- A role without a password cannot authenticate, so the deploy step AFTER
-- this migration is, per environment, as a superuser:
--
--     ALTER ROLE fraudfusion_migrator PASSWORD '<from-secrets-manager>';
--     ALTER ROLE aml_monitor          PASSWORD '<...>';  -- etc. per role
--
-- and the matching k8s Secret values (detector-db, postgres-credentials)
-- updated in the same change window (see "Rotate passwords" note in
-- deploy/kubernetes/postgres-init.md).
-- ============================================================================

-- ---------- Roles ----------
-- Migrator/owner role: applies database/*.sql migrations at deploy time.
-- Service roles: referenced by deploy/kubernetes manifests (DB_USER /
-- DATABASE_URL envs). fraudfusion_regulator_ro: DB-side read-only principal
-- that the dual-control regulator-access workflow maps to.
DO $$
DECLARE
    r text;
    login_roles text[] := ARRAY[
        'fraudfusion_migrator',
        'aml_monitor',
        'advance_fee_fraud_detector',
        'crypto_fraud_detector',
        'investment_fraud_detector',
        'sim_swap_detector',
        'account_takeover_detector',
        'identity_theft_detector',
        'ledger_command',
        'chargeback_fraud_detector',
        'insider_fraud_detector',
        'onboarding_service',
        'land_verification_service',
        'kyc_api',
        'fraudfusion_regulator_ro'
    ];
BEGIN
    FOREACH r IN ARRAY login_roles LOOP
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN', r);
        END IF;
    END LOOP;
END $$;

-- ---------- Database-scoped grants (guarded: DB may not exist here) ----------
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_database WHERE datname = 'fraudfusion') THEN
        -- Lock down the default PUBLIC connect grant, then grant explicitly.
        EXECUTE 'REVOKE ALL ON DATABASE fraudfusion FROM PUBLIC';
        EXECUTE 'GRANT CONNECT ON DATABASE fraudfusion TO
            fraudfusion_migrator,
            aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
            investment_fraud_detector, sim_swap_detector, account_takeover_detector,
            identity_theft_detector, ledger_command, chargeback_fraud_detector,
            insider_fraud_detector, onboarding_service, land_verification_service,
            kyc_api, fraudfusion_regulator_ro';
    END IF;
END $$;

-- ---------- Schema privileges (least privilege: no PUBLIC defaults) ----------
-- PG15+ already revokes CREATE ON public FROM PUBLIC by default; make the
-- intent explicit and re-runnable on older clusters.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- Migrator owns schema evolution.
GRANT CREATE ON SCHEMA public TO fraudfusion_migrator;

-- Per-service CRUD on the application schema only (no DDL).
GRANT USAGE ON SCHEMA public TO
    aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
    investment_fraud_detector, sim_swap_detector, account_takeover_detector,
    identity_theft_detector, ledger_command, chargeback_fraud_detector,
    insider_fraud_detector, onboarding_service, land_verification_service,
    kyc_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO
    aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
    investment_fraud_detector, sim_swap_detector, account_takeover_detector,
    identity_theft_detector, ledger_command, chargeback_fraud_detector,
    insider_fraud_detector, onboarding_service, land_verification_service,
    kyc_api;

-- Read-only regulator/audit access.
GRANT USAGE ON SCHEMA public TO fraudfusion_regulator_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO fraudfusion_regulator_ro;

-- ---------- Default privileges for tables created by later migrations ----------
-- GRANT ... ON ALL TABLES covers only existing tables; these cover tables
-- created afterwards by fraudfusion_migrator.
ALTER DEFAULT PRIVILEGES FOR ROLE fraudfusion_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO
    aml_monitor, advance_fee_fraud_detector, crypto_fraud_detector,
    investment_fraud_detector, sim_swap_detector, account_takeover_detector,
    identity_theft_detector, ledger_command, chargeback_fraud_detector,
    insider_fraud_detector, onboarding_service, land_verification_service,
    kyc_api;
ALTER DEFAULT PRIVILEGES FOR ROLE fraudfusion_migrator IN SCHEMA public
    GRANT SELECT ON TABLES TO fraudfusion_regulator_ro;

-- ---------- Notes (from deploy/kubernetes/postgres-init.md) ----------
-- * Detectors with runtime EnsureSchema (e.g. aml-monitor) additionally need
--   CREATE on the schema for their own tables, or the migrator pre-creates
--   them: GRANT CREATE ON SCHEMA public TO aml_monitor;
-- * Keycloak manages its own database (keycloak role + DB, see
--   deploy/kubernetes/keycloak.yaml) and is intentionally separate.
-- ============================================================================
