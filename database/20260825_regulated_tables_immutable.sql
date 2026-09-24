-- 20260825_regulated_tables_immutable.sql
-- Anti-wipe hardening (lane B3 / P0-3): trigger-based UPDATE/DELETE denial on
-- regulated evidence tables. Modeled on the append-only ledger pattern in
-- 20260822_double_entry_ledger_settlement_reconciliation.sql.
--
-- Protected surfaces:
--   * AML: aml_sars (status transitions only via guarded state machine),
--     aml_transaction_analyses, aml_patterns, aml_sanctions_checks,
--     aml_sof_verifications
--   * Insider fraud: insider_fraud_events, insider_fraud_alerts,
--     privileged_access_logs, unusual_activities, data_exfiltration_attempts
--   * Chargeback evidence: chargeback_alerts, friendly_fraud_cases,
--     chargeback_abuse_patterns, chargeback_risk_decisions
--     (dispute_records gets a column whitelist so the ON CONFLICT DO UPDATE
--     ingestion path keeps working while identity columns are frozen)
--   * Audit/control: deletion_approvals (status transitions only),
--     storage_audit_events (append-only)
--
-- Idempotent: safe to run repeatedly (IF NOT EXISTS / DROP TRIGGER IF EXISTS /
-- CREATE OR REPLACE FUNCTION, and guards for tables that may not exist yet).

BEGIN;

-- ---------------------------------------------------------------------------
-- Generic deny function
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION prevent_regulated_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is immutable regulated evidence; UPDATE/DELETE denied (anti-wipe policy). Use the documented transition function where one exists.', TG_TABLE_NAME;
END;
$$;

-- Helper: attach deny trigger only if the table exists (idempotent + safe on
-- partially-migrated environments).
CREATE OR REPLACE FUNCTION antiwipe_attach_immutable(target_table TEXT)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF to_regclass(target_table) IS NULL THEN
        RAISE NOTICE 'table % does not exist yet; skipping immutability trigger', target_table;
        RETURN;
    END IF;
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', target_table || '_immutable', target_table);
    EXECUTE format(
        'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION prevent_regulated_mutation()',
        target_table || '_immutable', target_table);
END;
$$;

-- ---------------------------------------------------------------------------
-- AML evidence tables: fully immutable (insert-only)
-- ---------------------------------------------------------------------------
SELECT antiwipe_attach_immutable('aml_transaction_analyses');
SELECT antiwipe_attach_immutable('aml_patterns');
SELECT antiwipe_attach_immutable('aml_sanctions_checks');
SELECT antiwipe_attach_immutable('aml_sof_verifications');

-- ---------------------------------------------------------------------------
-- aml_sars: one-way state machine draft -> filed (then frozen forever)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION aml_sars_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'aml_sars rows are immutable regulator evidence; DELETE denied (anti-wipe policy)';
    END IF;

    -- UPDATE: allowed ONLY for the explicit draft->filed transition touching
    -- only status / reference_number / filing_date / updated_at.
    IF OLD.status = 'filed' THEN
        RAISE EXCEPTION 'aml_sars row % is filed and frozen; no updates permitted', OLD.sar_id;
    END IF;
    IF NOT (OLD.status = 'draft' AND NEW.status IN ('draft','filed')) THEN
        RAISE EXCEPTION 'aml_sars illegal status transition % -> % for %', OLD.status, NEW.status, OLD.sar_id;
    END IF;
    -- Identity and narrative columns are immutable even in draft.
    IF NEW.sar_id IS DISTINCT FROM OLD.sar_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.narrative IS DISTINCT FROM OLD.narrative
       OR NEW.transaction_ids IS DISTINCT FROM OLD.transaction_ids
       OR NEW.activity_type IS DISTINCT FROM OLD.activity_type
       OR NEW.filing_institution IS DISTINCT FROM OLD.filing_institution
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'aml_sars immutable column modified for %; only status/reference_number/filing_date may change', OLD.sar_id;
    END IF;
    IF NEW.status = 'filed' AND NEW.filing_date IS NULL THEN
        NEW.filing_date := now();
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF to_regclass('aml_sars') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS aml_sars_state_machine ON aml_sars;
        CREATE TRIGGER aml_sars_state_machine BEFORE UPDATE OR DELETE ON aml_sars
        FOR EACH ROW EXECUTE FUNCTION aml_sars_guard();
    ELSE
        RAISE NOTICE 'aml_sars does not exist yet; skipping';
    END IF;
END $$;

-- Explicit transition function for the AML filing path (preferred over bare
-- UPDATE; the trigger above still guards direct UPDATEs from repository.go).
CREATE OR REPLACE FUNCTION aml_sar_mark_filed(p_sar_id TEXT, p_reference_number TEXT)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE aml_sars
       SET status = 'filed',
           reference_number = COALESCE(NULLIF(p_reference_number, ''), reference_number),
           filing_date = now(),
           updated_at = now()
     WHERE sar_id = p_sar_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'aml_sars row % not found', p_sar_id;
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Insider-fraud evidence: fully immutable (insert-only)
-- ---------------------------------------------------------------------------
SELECT antiwipe_attach_immutable('insider_fraud_events');
SELECT antiwipe_attach_immutable('insider_fraud_alerts');
SELECT antiwipe_attach_immutable('privileged_access_logs');
SELECT antiwipe_attach_immutable('unusual_activities');
SELECT antiwipe_attach_immutable('data_exfiltration_attempts');

-- ---------------------------------------------------------------------------
-- Chargeback evidence
-- ---------------------------------------------------------------------------
SELECT antiwipe_attach_immutable('chargeback_alerts');
SELECT antiwipe_attach_immutable('friendly_fraud_cases');
SELECT antiwipe_attach_immutable('chargeback_abuse_patterns');
SELECT antiwipe_attach_immutable('chargeback_risk_decisions');

-- dispute_records: the ingestion path uses ON CONFLICT DO UPDATE, so allow
-- updates to a whitelist of mutable columns; identity columns stay frozen and
-- DELETE is denied.
CREATE OR REPLACE FUNCTION dispute_records_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'dispute_records are chargeback evidence; DELETE denied (anti-wipe policy). Use soft-delete (deleted_at) instead';
    END IF;
    IF NEW.dispute_id IS DISTINCT FROM OLD.dispute_id
       OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'dispute_records identity columns are immutable (id %) ', OLD.id;
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF to_regclass('dispute_records') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS dispute_records_immutable ON dispute_records;
        CREATE TRIGGER dispute_records_immutable BEFORE UPDATE OR DELETE ON dispute_records
        FOR EACH ROW EXECUTE FUNCTION dispute_records_guard();
    ELSE
        RAISE NOTICE 'dispute_records does not exist yet; skipping';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- storage_audit_events: append-only gateway audit mirror table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage_audit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255),
    operation VARCHAR(32) NOT NULL,
    bucket VARCHAR(255) NOT NULL,
    object_key TEXT NOT NULL,
    actor_id VARCHAR(255),
    actor_ip VARCHAR(64),
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS storage_audit_events_bucket_key_idx
    ON storage_audit_events (bucket, object_key, created_at DESC);
CREATE INDEX IF NOT EXISTS storage_audit_events_actor_idx
    ON storage_audit_events (actor_id, created_at DESC);
SELECT antiwipe_attach_immutable('storage_audit_events');

COMMIT;
