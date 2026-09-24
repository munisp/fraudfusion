-- Financial control runtime hardening. Guarded for fresh-DB safety:
-- ledger_* / financial_close_periods tables are created by the lexically
-- later 20260822_ledger_outbox_and_financial_close.sql; if that file has not
-- run yet, the guarded blocks skip and re-running this file applies them.

DO $$
BEGIN
    IF to_regclass('ledger_outbox') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE ledger_outbox ADD COLUMN IF NOT EXISTS leased_by VARCHAR(128), ADD COLUMN IF NOT EXISTS last_error VARCHAR(512), ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()';
        EXECUTE 'CREATE INDEX IF NOT EXISTS ledger_outbox_lease_recovery_idx ON ledger_outbox (lease_expires_at) WHERE status = ''leased''';
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('provider_settlement_events') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE provider_settlement_events ADD COLUMN IF NOT EXISTS event_type VARCHAR(32) NOT NULL DEFAULT ''accepted'', ADD COLUMN IF NOT EXISTS provider_reference VARCHAR(255), ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT ''{}''::jsonb';
        EXECUTE 'CREATE INDEX IF NOT EXISTS provider_settlement_events_settlement_idx ON provider_settlement_events (tenant_id, settlement_id, occurred_at)';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS provider_callback_alerts (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(80) NOT NULL,
    provider_event_id VARCHAR(255) NOT NULL,
    alert_type VARCHAR(64) NOT NULL CHECK (alert_type IN ('payload_hash_mismatch','unknown_settlement','provider_reference_mismatch','invalid_state_transition')),
    expected_payload_sha256 CHAR(64),
    observed_payload_sha256 CHAR(64) NOT NULL CHECK (observed_payload_sha256 ~ '^[0-9a-f]{64}$'),
    details JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS provider_callback_alerts_open_idx
    ON provider_callback_alerts (tenant_id, provider, created_at DESC);

DO $$
BEGIN
    IF to_regclass('reconciliation_breaks') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE reconciliation_breaks ADD COLUMN IF NOT EXISTS resolution_reason VARCHAR(1024), ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(255)';
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('financial_close_periods') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE financial_close_periods ADD CONSTRAINT financial_close_periods_tenant_id_unique UNIQUE (tenant_id, id)';
        EXECUTE 'ALTER TABLE financial_close_periods ADD COLUMN IF NOT EXISTS reopened_by VARCHAR(255), ADD COLUMN IF NOT EXISTS reopen_reason VARCHAR(1024), ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ';
        EXECUTE 'CREATE TABLE IF NOT EXISTS financial_close_events (id UUID PRIMARY KEY, tenant_id VARCHAR(255) NOT NULL, close_id UUID NOT NULL, event_type VARCHAR(32) NOT NULL CHECK (event_type IN (''requested'',''approved'',''reopened'')), actor_id VARCHAR(255) NOT NULL, details JSONB NOT NULL DEFAULT ''{}''::jsonb, occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), FOREIGN KEY (tenant_id, close_id) REFERENCES financial_close_periods (tenant_id, id) ON DELETE RESTRICT)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS financial_close_events_audit_idx ON financial_close_events (tenant_id, close_id, occurred_at)';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION prevent_financial_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'financial audit records are append-only';
END;
$$;
DROP TRIGGER IF EXISTS provider_callback_alerts_immutable ON provider_callback_alerts;
CREATE TRIGGER provider_callback_alerts_immutable BEFORE UPDATE OR DELETE ON provider_callback_alerts
FOR EACH ROW EXECUTE FUNCTION prevent_financial_audit_mutation();

DO $$
BEGIN
    IF to_regclass('financial_close_events') IS NOT NULL THEN
        EXECUTE 'DROP TRIGGER IF EXISTS financial_close_events_immutable ON financial_close_events';
        EXECUTE 'CREATE TRIGGER financial_close_events_immutable BEFORE UPDATE OR DELETE ON financial_close_events FOR EACH ROW EXECUTE FUNCTION prevent_financial_audit_mutation()';
    END IF;
END $$;
