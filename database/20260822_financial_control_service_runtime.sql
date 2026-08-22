BEGIN;

ALTER TABLE ledger_outbox
    ADD COLUMN IF NOT EXISTS leased_by VARCHAR(128),
    ADD COLUMN IF NOT EXISTS last_error VARCHAR(512),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS ledger_outbox_lease_recovery_idx
    ON ledger_outbox (lease_expires_at) WHERE status = 'leased';

ALTER TABLE provider_settlement_events
    ADD COLUMN IF NOT EXISTS event_type VARCHAR(32) NOT NULL DEFAULT 'accepted'
        CHECK (event_type IN ('accepted','settled','rejected','reversed')),
    ADD COLUMN IF NOT EXISTS provider_reference VARCHAR(255),
    ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS provider_settlement_events_settlement_idx
    ON provider_settlement_events (tenant_id, settlement_id, occurred_at);

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

ALTER TABLE reconciliation_breaks
    ADD COLUMN IF NOT EXISTS resolution_reason VARCHAR(1024),
    ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(255);

ALTER TABLE financial_close_periods
    ADD CONSTRAINT financial_close_periods_tenant_id_unique UNIQUE (tenant_id, id);

CREATE TABLE IF NOT EXISTS financial_close_events (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    close_id UUID NOT NULL,
    event_type VARCHAR(32) NOT NULL CHECK (event_type IN ('requested','approved','reopened')),
    actor_id VARCHAR(255) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (tenant_id, close_id) REFERENCES financial_close_periods (tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS financial_close_events_audit_idx
    ON financial_close_events (tenant_id, close_id, occurred_at);

ALTER TABLE financial_close_periods
    ADD COLUMN IF NOT EXISTS reopened_by VARCHAR(255),
    ADD COLUMN IF NOT EXISTS reopen_reason VARCHAR(1024),
    ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ;

CREATE OR REPLACE FUNCTION prevent_financial_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'financial audit records are append-only';
END;
$$;
DROP TRIGGER IF EXISTS provider_callback_alerts_immutable ON provider_callback_alerts;
CREATE TRIGGER provider_callback_alerts_immutable BEFORE UPDATE OR DELETE ON provider_callback_alerts
FOR EACH ROW EXECUTE FUNCTION prevent_financial_audit_mutation();
DROP TRIGGER IF EXISTS financial_close_events_immutable ON financial_close_events;
CREATE TRIGGER financial_close_events_immutable BEFORE UPDATE OR DELETE ON financial_close_events
FOR EACH ROW EXECUTE FUNCTION prevent_financial_audit_mutation();

CREATE OR REPLACE FUNCTION enforce_financial_close()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE unresolved_breaks INTEGER;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.period_start IS DISTINCT FROM OLD.period_start
       OR NEW.period_end IS DISTINCT FROM OLD.period_end
       OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
       OR NEW.ledger_snapshot_sha256 IS DISTINCT FROM OLD.ledger_snapshot_sha256 THEN
        RAISE EXCEPTION 'financial close identity, requester, period, and snapshot are immutable';
    END IF;
    IF OLD.status = 'open' AND NEW.status <> 'review' THEN
        RAISE EXCEPTION 'financial close must move from open to review before approval';
    END IF;
    IF OLD.status = 'review' AND NEW.status NOT IN ('review','closed') THEN
        RAISE EXCEPTION 'financial close review may only be approved into closed state';
    END IF;
    IF OLD.status = 'closed' AND NEW.status <> 'reopened' THEN
        RAISE EXCEPTION 'closed financial period may only transition to reopened';
    END IF;
    IF OLD.status = 'reopened' AND NEW.status <> 'review' THEN
        RAISE EXCEPTION 'reopened financial period must return to review';
    END IF;
    IF NEW.status = 'closed' AND OLD.status <> 'closed' THEN
        IF NEW.approved_by IS NULL OR NEW.requested_by IS NULL OR NEW.approved_by = NEW.requested_by THEN
            RAISE EXCEPTION 'financial close requires distinct requester and approver';
        END IF;
        SELECT COUNT(*) INTO unresolved_breaks
          FROM reconciliation_breaks rb
          JOIN reconciliation_runs rr ON rr.id = rb.reconciliation_run_id AND rr.tenant_id = rb.tenant_id
         WHERE rb.tenant_id = NEW.tenant_id
           AND rb.status IN ('open','investigating')
           AND rb.severity IN ('high','critical')
           AND rr.statement_as_of BETWEEN NEW.period_start AND NEW.period_end;
        IF unresolved_breaks > 0 THEN
            RAISE EXCEPTION 'financial close blocked by % unresolved high/critical reconciliation breaks', unresolved_breaks;
        END IF;
        IF NEW.ledger_snapshot_sha256 IS NULL OR NEW.ledger_snapshot_sha256 !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'financial close requires a ledger snapshot SHA-256';
        END IF;
        NEW.closed_at := NOW();
    END IF;
    IF NEW.status = 'reopened' AND OLD.status = 'closed' THEN
        IF NEW.reopened_by IS NULL OR NEW.reopen_reason IS NULL OR length(trim(NEW.reopen_reason)) < 8 THEN
            RAISE EXCEPTION 'reopening a financial close requires actor and substantive reason';
        END IF;
        NEW.reopened_at := NOW();
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS financial_close_guard ON financial_close_periods;
CREATE TRIGGER financial_close_guard BEFORE UPDATE ON financial_close_periods
FOR EACH ROW EXECUTE FUNCTION enforce_financial_close();

COMMIT;
