BEGIN;

CREATE TABLE IF NOT EXISTS ledger_outbox (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    journal_id UUID NOT NULL,
    event_type VARCHAR(64) NOT NULL CHECK (event_type IN ('settlement.submit','settlement.reverse','reconciliation.request')),
    idempotency_key VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','published','failed','dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_expires_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, event_type, idempotency_key),
    FOREIGN KEY (tenant_id, journal_id) REFERENCES ledger_journals (tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ledger_outbox_dispatch_idx ON ledger_outbox (status, available_at) WHERE status IN ('pending','failed');

CREATE TABLE IF NOT EXISTS financial_close_periods (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open' CHECK (status IN ('open','review','closed','reopened')),
    requested_by VARCHAR(255),
    approved_by VARCHAR(255),
    ledger_snapshot_sha256 CHAR(64),
    closed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (period_end >= period_start),
    UNIQUE (tenant_id, period_start, period_end)
);

CREATE OR REPLACE FUNCTION enforce_financial_close()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE unresolved_breaks INTEGER;
BEGIN
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
    IF OLD.status = 'closed' AND NEW.status <> 'reopened' THEN
        RAISE EXCEPTION 'closed financial period may only transition to reopened';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS financial_close_guard ON financial_close_periods;
CREATE TRIGGER financial_close_guard BEFORE UPDATE ON financial_close_periods
FOR EACH ROW EXECUTE FUNCTION enforce_financial_close();

COMMIT;
