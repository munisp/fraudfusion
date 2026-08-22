BEGIN;

CREATE TABLE IF NOT EXISTS ledger_accounts (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    account_code VARCHAR(100) NOT NULL,
    account_type VARCHAR(32) NOT NULL CHECK (account_type IN ('asset','liability','equity','revenue','expense','clearing')),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','closed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, account_code, currency),
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ledger_journals (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    idempotency_key VARCHAR(255) NOT NULL,
    command_sha256 CHAR(64) NOT NULL CHECK (command_sha256 ~ '^[0-9a-f]{64}$'),
    journal_type VARCHAR(40) NOT NULL CHECK (journal_type IN ('authorization','capture','settlement','reversal','fee','adjustment')),
    status VARCHAR(16) NOT NULL DEFAULT 'posted' CHECK (status IN ('posted','reversed')),
    external_reference VARCHAR(255),
    actor_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, idempotency_key),
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ledger_postings (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    journal_id UUID NOT NULL,
    account_id UUID NOT NULL,
    direction CHAR(1) NOT NULL CHECK (direction IN ('D','C')),
    amount NUMERIC(20,6) NOT NULL CHECK (amount > 0),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (tenant_id, journal_id) REFERENCES ledger_journals (tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, account_id) REFERENCES ledger_accounts (tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ledger_postings_tenant_journal_idx ON ledger_postings (tenant_id, journal_id);
CREATE INDEX IF NOT EXISTS ledger_postings_tenant_account_idx ON ledger_postings (tenant_id, account_id, created_at);

CREATE OR REPLACE FUNCTION prevent_ledger_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ledger journals and postings are append-only; create a reversal journal instead';
END;
$$;
DROP TRIGGER IF EXISTS ledger_journals_immutable ON ledger_journals;
CREATE TRIGGER ledger_journals_immutable BEFORE UPDATE OR DELETE ON ledger_journals
FOR EACH ROW EXECUTE FUNCTION prevent_ledger_mutation();
DROP TRIGGER IF EXISTS ledger_postings_immutable ON ledger_postings;
CREATE TRIGGER ledger_postings_immutable BEFORE UPDATE OR DELETE ON ledger_postings
FOR EACH ROW EXECUTE FUNCTION prevent_ledger_mutation();

CREATE OR REPLACE FUNCTION validate_balanced_journal()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_journal UUID := COALESCE(NEW.journal_id, OLD.journal_id);
    target_tenant VARCHAR(255) := COALESCE(NEW.tenant_id, OLD.tenant_id);
    posting_count INTEGER;
    imbalance NUMERIC(20,6);
    currency_count INTEGER;
BEGIN
    SELECT COUNT(*),
           COALESCE(SUM(CASE direction WHEN 'D' THEN amount ELSE -amount END), 0),
           COUNT(DISTINCT currency)
      INTO posting_count, imbalance, currency_count
      FROM ledger_postings
     WHERE tenant_id = target_tenant AND journal_id = target_journal;
    IF posting_count < 2 THEN
        RAISE EXCEPTION 'journal % requires at least two postings', target_journal;
    END IF;
    IF currency_count <> 1 OR imbalance <> 0 THEN
        RAISE EXCEPTION 'journal % is not balanced within one currency', target_journal;
    END IF;
    RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS ledger_journal_balanced ON ledger_postings;
CREATE CONSTRAINT TRIGGER ledger_journal_balanced
AFTER INSERT ON ledger_postings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_balanced_journal();

CREATE TABLE IF NOT EXISTS settlement_items (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    journal_id UUID NOT NULL,
    provider VARCHAR(80) NOT NULL,
    provider_reference VARCHAR(255),
    direction VARCHAR(8) NOT NULL CHECK (direction IN ('inbound','outbound')),
    amount NUMERIC(20,6) NOT NULL CHECK (amount > 0),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    status VARCHAR(24) NOT NULL CHECK (status IN ('pending','submitted','accepted','settled','rejected','reversed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, provider, provider_reference),
    FOREIGN KEY (tenant_id, journal_id) REFERENCES ledger_journals (tenant_id, id) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION enforce_settlement_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.journal_id IS DISTINCT FROM OLD.journal_id
       OR NEW.provider IS DISTINCT FROM OLD.provider
       OR NEW.amount IS DISTINCT FROM OLD.amount
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.direction IS DISTINCT FROM OLD.direction THEN
        RAISE EXCEPTION 'settlement identity and amount fields are immutable';
    END IF;
    IF NOT ((OLD.status = 'pending' AND NEW.status IN ('submitted','rejected'))
         OR (OLD.status = 'submitted' AND NEW.status IN ('accepted','rejected'))
         OR (OLD.status = 'accepted' AND NEW.status IN ('settled','rejected'))
         OR (OLD.status = 'settled' AND NEW.status = 'reversed')) THEN
        RAISE EXCEPTION 'invalid settlement state transition: % -> %', OLD.status, NEW.status;
    END IF;
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS settlement_transition_guard ON settlement_items;
CREATE TRIGGER settlement_transition_guard BEFORE UPDATE ON settlement_items
FOR EACH ROW EXECUTE FUNCTION enforce_settlement_transition();

CREATE TABLE IF NOT EXISTS provider_settlement_events (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(80) NOT NULL,
    provider_event_id VARCHAR(255) NOT NULL,
    settlement_id UUID,
    payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, provider_event_id),
    FOREIGN KEY (tenant_id, settlement_id) REFERENCES settlement_items (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS reconciliation_runs (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(80) NOT NULL,
    statement_sha256 CHAR(64) NOT NULL CHECK (statement_sha256 ~ '^[0-9a-f]{64}$'),
    statement_as_of DATE NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, provider, statement_sha256)
);

CREATE TABLE IF NOT EXISTS reconciliation_breaks (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    reconciliation_run_id UUID NOT NULL,
    settlement_id UUID,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    break_type VARCHAR(48) NOT NULL CHECK (break_type IN ('missing_internal','missing_provider','amount_mismatch','currency_mismatch','state_mismatch','timing_mismatch')),
    expected_payload JSONB NOT NULL,
    observed_payload JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolved','waived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolver_id VARCHAR(255),
    FOREIGN KEY (tenant_id, reconciliation_run_id) REFERENCES reconciliation_runs (tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, settlement_id) REFERENCES settlement_items (tenant_id, id) ON DELETE RESTRICT
);

COMMIT;
