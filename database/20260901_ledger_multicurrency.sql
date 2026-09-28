-- Ledger multi-currency support + journal reversal state machine.
--
-- 1. ledger_journals gains currency (default 'NGN' for existing rows),
--    fx_rate/fx_quote_id (both NULL or both set) and reverses_journal_id.
-- 2. The append-only trigger on ledger_journals is replaced with a
--    DB-checked state machine: the ONLY permitted UPDATE is
--    status: posted -> reversed (all other columns immutable). Deletes stay
--    forbidden. Reversing an already-reversed journal is impossible at the
--    database layer.
-- 3. validate_balanced_journal() is extended: single-currency journals must
--    net to zero as before; a two-currency journal is only balanced when
--    the journal carries an explicit fx_rate and the net debit in journal
--    currency * fx_rate equals the net credit in the other currency
--    (symmetric, so reversal journals with swapped directions also
--    balance).
--
-- Fresh-DB-safe and idempotent: every DDL step is guarded by catalog
-- checks so the file can be applied twice and on top of the
-- 20260822_double_entry_ledger_settlement_reconciliation.sql baseline.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Column additions (guarded).
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'ledger_journals' AND column_name = 'currency') THEN
        ALTER TABLE ledger_journals
            ADD COLUMN currency CHAR(3) NOT NULL DEFAULT 'NGN';
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'ledger_journals' AND column_name = 'fx_rate') THEN
        ALTER TABLE ledger_journals ADD COLUMN fx_rate NUMERIC(30,12);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'ledger_journals' AND column_name = 'fx_quote_id') THEN
        ALTER TABLE ledger_journals ADD COLUMN fx_quote_id VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'ledger_journals' AND column_name = 'reverses_journal_id') THEN
        ALTER TABLE ledger_journals ADD COLUMN reverses_journal_id UUID;
    END IF;
END $$;

-- Constraints are guarded by pg_constraint lookups (ADD CONSTRAINT IF NOT
-- EXISTS does not exist in PostgreSQL).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ledger_journals_currency_format') THEN
        ALTER TABLE ledger_journals
            ADD CONSTRAINT ledger_journals_currency_format CHECK (currency ~ '^[A-Z]{3}$');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ledger_journals_fx_pair') THEN
        ALTER TABLE ledger_journals
            ADD CONSTRAINT ledger_journals_fx_pair
            CHECK ((fx_rate IS NULL) = (fx_quote_id IS NULL) AND (fx_rate IS NULL OR fx_rate > 0));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Journal status state machine (posted -> reversed only).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION enforce_journal_status_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ledger journals are append-only; create a reversal journal instead';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.command_sha256 IS DISTINCT FROM OLD.command_sha256
       OR NEW.journal_type IS DISTINCT FROM OLD.journal_type
       OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
       OR NEW.external_reference IS DISTINCT FROM OLD.external_reference
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.fx_rate IS DISTINCT FROM OLD.fx_rate
       OR NEW.fx_quote_id IS DISTINCT FROM OLD.fx_quote_id
       OR NEW.reverses_journal_id IS DISTINCT FROM OLD.reverses_journal_id THEN
        RAISE EXCEPTION 'journal identity fields are immutable; only status may transition posted -> reversed';
    END IF;
    IF NOT (OLD.status = 'posted' AND NEW.status = 'reversed') THEN
        RAISE EXCEPTION 'invalid journal status transition: % -> % (only posted -> reversed is allowed)', OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS ledger_journals_immutable ON ledger_journals;
DROP TRIGGER IF EXISTS ledger_journal_status_transition ON ledger_journals;
CREATE TRIGGER ledger_journal_status_transition BEFORE UPDATE OR DELETE ON ledger_journals
FOR EACH ROW EXECUTE FUNCTION enforce_journal_status_transition();

-- Postings stay strictly append-only (unchanged function from 20260822,
-- recreated here only if missing).
CREATE OR REPLACE FUNCTION prevent_ledger_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ledger journals and postings are append-only; create a reversal journal instead';
END;
$$;
DROP TRIGGER IF EXISTS ledger_postings_immutable ON ledger_postings;
CREATE TRIGGER ledger_postings_immutable BEFORE UPDATE OR DELETE ON ledger_postings
FOR EACH ROW EXECUTE FUNCTION prevent_ledger_mutation();

-- ---------------------------------------------------------------------------
-- 3. Balanced-journal validation with optional fx pair.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_balanced_journal()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_journal UUID := COALESCE(NEW.journal_id, OLD.journal_id);
    target_tenant VARCHAR(255) := COALESCE(NEW.tenant_id, OLD.tenant_id);
    posting_count INTEGER;
    imbalance NUMERIC(30,12);
    currency_count INTEGER;
    journal_currency CHAR(3);
    journal_fx NUMERIC(30,12);
    net_journal_ccy NUMERIC(30,12);
    net_other_ccy NUMERIC(30,12);
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
    IF currency_count = 1 THEN
        IF imbalance <> 0 THEN
            RAISE EXCEPTION 'journal % is not balanced within one currency', target_journal;
        END IF;
        RETURN NULL;
    END IF;
    IF currency_count = 2 THEN
        -- Cross-currency journal: allowed only with an explicit fx quote on
        -- the journal. Net debit in the journal currency * fx_rate must
        -- equal net credit in the other currency (0.000001 tolerance for
        -- 6-decimal rounding of the converted leg). Symmetric so reversal
        -- journals (directions swapped) also balance.
        SELECT j.currency, j.fx_rate INTO journal_currency, journal_fx
          FROM ledger_journals j
         WHERE j.tenant_id = target_tenant AND j.id = target_journal;
        IF journal_fx IS NULL THEN
            RAISE EXCEPTION 'cross-currency journal % requires fx_rate and fx_quote_id', target_journal;
        END IF;
        SELECT COALESCE(SUM(CASE WHEN p.currency = journal_currency THEN CASE p.direction WHEN 'D' THEN p.amount ELSE -p.amount END ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN p.currency <> journal_currency THEN CASE p.direction WHEN 'C' THEN p.amount ELSE -p.amount END ELSE 0 END), 0)
          INTO net_journal_ccy, net_other_ccy
          FROM ledger_postings p
         WHERE p.tenant_id = target_tenant AND p.journal_id = target_journal;
        IF ABS(net_journal_ccy * journal_fx - net_other_ccy) > 0.000001 THEN
            RAISE EXCEPTION 'cross-currency journal % is not balanced at fx_rate %', target_journal, journal_fx;
        END IF;
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'journal % spans % currencies; at most two with an fx quote are allowed', target_journal, currency_count;
END;
$$;

COMMIT;
