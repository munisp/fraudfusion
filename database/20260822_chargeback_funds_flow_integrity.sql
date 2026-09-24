BEGIN;

-- Fail deployment rather than silently accepting legacy rows that would weaken
-- tenant-scoped transaction identity or monetary integrity.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM chargeback_transactions
        WHERE tenant_id IS NULL OR transaction_id IS NULL OR customer_id IS NULL
           OR merchant_id IS NULL OR amount IS NULL OR amount <= 0
           OR currency IS NULL OR currency !~ '^[A-Z]{3}$'
    ) THEN
        RAISE EXCEPTION 'chargeback transaction integrity backfill is required before enforcing funds-flow constraints';
    END IF;
    IF EXISTS (
        SELECT 1 FROM dispute_records
        WHERE tenant_id IS NULL OR dispute_id IS NULL OR transaction_id IS NULL OR customer_id IS NULL
    ) THEN
        RAISE EXCEPTION 'dispute-record integrity backfill is required before enforcing funds-flow constraints';
    END IF;
END $$;

ALTER TABLE chargeback_transactions
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN transaction_id SET NOT NULL,
    ALTER COLUMN customer_id SET NOT NULL,
    ALTER COLUMN merchant_id SET NOT NULL,
    ALTER COLUMN amount SET NOT NULL,
    ALTER COLUMN currency SET NOT NULL;

ALTER TABLE dispute_records
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN dispute_id SET NOT NULL,
    ALTER COLUMN transaction_id SET NOT NULL,
    ALTER COLUMN customer_id SET NOT NULL;

ALTER TABLE chargeback_transactions
    DROP CONSTRAINT IF EXISTS chargeback_transactions_positive_amount,
    ADD CONSTRAINT chargeback_transactions_positive_amount CHECK (amount > 0),
    DROP CONSTRAINT IF EXISTS chargeback_transactions_currency_iso4217,
    ADD CONSTRAINT chargeback_transactions_currency_iso4217 CHECK (currency ~ '^[A-Z]{3}$');

-- The application uses the unique index for idempotency. Ensure it exists
-- (service boot normally creates it; a migration-only chain does not), then
-- promote it to a named constraint so PostgreSQL can enforce tenant-scoped
-- dispute references. Guarded on table+column presence for fresh-DB safety.
DO $$
BEGIN
    IF to_regclass('chargeback_transactions') IS NOT NULL
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='chargeback_transactions' AND column_name='tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='chargeback_transactions' AND column_name='transaction_id')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chargeback_transactions_tenant_transaction_key')
    THEN
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'chargeback_transactions_tenant_transaction_key') THEN
            EXECUTE 'CREATE UNIQUE INDEX chargeback_transactions_tenant_transaction_key
                     ON chargeback_transactions (tenant_id, transaction_id)';
        END IF;
        EXECUTE 'ALTER TABLE chargeback_transactions
                 ADD CONSTRAINT chargeback_transactions_tenant_transaction_key
                 UNIQUE USING INDEX chargeback_transactions_tenant_transaction_key';
    END IF;
END $$;

-- FK depends on the tenant_transaction_key constraint above; skip gracefully
-- if the constraint could not be created (fresh-DB ordering safety).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chargeback_transactions_tenant_transaction_key')
       AND to_regclass('dispute_records') IS NOT NULL
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='dispute_records' AND column_name='tenant_id')
    THEN
        EXECUTE 'ALTER TABLE dispute_records
            DROP CONSTRAINT IF EXISTS dispute_records_transaction_tenant_fk,
            ADD CONSTRAINT dispute_records_transaction_tenant_fk
            FOREIGN KEY (tenant_id, transaction_id)
            REFERENCES chargeback_transactions (tenant_id, transaction_id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION prevent_chargeback_transaction_payload_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.transaction_id IS DISTINCT FROM NEW.transaction_id
       OR OLD.customer_id IS DISTINCT FROM NEW.customer_id
       OR OLD.merchant_id IS DISTINCT FROM NEW.merchant_id
       OR OLD.amount IS DISTINCT FROM NEW.amount
       OR OLD.currency IS DISTINCT FROM NEW.currency THEN
        RAISE EXCEPTION 'chargeback transaction payload is immutable after insertion';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS chargeback_transactions_payload_immutable ON chargeback_transactions;
CREATE TRIGGER chargeback_transactions_payload_immutable
BEFORE UPDATE ON chargeback_transactions
FOR EACH ROW EXECUTE FUNCTION prevent_chargeback_transaction_payload_mutation();

COMMIT;
