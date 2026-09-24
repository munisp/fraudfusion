-- Indexes (guarded for fresh-DB safety; tables may be service-created).
DO $$
BEGIN
    IF to_regclass('chargeback_transactions') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS chargeback_transactions_tenant_customer_created_idx ON chargeback_transactions (tenant_id, customer_id, created_at DESC);';
        EXECUTE 'CREATE INDEX IF NOT EXISTS chargeback_transactions_tenant_merchant_created_idx ON chargeback_transactions (tenant_id, merchant_id, created_at DESC);';
    END IF;
    IF to_regclass('dispute_records') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS dispute_records_tenant_customer_created_idx ON dispute_records (tenant_id, customer_id, created_at DESC);';
    END IF;
    IF to_regclass('friendly_fraud_cases') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS friendly_fraud_cases_tenant_customer_created_idx ON friendly_fraud_cases (tenant_id, customer_id, created_at DESC);';
    END IF;
    IF to_regclass('chargeback_risk_decisions') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS chargeback_risk_decisions_tenant_subject_created_idx ON chargeback_risk_decisions (tenant_id, subject_id, created_at DESC);';
    END IF;
END $$;


-- Guarded ALTERs: base tables are created by 20260827_service_base_tables.sql
-- or by services at boot; skip gracefully if absent (fresh-DB migrate safe).
DO $$
BEGIN
    IF to_regclass('chargeback_transactions') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE chargeback_transactions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
    IF to_regclass('friendly_fraud_cases') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE friendly_fraud_cases ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
    IF to_regclass('chargeback_abuse_patterns') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE chargeback_abuse_patterns ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
    IF to_regclass('dispute_records') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE dispute_records ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
        EXECUTE 'ALTER TABLE dispute_records ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255);';
        EXECUTE 'ALTER TABLE dispute_records ADD COLUMN IF NOT EXISTS description TEXT;';
    END IF;
    IF to_regclass('chargeback_alerts') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE chargeback_alerts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
END $$;
