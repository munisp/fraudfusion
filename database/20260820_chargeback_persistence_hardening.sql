BEGIN;

ALTER TABLE chargeback_transactions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE friendly_fraud_cases ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE chargeback_abuse_patterns ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE dispute_records ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE dispute_records ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255);
ALTER TABLE dispute_records ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE chargeback_alerts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);

CREATE TABLE IF NOT EXISTS chargeback_risk_decisions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    decision_type VARCHAR(100) NOT NULL,
    score NUMERIC(6,2) NOT NULL CHECK (score >= 0 AND score <= 100),
    payload JSONB NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS chargeback_transactions_tenant_transaction_key
    ON chargeback_transactions (tenant_id, transaction_id);
CREATE UNIQUE INDEX IF NOT EXISTS dispute_records_tenant_dispute_key
    ON dispute_records (tenant_id, dispute_id);
CREATE INDEX IF NOT EXISTS chargeback_transactions_tenant_customer_created_idx
    ON chargeback_transactions (tenant_id, customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS chargeback_transactions_tenant_merchant_created_idx
    ON chargeback_transactions (tenant_id, merchant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS dispute_records_tenant_customer_created_idx
    ON dispute_records (tenant_id, customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS friendly_fraud_cases_tenant_customer_created_idx
    ON friendly_fraud_cases (tenant_id, customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS chargeback_risk_decisions_tenant_subject_created_idx
    ON chargeback_risk_decisions (tenant_id, subject_id, created_at DESC);

COMMIT;
