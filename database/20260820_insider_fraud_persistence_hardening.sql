BEGIN;

ALTER TABLE insider_fraud_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE insider_fraud_events ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE privileged_access_logs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE privileged_access_logs ADD COLUMN IF NOT EXISTS location VARCHAR(255);
ALTER TABLE unusual_activities ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE data_exfiltration_attempts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE insider_fraud_alerts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS insider_fraud_events_tenant_employee_created_idx
    ON insider_fraud_events (tenant_id, employee_id, created_at DESC);
CREATE INDEX IF NOT EXISTS privileged_access_logs_tenant_employee_created_idx
    ON privileged_access_logs (tenant_id, employee_id, created_at DESC);
CREATE INDEX IF NOT EXISTS privileged_access_logs_tenant_resource_created_idx
    ON privileged_access_logs (tenant_id, resource, created_at DESC);
CREATE INDEX IF NOT EXISTS unusual_activities_tenant_employee_created_idx
    ON unusual_activities (tenant_id, employee_id, created_at DESC);
CREATE INDEX IF NOT EXISTS data_exfiltration_attempts_tenant_employee_created_idx
    ON data_exfiltration_attempts (tenant_id, employee_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS insider_fraud_alerts_tenant_created_idx
    ON insider_fraud_alerts (tenant_id, created_at DESC);

COMMIT;
