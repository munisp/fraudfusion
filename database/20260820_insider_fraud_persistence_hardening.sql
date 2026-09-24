-- Indexes (guarded for fresh-DB safety; tables may be service-created).
DO $$
BEGIN
    IF to_regclass('insider_fraud_events') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS insider_fraud_events_tenant_employee_created_idx ON insider_fraud_events (tenant_id, employee_id, created_at DESC);';
    END IF;
    IF to_regclass('privileged_access_logs') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS privileged_access_logs_tenant_employee_created_idx ON privileged_access_logs (tenant_id, employee_id, created_at DESC);';
        EXECUTE 'CREATE INDEX IF NOT EXISTS privileged_access_logs_tenant_resource_created_idx ON privileged_access_logs (tenant_id, resource, created_at DESC);';
    END IF;
    IF to_regclass('unusual_activities') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS unusual_activities_tenant_employee_created_idx ON unusual_activities (tenant_id, employee_id, created_at DESC);';
    END IF;
    IF to_regclass('data_exfiltration_attempts') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS data_exfiltration_attempts_tenant_employee_created_idx ON data_exfiltration_attempts (tenant_id, employee_id, detected_at DESC);';
    END IF;
    IF to_regclass('insider_fraud_alerts') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS insider_fraud_alerts_tenant_created_idx ON insider_fraud_alerts (tenant_id, created_at DESC);';
    END IF;
END $$;


-- Guarded ALTERs: base tables are created by 20260827_service_base_tables.sql
-- or by services at boot; skip gracefully if absent (fresh-DB migrate safe).
DO $$
BEGIN
    IF to_regclass('insider_fraud_events') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE insider_fraud_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
        EXECUTE 'ALTER TABLE insider_fraud_events ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT ''{}''::jsonb;';
    END IF;
    IF to_regclass('privileged_access_logs') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE privileged_access_logs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
        EXECUTE 'ALTER TABLE privileged_access_logs ADD COLUMN IF NOT EXISTS location VARCHAR(255);';
    END IF;
    IF to_regclass('unusual_activities') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE unusual_activities ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
    IF to_regclass('data_exfiltration_attempts') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE data_exfiltration_attempts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
    IF to_regclass('insider_fraud_alerts') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE insider_fraud_alerts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
END $$;
