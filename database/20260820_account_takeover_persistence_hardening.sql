

-- Step 1: column ADDs (guarded: base tables may be service-created or
-- from 20260827_service_base_tables.sql; skip gracefully if absent).
DO $$
BEGIN
    IF to_regclass('ato_events') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE ato_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
        EXECUTE 'ALTER TABLE ato_events ADD COLUMN IF NOT EXISTS indicators TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];';
    END IF;
    IF to_regclass('login_patterns') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE login_patterns ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
        EXECUTE 'ALTER TABLE login_patterns ADD COLUMN IF NOT EXISTS user_agent TEXT;';
    END IF;
    IF to_regclass('device_fingerprints') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE device_fingerprints ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
    IF to_regclass('credential_stuffing_attempts') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE credential_stuffing_attempts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
    IF to_regclass('ato_alerts') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE ato_alerts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);';
    END IF;
END $$;

-- Step 2: indexes (guarded on table AND column existence; columns come
-- from Step 1 above or the base-table migration).
DO $$
BEGIN
    IF to_regclass('ato_events') IS NOT NULL AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ato_events' AND column_name='created_at') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ato_events' AND column_name='tenant_id') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ato_events' AND column_name='user_id') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS ato_events_tenant_user_created_idx ON ato_events (tenant_id, user_id, created_at DESC);';
    END IF;
    IF to_regclass('login_patterns') IS NOT NULL AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='login_patterns' AND column_name='created_at') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='login_patterns' AND column_name='ip_address') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='login_patterns' AND column_name='tenant_id') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='login_patterns' AND column_name='user_id') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS login_patterns_tenant_user_created_idx ON login_patterns (tenant_id, user_id, created_at DESC);';
        EXECUTE 'CREATE INDEX IF NOT EXISTS login_patterns_tenant_ip_created_idx ON login_patterns (tenant_id, ip_address, created_at DESC);';
    END IF;
    IF to_regclass('device_fingerprints') IS NOT NULL AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='device_fingerprints' AND column_name='created_at') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='device_fingerprints' AND column_name='device_id') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='device_fingerprints' AND column_name='tenant_id') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='device_fingerprints' AND column_name='user_id') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS device_fingerprints_tenant_user_device_created_idx ON device_fingerprints (tenant_id, user_id, device_id, created_at DESC);';
    END IF;
    IF to_regclass('credential_stuffing_attempts') IS NOT NULL AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='credential_stuffing_attempts' AND column_name='created_at') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='credential_stuffing_attempts' AND column_name='ip_address') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='credential_stuffing_attempts' AND column_name='tenant_id') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS credential_stuffing_attempts_tenant_ip_created_idx ON credential_stuffing_attempts (tenant_id, ip_address, created_at DESC);';
    END IF;
    IF to_regclass('ato_alerts') IS NOT NULL AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ato_alerts' AND column_name='created_at') AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ato_alerts' AND column_name='tenant_id') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS ato_alerts_tenant_created_idx ON ato_alerts (tenant_id, created_at DESC);';
    END IF;
END $$;
