-- Indexes (guarded for fresh-DB safety; tables may be service-created).
DO $$
BEGIN
    IF to_regclass('ato_events') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS ato_events_tenant_user_created_idx ON ato_events (tenant_id, user_id, created_at DESC);';
    END IF;
    IF to_regclass('login_patterns') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS login_patterns_tenant_user_created_idx ON login_patterns (tenant_id, user_id, created_at DESC);';
        EXECUTE 'CREATE INDEX IF NOT EXISTS login_patterns_tenant_ip_created_idx ON login_patterns (tenant_id, ip_address, created_at DESC);';
    END IF;
    IF to_regclass('device_fingerprints') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS device_fingerprints_tenant_user_device_created_idx ON device_fingerprints (tenant_id, user_id, device_id, created_at DESC);';
    END IF;
    IF to_regclass('credential_stuffing_attempts') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS credential_stuffing_attempts_tenant_ip_created_idx ON credential_stuffing_attempts (tenant_id, ip_address, created_at DESC);';
    END IF;
    IF to_regclass('ato_alerts') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS ato_alerts_tenant_created_idx ON ato_alerts (tenant_id, created_at DESC);';
    END IF;
END $$;


-- Guarded ALTERs: base tables are created by 20260827_service_base_tables.sql
-- or by services at boot; skip gracefully if absent (fresh-DB migrate safe).
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
