BEGIN;

ALTER TABLE ato_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE ato_events ADD COLUMN IF NOT EXISTS indicators TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE login_patterns ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE login_patterns ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE device_fingerprints ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE credential_stuffing_attempts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE ato_alerts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS ato_events_tenant_user_created_idx
    ON ato_events (tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS login_patterns_tenant_user_created_idx
    ON login_patterns (tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS login_patterns_tenant_ip_created_idx
    ON login_patterns (tenant_id, ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS device_fingerprints_tenant_user_device_created_idx
    ON device_fingerprints (tenant_id, user_id, device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS credential_stuffing_attempts_tenant_ip_created_idx
    ON credential_stuffing_attempts (tenant_id, ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS ato_alerts_tenant_created_idx
    ON ato_alerts (tenant_id, created_at DESC);

COMMIT;
