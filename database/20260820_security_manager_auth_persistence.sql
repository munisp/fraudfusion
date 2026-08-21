BEGIN;

CREATE TABLE IF NOT EXISTS security_users (
    username VARCHAR(255) PRIMARY KEY,
    password_hash TEXT NOT NULL,
    email_encrypted TEXT NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('admin','analyst','viewer','api_user')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_login_failures (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    ip_address INET,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS security_login_failures_username_attempted_idx
    ON security_login_failures (username, attempted_at DESC);

COMMIT;
