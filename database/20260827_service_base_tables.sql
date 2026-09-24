-- Base tables for the fraud-detector services.
--
-- The 20260820_* hardening migrations only ALTER these tables, so on a fresh
-- database they depend on the tables existing. This migration creates every
-- table the Go/Python detector services query, with the exact columns those
-- services read and write (verified by grepping services/go and
-- services/python), and is fully idempotent (CREATE TABLE IF NOT EXISTS,
-- INSERT ... ON CONFLICT DO NOTHING).
--
-- Tenant columns are included wherever a service filters by tenant_id.

BEGIN;

-- ---------------------------------------------------------------------------
-- account-takeover-detector (services/python/account-takeover-detector)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ato_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    indicators TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ato_alerts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS login_patterns (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(100),
    device_id VARCHAR(255),
    location VARCHAR(255),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Shared with sim-swap-detector (services/go/sim-swap-detector), which filters
-- on first_seen_at — the column the previous schema lacked.
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    fingerprint TEXT,
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    device_model VARCHAR(255),
    os VARCHAR(100),
    os_version VARCHAR(100),
    ip_address VARCHAR(100),
    location VARCHAR(255),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, device_id)
);

CREATE TABLE IF NOT EXISTS credential_stuffing_attempts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(100),
    failed_attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- sim-swap-detector (services/go/sim-swap-detector)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sim_swap_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    event_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    phone_number VARCHAR(50),
    old_sim_id VARCHAR(100),
    new_sim_id VARCHAR(100),
    telco VARCHAR(50),
    swap_timestamp TIMESTAMPTZ NOT NULL,
    location VARCHAR(255),
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(50),
    is_fraud BOOLEAN NOT NULL DEFAULT FALSE,
    red_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS account_access_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    access_id VARCHAR(255),
    user_id VARCHAR(255) NOT NULL,
    device_id VARCHAR(255),
    access_type VARCHAR(50) NOT NULL, -- login, otp_request, settings_change, transfer
    success BOOLEAN NOT NULL DEFAULT TRUE,
    ip_address VARCHAR(100),
    location VARCHAR(255),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sim_swap_alerts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    event_id VARCHAR(255),
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(50),
    red_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS blocked_accounts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    reason TEXT,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- insider-fraud-detector (services/go/insider-fraud-detector)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS insider_fraud_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    employee_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS privileged_access_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    employee_id VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(100),
    ip_address VARCHAR(100),
    location VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS unusual_activities (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    employee_id VARCHAR(255) NOT NULL,
    activity_type VARCHAR(100) NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS data_exfiltration_attempts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    employee_id VARCHAR(255) NOT NULL,
    data_volume BIGINT NOT NULL DEFAULT 0,
    destination VARCHAR(255),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS insider_fraud_alerts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    employee_id VARCHAR(255) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- crypto-fraud-detector (services/go/crypto-fraud-detector)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS crypto_transactions (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    wallet_address VARCHAR(255),
    cryptocurrency VARCHAR(50),
    amount NUMERIC NOT NULL DEFAULT 0,
    transaction_type VARCHAR(50),
    platform VARCHAR(100),
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(50),
    flagged BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS crypto_blacklist (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    wallet_address VARCHAR(255) NOT NULL,
    reason TEXT,
    blacklisted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (wallet_address)
);

CREATE TABLE IF NOT EXISTS p2p_trades (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    seller_id VARCHAR(255) NOT NULL,
    buyer_id VARCHAR(255) NOT NULL,
    amount NUMERIC NOT NULL DEFAULT 0,
    currency VARCHAR(20) NOT NULL,
    price_per_unit NUMERIC NOT NULL DEFAULT 0,
    platform VARCHAR(100),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    disputed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS p2p_trading_alerts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    trade_id VARCHAR(255),
    seller_id VARCHAR(255),
    buyer_id VARCHAR(255),
    amount NUMERIC NOT NULL DEFAULT 0,
    currency VARCHAR(20),
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    description TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- advance-fee-fraud-detector (services/go/advance-fee-fraud-detector)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS advance_fee_messages (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    message_id VARCHAR(255) NOT NULL UNIQUE,
    user_id VARCHAR(255),
    sender_email VARCHAR(255),
    sender_name VARCHAR(255),
    subject TEXT,
    content TEXT,
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(50),
    scam_type VARCHAR(100),
    is_419_scam BOOLEAN NOT NULL DEFAULT FALSE,
    red_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- investment-fraud-detector (services/go/investment-fraud-detector)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS investment_schemes (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    name VARCHAR(500) NOT NULL,
    promoter_id VARCHAR(255),
    investment_type VARCHAR(100),
    promised_returns DOUBLE PRECISION NOT NULL DEFAULT 0,
    min_investment NUMERIC NOT NULL DEFAULT 0,
    description TEXT,
    website VARCHAR(500),
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(50),
    is_ponzi BOOLEAN NOT NULL DEFAULT FALSE,
    sec_registered BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- SEC Nigeria registered entities (capital market operators / fund managers).
-- Seeded below with a small sample; operators must sync the full SEC Nigeria
-- register for production use.
CREATE TABLE IF NOT EXISTS sec_registered_entities (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    name VARCHAR(500) NOT NULL,
    promoter_id VARCHAR(255),
    registration_number VARCHAR(100),
    entity_type VARCHAR(100),
    registered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS investment_blacklist (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    scheme_name VARCHAR(500) NOT NULL,
    reason TEXT,
    blacklisted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheme_referrals (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    scheme_id VARCHAR(255) NOT NULL,
    referrer_id VARCHAR(255),
    referee_id VARCHAR(255),
    level INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheme_documents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    scheme_id VARCHAR(255) NOT NULL,
    doc_type VARCHAR(50) NOT NULL, -- audit, financial, prospectus
    document_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheme_payments (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    scheme_id VARCHAR(255) NOT NULL,
    payment_type VARCHAR(50) NOT NULL, -- deposit, return
    source VARCHAR(100), -- new_investment, revenue
    amount NUMERIC NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS investor_losses (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    investor_id VARCHAR(255) NOT NULL,
    scheme_id VARCHAR(255),
    amount NUMERIC NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sec_reports (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    scheme_id VARCHAR(255) NOT NULL,
    report_type VARCHAR(100) NOT NULL,
    description TEXT,
    filed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- identity-theft-detector (services/python/identity-theft-detector)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_theft_alerts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    alert_id VARCHAR(255),
    user_id VARCHAR(255) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Seed data: sample SEC Nigeria registered entities (idempotent).
-- Sample entries only — sync the full SEC register in production.
-- ---------------------------------------------------------------------------

INSERT INTO sec_registered_entities (name, promoter_id, registration_number, entity_type, registered_at) VALUES
    ('Stanbic IBTC Asset Management Limited', 'PROM-STANBIC-AM', 'SEC/CMO/AM-001', 'fund_manager', '2012-01-01'),
    ('ARM Investment Managers Limited', 'PROM-ARM-IM', 'SEC/CMO/AM-002', 'fund_manager', '2011-06-01'),
    ('United Capital Asset Management Limited', 'PROM-UCAP-AM', 'SEC/CMO/AM-003', 'fund_manager', '2012-09-01'),
    ('Chapel Hill Denham Management Limited', 'PROM-CHD-MGT', 'SEC/CMO/AM-004', 'fund_manager', '2013-03-01'),
    ('FBNQuest Asset Management Limited', 'PROM-FBNQ-AM', 'SEC/CMO/AM-005', 'fund_manager', '2014-01-01'),
    ('Quantum Zenith Asset Management Limited', 'PROM-QZ-AM', 'SEC/CMO/AM-006', 'fund_manager', '2015-05-01')
ON CONFLICT (name) DO NOTHING;

COMMIT;
