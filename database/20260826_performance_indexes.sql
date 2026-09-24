-- ============================================================================
-- Performance indexes (Lane B2 audit remediation, DB1/DB2/DB5)
-- ============================================================================
-- Idempotent: every statement uses IF NOT EXISTS, so the file is safe to
-- re-run. For zero-downtime deploys on large tables, run the CONCURRENTLY
-- variants manually outside a transaction block (CREATE INDEX CONCURRENTLY
-- cannot run inside a transaction); the plain CREATE INDEX IF NOT EXISTS
-- forms below are chosen for migration-runner compatibility and lock only
-- briefly on mostly-empty/new tables.
--
-- After applying on a populated database, run ANALYZE on the touched tables
-- (see bottom) so the planner picks up the new indexes immediately.
-- ============================================================================

-- ---------- aml-monitor hot paths (repository.go) ----------
-- aml_* tables are created at aml-monitor boot (repository.go), so they may
-- not exist when this migration runs on a fresh database. Guard every index
-- with to_regclass so Migrate() never fails with "relation does not exist";
-- re-running this file after the services have booted applies any indexes
-- that were skipped (all statements are idempotent).
DO $$
BEGIN
    IF to_regclass('aml_transaction_analyses') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_txn_analyses_flagged_created_idx ON aml_transaction_analyses (flagged, created_at DESC)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_txn_analyses_user_created_idx ON aml_transaction_analyses (user_id, created_at DESC)';
        -- Partial index for the hottest predicate: flagged rows only.
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_txn_analyses_flagged_only_idx ON aml_transaction_analyses (created_at DESC) WHERE flagged';
    END IF;
    IF to_regclass('aml_patterns') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_patterns_user_detected_idx ON aml_patterns (user_id, detected_at DESC)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_patterns_detected_idx ON aml_patterns (detected_at DESC)';
    END IF;
    IF to_regclass('aml_sars') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_sars_status_created_idx ON aml_sars (status, created_at DESC)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_sars_created_idx ON aml_sars (created_at DESC)';
    END IF;
    IF to_regclass('aml_sanctions_checks') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_sanctions_entity_checked_idx ON aml_sanctions_checks (entity_name, checked_at DESC)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_sanctions_checked_idx ON aml_sanctions_checks (checked_at DESC)';
    END IF;
    IF to_regclass('aml_sof_verifications') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS aml_sof_user_created_idx ON aml_sof_verifications (user_id, created_at DESC)';
    END IF;
END $$;

-- ---------- account-takeover velocity features ----------
-- login_patterns is scanned per request over a 24h/30d tenant+user window
-- and receives an INSERT per request (write amplification). The table is
-- created by the account-takeover service at boot, so guard it.
DO $$
BEGIN
    IF to_regclass('login_patterns') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS login_patterns_tenant_user_created_idx ON login_patterns (tenant_id, user_id, created_at DESC)';
    END IF;
END $$;

-- ---------- crypto-fraud detector rule engine ----------
-- COUNT(*) velocity scans + wallet lookups per score call. Tables are
-- service-created at boot; guard each.
DO $$
BEGIN
    IF to_regclass('crypto_transactions') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS crypto_transactions_user_ts_idx ON crypto_transactions (user_id, "timestamp" DESC)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS crypto_transactions_wallet_idx ON crypto_transactions (wallet_address)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS crypto_transactions_user_platform_ts_idx ON crypto_transactions (user_id, "timestamp" DESC) WHERE platform LIKE ''%p2p%''';
    END IF;
    IF to_regclass('crypto_blacklist') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS crypto_blacklist_wallet_idx ON crypto_blacklist (wallet_address)';
    END IF;
    IF to_regclass('p2p_trades') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS p2p_trades_seller_created_idx ON p2p_trades (seller_id, created_at DESC)';
    END IF;
    IF to_regclass('p2p_trading_alerts') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS p2p_trading_alerts_trade_idx ON p2p_trading_alerts (trade_id, detected_at DESC)';
    END IF;
END $$;

-- ---------- investment / sim-swap / advance-fee detector tables ----------
-- These services create tables at startup; index their hot columns.
DO $$
BEGIN
    IF to_regclass('investment_schemes') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS investment_schemes_created_idx ON investment_schemes (created_at DESC)';
    END IF;
    IF to_regclass('sim_swap_events') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS sim_swap_events_user_ts_idx ON sim_swap_events (user_id, created_at DESC)';
    END IF;
    IF to_regclass('advance_fee_cases') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS advance_fee_cases_created_idx ON advance_fee_cases (created_at DESC)';
    END IF;
END $$;

-- ---------- fraud alerts / audit / sessions ----------
DO $$
BEGIN
    IF to_regclass('fraud_alerts') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS fraud_alerts_tenant_created_idx ON fraud_alerts (tenant_id, created_at DESC)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS fraud_alerts_open_idx ON fraud_alerts (created_at DESC) WHERE status IN (''open'',''new'',''pending'')';
    END IF;
    IF to_regclass('audit_events') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS audit_events_tenant_ts_idx ON audit_events (tenant_id, created_at DESC)';
    END IF;
    IF to_regclass('audit_log') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS audit_log_tenant_ts_idx ON audit_log (tenant_id, created_at DESC)';
    END IF;
    IF to_regclass('sessions') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS sessions_user_expiry_idx ON sessions (user_id, expires_at)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS sessions_expired_idx ON sessions (expires_at) WHERE expires_at < NOW()';
    END IF;
    IF to_regclass('tokens') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS tokens_user_expiry_idx ON tokens (user_id, expires_at)';
    END IF;
END $$;

-- ---------- ledger outbox leased-recovery path (DB3) ----------
-- Dispatcher recovery scans status='leased' AND lease_expires_at <= NOW();
-- the existing dispatch partial index does not cover it.
DO $$
BEGIN
    IF to_regclass('ledger_outbox') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS ledger_outbox_lease_recovery_idx ON ledger_outbox (lease_expires_at) WHERE status = ''leased''';
    END IF;
END $$;

-- ---------- planner statistics ----------
-- Run after bulk loads / index creation so the planner uses the new indexes.
ANALYZE;
