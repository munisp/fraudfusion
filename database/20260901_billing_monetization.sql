-- Billing & monetization schema: subscription plans, tenant subscriptions,
-- metered API keys (hashed), usage events/rollups, and invoices.
--
-- Consumed by services/python/billing-service (:8400, /v1/billing/*).
-- Money is integer kobo everywhere (1 NGN = 100 kobo); never float.
--
-- Fresh-DB-safe and idempotent: every CREATE/ALTER is guarded with
-- to_regclass / information_schema DO blocks, INSERTs use ON CONFLICT.

BEGIN;

-- ---------------------------------------------------------------------------
-- tenants (create-if-missing guard; canonical definition lives in
-- database/20260826_tenants_onboarding.sql — the column shapes match).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.tenants') IS NULL THEN
        CREATE TABLE tenants (
            id            TEXT PRIMARY KEY,
            organization  TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            owner_sub     TEXT NOT NULL DEFAULT '',
            use_case      TEXT NOT NULL DEFAULT '',
            environment   TEXT NOT NULL DEFAULT 'sandbox'
                          CHECK (environment IN ('sandbox', 'production')),
            kyc_tier      TEXT NOT NULL DEFAULT 'basic'
                          CHECK (kyc_tier IN ('basic', 'enhanced', 'premium')),
            state         TEXT NOT NULL DEFAULT 'in_progress'
                          CHECK (state IN ('not_started', 'in_progress', 'pending_review', 'active', 'suspended')),
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- billing_plans: the four commercial tiers. Amounts in kobo.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.billing_plans') IS NULL THEN
        CREATE TABLE billing_plans (
            id                      TEXT PRIMARY KEY,           -- e.g. 'growth'
            display_name            TEXT NOT NULL,
            monthly_fee_kobo        BIGINT NOT NULL DEFAULT 0 CHECK (monthly_fee_kobo >= 0),
            -- JSONB: {operation: included_units_per_month}
            included_units          JSONB NOT NULL DEFAULT '{}'::jsonb,
            -- JSONB: {operation: overage_price_kobo_per_unit}
            overage_rates_kobo      JSONB NOT NULL DEFAULT '{}'::jsonb,
            -- JSONB array of scopes the plan may hold, e.g. ["fraud_score","aml_score"]
            allowed_scopes          JSONB NOT NULL DEFAULT '[]'::jsonb,
            default_rate_limit_rpm  INTEGER NOT NULL DEFAULT 60 CHECK (default_rate_limit_rpm > 0),
            is_active               BOOLEAN NOT NULL DEFAULT TRUE,
            created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    END IF;
END $$;

-- Seed the four tiers (idempotent). Overage per-call prices:
--   fraud_score NGN 0.40 = 40 kobo (growth) / 30 (scale)
--   aml_score   NGN 0.90 = 90 kobo (growth) / 70 (scale)
--   kyc_verify  NGN 120  = 12000 kobo / 10000
--   kgqa_query  NGN 2.50 = 250 kobo / 200
--   land_verification NGN 5,000 = 500000 kobo / 450000
INSERT INTO billing_plans
    (id, display_name, monthly_fee_kobo, included_units, overage_rates_kobo, allowed_scopes, default_rate_limit_rpm)
VALUES
    ('developer_sandbox', 'Developer Sandbox', 0,
     '{"fraud_score": 1000, "aml_score": 200, "kyc_verify": 20, "kgqa_query": 500, "land_verification": 0}'::jsonb,
     '{}'::jsonb,
     '["fraud_score", "aml_score", "kyc_verify", "kgqa_query"]'::jsonb, 30),
    ('growth', 'Growth', 15000000,              -- NGN 150,000 / month
     '{"fraud_score": 50000, "aml_score": 10000, "kyc_verify": 500, "kgqa_query": 20000, "land_verification": 10}'::jsonb,
     '{"fraud_score": 40, "aml_score": 90, "kyc_verify": 12000, "kgqa_query": 250, "land_verification": 500000}'::jsonb,
     '["fraud_score", "aml_score", "kyc_verify", "kgqa_query", "land_verification"]'::jsonb, 120),
    ('scale', 'Scale', 60000000,                -- NGN 600,000 / month
     '{"fraud_score": 300000, "aml_score": 60000, "kyc_verify": 3000, "kgqa_query": 120000, "land_verification": 60}'::jsonb,
     '{"fraud_score": 30, "aml_score": 70, "kyc_verify": 10000, "kgqa_query": 200, "land_verification": 450000}'::jsonb,
     '["fraud_score", "aml_score", "kyc_verify", "kgqa_query", "land_verification"]'::jsonb, 600),
    ('enterprise', 'Enterprise', 0,             -- custom pricing; rates overridden per contract
     '{}'::jsonb,
     '{}'::jsonb,
     '["fraud_score", "aml_score", "kyc_verify", "kgqa_query", "land_verification"]'::jsonb, 1200)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- billing_subscriptions: tenant -> plan, with billing period.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.billing_subscriptions') IS NULL THEN
        CREATE TABLE billing_subscriptions (
            id                  TEXT PRIMARY KEY,
            tenant_id           TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            plan_id             TEXT NOT NULL REFERENCES billing_plans (id),
            -- active | past_due | suspended | cancelled
            status              TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('trialing', 'active', 'past_due', 'suspended', 'cancelled')),
            -- YYYY-MM billing period in which the subscription became active.
            current_period_start DATE NOT NULL DEFAULT date_trunc('month', now())::date,
            current_period_end   DATE NOT NULL DEFAULT (date_trunc('month', now()) + interval '1 month' - interval '1 day')::date,
            -- Optional per-tenant negotiated overrides (enterprise):
            -- {"monthly_fee_kobo": ..., "included_units": {...}, "overage_rates_kobo": {...}}
            overrides           JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS billing_subscriptions_tenant_active_idx
    ON billing_subscriptions (tenant_id) WHERE status IN ('trialing', 'active', 'past_due');
CREATE INDEX IF NOT EXISTS billing_subscriptions_plan_idx
    ON billing_subscriptions (plan_id);

-- ---------------------------------------------------------------------------
-- api_keys: metered API keys. Only the SHA-256 hash + non-secret prefix are
-- stored; the plaintext is returned exactly once at issue/rotation time.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.api_keys') IS NULL THEN
        CREATE TABLE api_keys (
            id           TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            name         TEXT NOT NULL DEFAULT '',
            -- Non-secret prefix, e.g. "ffk_live_ab12cd34" (first 8 of the random part).
            key_prefix   TEXT NOT NULL,
            -- SHA-256 hex of the full plaintext key. NEVER store plaintext.
            key_hash     CHAR(64) NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
            -- JSONB array of operation scopes, e.g. ["fraud_score","kyc_verify"].
            scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,
            rate_limit_rpm INTEGER NOT NULL DEFAULT 60 CHECK (rate_limit_rpm > 0),
            -- active | suspended | revoked
            status       TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active', 'suspended', 'revoked')),
            expires_at   TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS api_keys_hash_idx ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS api_keys_status_idx ON api_keys (status);

-- ---------------------------------------------------------------------------
-- usage_events: one row per metered call. Idempotent on
-- (tenant_id, idempotency_key). amount_kobo is the rated value at ingestion
-- time for billable events that bypass inclusion accounting (e.g. ad-hoc).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.usage_events') IS NULL THEN
        CREATE TABLE usage_events (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            api_key_id      TEXT REFERENCES api_keys (id) ON DELETE SET NULL,
            service         TEXT NOT NULL,          -- e.g. 'fraud-scoring-service'
            operation       TEXT NOT NULL,          -- e.g. 'fraud_score'
            units           BIGINT NOT NULL DEFAULT 1 CHECK (units > 0),
            amount_kobo     BIGINT NOT NULL DEFAULT 0 CHECK (amount_kobo >= 0),
            idempotency_key TEXT NOT NULL,
            occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS usage_events_tenant_idem_idx
    ON usage_events (tenant_id, idempotency_key);
CREATE INDEX IF NOT EXISTS usage_events_tenant_op_time_idx
    ON usage_events (tenant_id, operation, occurred_at);
CREATE INDEX IF NOT EXISTS usage_events_key_idx
    ON usage_events (api_key_id);

-- ---------------------------------------------------------------------------
-- usage_rollups: monthly aggregate per tenant+operation. `period` is YYYY-MM.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.usage_rollups') IS NULL THEN
        CREATE TABLE usage_rollups (
            tenant_id   TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            period      CHAR(7) NOT NULL CHECK (period ~ '^[0-9]{4}-[0-9]{2}$'),
            operation   TEXT NOT NULL,
            units       BIGINT NOT NULL DEFAULT 0 CHECK (units >= 0),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, period, operation)
        );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- billing_invoices: monthly invoice per tenant. Line items are a JSONB array:
-- [{"kind": "subscription"|"overage", "operation": ..., "units": ...,
--   "unit_price_kobo": ..., "amount_kobo": ..., "description": ...}]
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.billing_invoices') IS NULL THEN
        CREATE TABLE billing_invoices (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            subscription_id TEXT REFERENCES billing_subscriptions (id) ON DELETE SET NULL,
            period          CHAR(7) NOT NULL CHECK (period ~ '^[0-9]{4}-[0-9]{2}$'),
            line_items      JSONB NOT NULL DEFAULT '[]'::jsonb,
            subtotal_kobo   BIGINT NOT NULL DEFAULT 0 CHECK (subtotal_kobo >= 0),
            -- VAT 7.5% on services (NG), computed at generation time
            -- (Decimal, ROUND_HALF_UP, whole kobo).
            vat_kobo        BIGINT NOT NULL DEFAULT 0 CHECK (vat_kobo >= 0),
            total_kobo      BIGINT NOT NULL DEFAULT 0 CHECK (total_kobo >= 0),
            currency        CHAR(3) NOT NULL DEFAULT 'NGN',
            -- draft -> issued -> paid | void
            status          TEXT NOT NULL DEFAULT 'draft'
                            CHECK (status IN ('draft', 'issued', 'paid', 'void')),
            due_date        DATE,
            issued_at       TIMESTAMPTZ,
            paid_at         TIMESTAMPTZ,
            -- Link into the double-entry ledger
            -- (database/20260822_double_entry_ledger_settlement_reconciliation.sql):
            -- when the invoice is paid, the settlement journal UUID posted to
            -- ledger_journals (DR accounts-receivable / CR revenue) is recorded
            -- here. No hard FK so this migration is safe on databases where
            -- the ledger tables have not been created yet.
            settlement_journal_id UUID,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, period)
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS billing_invoices_status_idx ON billing_invoices (status);
CREATE INDEX IF NOT EXISTS billing_invoices_tenant_idx ON billing_invoices (tenant_id, period);

-- Fresh-DB hardening: if the table predates this migration without the ledger
-- link column, add it now (guarded via information_schema).
DO $$
BEGIN
    IF to_regclass('public.billing_invoices') IS NOT NULL
       AND NOT EXISTS (
           SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'billing_invoices'
              AND column_name = 'settlement_journal_id') THEN
        ALTER TABLE billing_invoices ADD COLUMN settlement_journal_id UUID;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- dunning_events: audit trail of past_due -> suspended transitions.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.billing_dunning_events') IS NULL THEN
        CREATE TABLE billing_dunning_events (
            id           TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            invoice_id   TEXT REFERENCES billing_invoices (id) ON DELETE SET NULL,
            action       TEXT NOT NULL CHECK (action IN ('reminder', 'past_due', 'suspend_keys', 'grace', 'resume', 'write_off')),
            detail       TEXT NOT NULL DEFAULT '',
            actor        TEXT NOT NULL DEFAULT 'system',
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS billing_dunning_events_tenant_idx
    ON billing_dunning_events (tenant_id, created_at);

COMMIT;
