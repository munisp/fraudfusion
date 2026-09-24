-- Tenant onboarding schema: tenants, tenant API keys (hashed), integration
-- checklist, and the staff approval workflow state consumed by
-- services/python/onboarding-service (/api/v1/onboarding/*).
-- Idempotent: safe to re-run.

BEGIN;

CREATE TABLE IF NOT EXISTS tenants (
    id              TEXT PRIMARY KEY,
    organization    TEXT NOT NULL,
    contact_email   TEXT NOT NULL,
    -- Keycloak subject of the user who created the tenant.
    owner_sub       TEXT NOT NULL,
    use_case        TEXT NOT NULL DEFAULT '',
    environment     TEXT NOT NULL DEFAULT 'sandbox'
                    CHECK (environment IN ('sandbox', 'production')),
    kyc_tier        TEXT NOT NULL DEFAULT 'basic'
                    CHECK (kyc_tier IN ('basic', 'enhanced', 'premium')),
    state           TEXT NOT NULL DEFAULT 'in_progress'
                    CHECK (state IN ('not_started', 'in_progress', 'pending_review', 'active', 'suspended')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One tenant per owner+organization pair.
CREATE UNIQUE INDEX IF NOT EXISTS tenants_owner_org_idx
    ON tenants (owner_sub, organization);

CREATE TABLE IF NOT EXISTS tenant_api_keys (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    label            TEXT NOT NULL DEFAULT '',
    environment      TEXT NOT NULL DEFAULT 'sandbox'
                     CHECK (environment IN ('sandbox', 'production')),
    -- pending -> reviewed -> approved (dual control: reviewer != approver);
    -- pending|reviewed -> rejected; approved -> revoked.
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'reviewed', 'approved', 'rejected', 'revoked')),
    -- SHA-256 hex of the secret key material. The plaintext key is shown to
    -- the requester exactly once at approval time and never stored.
    key_hash         TEXT,
    -- Non-secret prefix (e.g. "ffk_ab12cd34") for identification in UIs/logs.
    key_prefix       TEXT,
    requested_by     TEXT NOT NULL,
    reviewed_by      TEXT,
    approved_by      TEXT,
    rejection_reason TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tenant_api_keys_tenant_idx
    ON tenant_api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS tenant_api_keys_status_idx
    ON tenant_api_keys (status);

CREATE TABLE IF NOT EXISTS onboarding_checklist_items (
    tenant_id  TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    item_id    TEXT NOT NULL,
    label      TEXT NOT NULL,
    required   BOOLEAN NOT NULL DEFAULT TRUE,
    done       BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, item_id)
);

-- Audit trail for staff approval decisions (dual-control evidence).
CREATE TABLE IF NOT EXISTS onboarding_approval_events (
    id          TEXT PRIMARY KEY,
    api_key_id  TEXT NOT NULL REFERENCES tenant_api_keys (id) ON DELETE CASCADE,
    action      TEXT NOT NULL CHECK (action IN ('request', 'review', 'approve', 'reject', 'revoke')),
    actor_sub   TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS onboarding_approval_events_key_idx
    ON onboarding_approval_events (api_key_id);

COMMIT;
