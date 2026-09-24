-- PEP list, sanctions watchlist, KYB applications, merchant onboarding, and
-- regulator-access provisioning schema. Consumed by
-- services/python/kyc-api (pep_list, watchlist) and
-- services/python/onboarding-service (kyb_applications, merchant_applications,
-- regulator_access).
-- Idempotent: safe to re-run.

BEGIN;

-- Local PEP list for screening (app/screening.py in kyc-api). Rows are
-- loaded by compliance batch jobs; services never write here at request time.
CREATE TABLE IF NOT EXISTS pep_list (
    id              TEXT PRIMARY KEY,
    full_name       TEXT NOT NULL,
    date_of_birth   DATE,
    nationality     TEXT,
    position        TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'seed',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pep_list_name_idx ON pep_list (lower(full_name));

-- Local sanctions watchlist cache. Takes precedence over the kyc-api JSON
-- seed file when populated; live UN/OFAC/NFIU feeds load here.
CREATE TABLE IF NOT EXISTS watchlist (
    id              TEXT PRIMARY KEY,
    full_name       TEXT NOT NULL,
    date_of_birth   DATE,
    nationality     TEXT,
    passport_number TEXT,
    program         TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'local',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS watchlist_name_idx ON watchlist (lower(full_name));

-- KYB (Know Your Business) submissions: business documents + CAC number,
-- reviewed under dual control (reviewer != approver, never the submitter).
CREATE TABLE IF NOT EXISTS kyb_applications (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT REFERENCES tenants (id) ON DELETE SET NULL,
    business_name    TEXT NOT NULL,
    cac_number       TEXT NOT NULL,  -- CAC registration number, e.g. RC1234567
    business_type    TEXT NOT NULL DEFAULT 'limited_liability'
                     CHECK (business_type IN ('business_name', 'limited_liability', 'plc', 'ngo', 'partnership')),
    contact_email    TEXT NOT NULL,
    -- JSON array of submitted business documents:
    -- [{"type": "cac_certificate"|"memart"|"utility_bill"|"board_resolution", "reference": "..."}]
    documents        JSONB NOT NULL DEFAULT '[]',
    status           TEXT NOT NULL DEFAULT 'submitted'
                     CHECK (status IN ('submitted', 'under_review', 'approved', 'rejected')),
    submitted_by     TEXT NOT NULL,
    reviewed_by      TEXT,
    approved_by      TEXT,
    rejection_reason TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kyb_applications_status_idx ON kyb_applications (status);
CREATE INDEX IF NOT EXISTS kyb_applications_submitter_idx ON kyb_applications (submitted_by);

-- Merchant onboarding applications (settlement account + category).
CREATE TABLE IF NOT EXISTS merchant_applications (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT REFERENCES tenants (id) ON DELETE SET NULL,
    business_name         TEXT NOT NULL,
    cac_number            TEXT,
    merchant_category     TEXT NOT NULL DEFAULT 'general',
    settlement_bank_code  TEXT NOT NULL,
    -- NUBAN: exactly 10 digits.
    settlement_account    TEXT NOT NULL,
    contact_email         TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'submitted'
                          CHECK (status IN ('submitted', 'under_review', 'approved', 'rejected', 'suspended')),
    submitted_by          TEXT NOT NULL,
    reviewed_by           TEXT,
    approved_by           TEXT,
    rejection_reason      TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS merchant_applications_status_idx ON merchant_applications (status);

-- Regulator access provisioning: read-only, time-boxed, dual-control.
-- requested -> active (after approval by a second, distinct admin) ->
-- expired (expires_at) | revoked.
CREATE TABLE IF NOT EXISTS regulator_access (
    id              TEXT PRIMARY KEY,
    regulator_org   TEXT NOT NULL,        -- e.g. "CBN", "NFIU", "SEC"
    principal_sub   TEXT NOT NULL,        -- Keycloak subject granted access
    scope           TEXT NOT NULL DEFAULT 'read_only'
                    CHECK (scope = 'read_only'),  -- regulators are read-only, always
    status          TEXT NOT NULL DEFAULT 'requested'
                    CHECK (status IN ('requested', 'active', 'expired', 'revoked')),
    requested_by    TEXT NOT NULL,
    approved_by     TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_by      TEXT,
    revoke_reason   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS regulator_access_status_idx ON regulator_access (status);
CREATE INDEX IF NOT EXISTS regulator_access_expiry_idx ON regulator_access (expires_at);

COMMIT;
