-- 20261025_land_due_diligence.sql
-- Round 11: land due-diligence module (land-verification-service),
-- implementing the buildable recommendations from the Channels TV land-fraud
-- interview (docs/land-fraud-video-recommendations.md).
--
-- Fresh-DB-safe and idempotent. (Formerly mirrored the SQLite schema — removed Round 27 — in
-- services/land-verification-service/api/data_store.py.
--
-- Contents:
--   1. parcels                (first-wins registration, consent-gated status)
--   2. parcel_conflicts       (multiple-sale detection at registration time)
--   3. parcel_consents        (family/consent-party tracking)
--   4. dispute_cases          (90-day SLA clock — dedicated-land-courts target)
--   5. parcel_revocations     (Land Use Act compensation-before-acquisition)
--   6. parcel_evidence_chain  (tamper-evident hash chain, hash-only payloads)

BEGIN;

CREATE TABLE IF NOT EXISTS parcels (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    parcel_ref VARCHAR(128) NOT NULL,
    state VARCHAR(50) NOT NULL,
    lga VARCHAR(100),
    property_address TEXT,
    certificate_number VARCHAR(100),
    survey_plan_hash VARCHAR(128),
    registered_by VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'provisional'
        CHECK (status IN ('provisional','clear','disputed','revoked')),
    consent_required JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, parcel_ref)
);
CREATE INDEX IF NOT EXISTS parcels_cert_idx
    ON parcels (tenant_id, certificate_number);

CREATE TABLE IF NOT EXISTS parcel_conflicts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    parcel_ref VARCHAR(128) NOT NULL,
    conflict_key VARCHAR(255) NOT NULL,
    existing_ref VARCHAR(128) NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS parcel_conflicts_ref_idx
    ON parcel_conflicts (tenant_id, parcel_ref);

CREATE TABLE IF NOT EXISTS parcel_consents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    parcel_ref VARCHAR(128) NOT NULL,
    party_name VARCHAR(256) NOT NULL,
    confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    method VARCHAR(100),
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, parcel_ref, party_name)
);

CREATE TABLE IF NOT EXISTS dispute_cases (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    parcel_ref VARCHAR(128) NOT NULL,
    case_number VARCHAR(100),
    state VARCHAR(50),
    description TEXT,
    court_location VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','resolved','withdrawn')),
    resolution VARCHAR(512),
    filed_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    sla_days INTEGER NOT NULL DEFAULT 90,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dispute_cases_parcel_idx
    ON dispute_cases (tenant_id, parcel_ref, status);

CREATE TABLE IF NOT EXISTS parcel_revocations (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    parcel_ref VARCHAR(128) NOT NULL,
    notice_ref VARCHAR(255),
    reason TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'notice_served'
        CHECK (status IN ('notice_served','documents_collected','compensated')),
    compensation_amount DOUBLE PRECISION,
    compensation_method VARCHAR(128),
    compensated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS parcel_revocations_parcel_idx
    ON parcel_revocations (tenant_id, parcel_ref, status);

CREATE TABLE IF NOT EXISTS parcel_evidence_chain (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    parcel_ref VARCHAR(128) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload_hash CHAR(64) NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    entry_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS parcel_evidence_chain_ref_idx
    ON parcel_evidence_chain (tenant_id, parcel_ref, id);

COMMIT;
