-- 20261027_land_innovations.sql
-- Round 13: ten land-fraud innovation features (schema portion).
--   * parcels.beacons / notice_expires_at  (geospatial overlap + notice period)
--   * parcel_consents.identity_hash / liveness_challenge_id (identity-bound consent)
--   * parcel_objections                    (public-notice objection workflow)
-- Idempotent; mirrors the SQLite schema/column-migrations in
-- services/land-verification-service/api/data_store.py.

BEGIN;

ALTER TABLE parcels ADD COLUMN IF NOT EXISTS beacons JSONB;
ALTER TABLE parcels ADD COLUMN IF NOT EXISTS notice_expires_at TIMESTAMPTZ;

ALTER TABLE parcel_consents ADD COLUMN IF NOT EXISTS identity_hash CHAR(64);
ALTER TABLE parcel_consents ADD COLUMN IF NOT EXISTS liveness_challenge_id VARCHAR(128);

CREATE TABLE IF NOT EXISTS parcel_objections (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    parcel_ref VARCHAR(128) NOT NULL,
    objector_name VARCHAR(256) NOT NULL,
    objector_id_hash CHAR(64),
    grounds TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','resolved','dismissed')),
    resolution VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS parcel_objections_ref_idx
    ON parcel_objections (tenant_id, parcel_ref, status);

COMMIT;
