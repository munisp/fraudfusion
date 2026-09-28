-- 20260929_doc_verification.sql
-- Round 8 Lane D: document-verification audit trail for kyc-api.
--
-- document_verifications persists one row per /api/v1/document/verify call:
-- the verdict status (verified | manual_review | rejected | unavailable),
-- the composite quality label, the cv2 integrity scores, and the per-layer
-- provenance (which of local_cv / ocr / vlm ran vs was unavailable, with
-- reasons). This is the evidence a compliance reviewer needs to see EXACTLY
-- which verification layers produced a verdict.
--
-- PRIVACY: hash-only persistence. The raw document bytes are NEVER stored —
-- only the SHA-256 of the upload (enough to detect resubmission of the same
-- artifact across customers) plus metadata. Extracted PII fields are
-- returned to the caller but not persisted here.
--
-- The SQLite mirror for local dev/tests lives in
-- services/python/kyc-api/app/db.py (SQLITE_SCHEMA).
--
-- Fresh-DB-safe and idempotent: to_regclass-guarded DO block, matching
-- 20260902_cultural_intelligence.sql / 20260928_kyc_rigor_agents.sql style.

DO $$
BEGIN
    IF to_regclass('document_verifications') IS NULL THEN
        CREATE TABLE document_verifications (
            id                       VARCHAR(64)  PRIMARY KEY,
            actor_sub                VARCHAR(255) NOT NULL DEFAULT '',
            document_type            VARCHAR(64)  NOT NULL,
            detected_format          VARCHAR(16)  NOT NULL,
            sha256                   CHAR(64)     NOT NULL,
            size_bytes               BIGINT       NOT NULL,
            status                   VARCHAR(16)  NOT NULL
                CHECK (status IN ('verified', 'manual_review',
                                  'rejected', 'unavailable')),
            quality                  VARCHAR(16)
                CHECK (quality IN ('poor', 'acceptable', 'good')),
            screen_replay_integrity  DOUBLE PRECISION
                CHECK (screen_replay_integrity BETWEEN 0 AND 1),
            printed_cutout_integrity DOUBLE PRECISION
                CHECK (printed_cutout_integrity BETWEEN 0 AND 1),
            provenance_json          JSONB        NOT NULL DEFAULT '[]',
            reasons_json             JSONB        NOT NULL DEFAULT '[]',
            created_at               TIMESTAMPTZ  NOT NULL DEFAULT now()
        );
        -- Resubmission detection: same artifact hash across verifications.
        CREATE INDEX document_verifications_sha_idx
            ON document_verifications (sha256);
        CREATE INDEX document_verifications_created_idx
            ON document_verifications (created_at);
    END IF;
END $$;
