-- 20260929_kyb_verification.sql
-- Round 8 Lane K: KYB document-content verification.
--
-- kyb_applications gains the verdict produced by onboarding-service
-- app/kyb_verification.py (content extraction, RC/name cross-checks against
-- the submitted CAC number and business name, utility-bill recency, board
-- signatory block, aggregate verified | manual_review | rejected |
-- engine_unavailable | skipped with engine provenance):
--
--   verification_json JSONB  — full verdict document (per-document verdicts,
--                              extracted fields, consistency results,
--                              provenance). Contains SHA-256 content hashes
--                              only — raw document bytes are never stored.
--   verified_at TIMESTAMPTZ  — when the pipeline last ran.
--
-- The base kyb_applications table is created in
-- 20260827_pep_kyb_merchant.sql; the to_regclass guard keeps this file a
-- no-op on databases where that table is absent.
--
-- Fresh-DB-safe and idempotent: to_regclass-guarded DO block with
-- ADD COLUMN IF NOT EXISTS (matching 20260928_identity_exposure.sql style).
-- Independent of 20260929_doc_verification.sql (Lane D) — either apply
-- order works.

BEGIN;

DO $$
BEGIN
    IF to_regclass('kyb_applications') IS NOT NULL THEN
        ALTER TABLE kyb_applications
            ADD COLUMN IF NOT EXISTS verification_json JSONB,
            ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
    END IF;
END $$;

COMMIT;
