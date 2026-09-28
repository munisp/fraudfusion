-- 20260901_python_services_caveats.sql
-- Python-services audit remediation (lane P): durable tables closing the
-- audited caveats in security-manager, identity-theft-detector,
-- land-verification-service, kyc-api, onboarding-service, backoffice-api and
-- the events-consumer.
--
-- Fresh-DB-safe and idempotent: CREATE TABLE IF NOT EXISTS, guarded ALTERs,
-- INSERT ... ON CONFLICT DO NOTHING. Runs after 20260825_* (which defines
-- antiwipe_attach_immutable / prevent_regulated_mutation) and after
-- 20260901_billing_monetization.sql (lexical order).
--
-- Contents:
--   1. security_audit_log                 (security-manager durable audit)
--   2. bvn_registry / nin_registry        (identity-theft-detector local registries, synthetic seeds)
--   3. customer_identifiers               (cross-reference identity graph)
--   4. lands_registry_records             (land registry file-import fallback, provenance-tracked)
--   5. parcel_claimants / court_disputes  (journey-34 double-allocation evidence)
--   6. professional_registry / professional_availability /
--      professional_bookings / notification_requests (journey-37 consultation booking)
--   7. kyc_requests (canonical PG mirror) + kyc_review_schedule + kyc_appeals
--   8. agent_applications                 (CBN agent-banking stakeholder)
--   9. events_archive / events_aggregates_weekly (events-consumer sink)
--  10. backoffice: fraud_alerts, document_reviews, document_store,
--      journey_executions, journey_steps, backoffice_audit_ledger (hash-chained),
--      backoffice_session_revocations

BEGIN;

-- Shared anti-wipe helpers (identical definitions exist in
-- 20260825_antiwipe_soft_delete.sql / 20260825_regulated_tables_immutable.sql;
-- CREATE OR REPLACE keeps this file independently runnable and idempotent).
CREATE OR REPLACE FUNCTION prevent_regulated_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is immutable regulated evidence; UPDATE/DELETE denied (anti-wipe policy). Use the documented transition function where one exists.', TG_TABLE_NAME;
END;
$$;

CREATE OR REPLACE FUNCTION antiwipe_attach_immutable(target_table TEXT)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF to_regclass(target_table) IS NULL THEN
        RAISE NOTICE 'table % does not exist yet; skipping immutability trigger', target_table;
        RETURN;
    END IF;
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', target_table || '_immutable', target_table);
    EXECUTE format(
        'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION prevent_regulated_mutation()',
        target_table || '_immutable', target_table);
END;
$$;

-- ---------------------------------------------------------------------------
-- 1. security-manager: durable audit log (in-memory ring remains for reads)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_audit_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    event_type VARCHAR(100) NOT NULL,
    user_id VARCHAR(255),
    ip_address VARCHAR(100),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_audit_log_user_idx
    ON security_audit_log (tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS security_audit_log_type_idx
    ON security_audit_log (tenant_id, event_type, created_at DESC);
-- Audit evidence is append-only regulated data.
SELECT antiwipe_attach_immutable('security_audit_log');

-- ---------------------------------------------------------------------------
-- 2. identity-theft-detector: local BVN/NIN registries (LocalRegistryAdapter)
-- ---------------------------------------------------------------------------
-- Populated by the admin CSV import endpoint. Seeded rows are SYNTHETIC test
-- fixtures (is_synthetic=TRUE, provenance='seed-synthetic') so dev/tests
-- exercise the real match path without fabricating real identities.
CREATE TABLE IF NOT EXISTS bvn_registry (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    bvn VARCHAR(11) NOT NULL,
    full_name VARCHAR(500) NOT NULL,
    date_of_birth VARCHAR(10),
    phone_number VARCHAR(50),
    email VARCHAR(255),
    is_synthetic BOOLEAN NOT NULL DEFAULT FALSE,
    provenance VARCHAR(255) NOT NULL DEFAULT 'admin-import',
    imported_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, bvn)
);

CREATE TABLE IF NOT EXISTS nin_registry (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    nin VARCHAR(11) NOT NULL,
    full_name VARCHAR(500) NOT NULL,
    date_of_birth VARCHAR(10),
    phone_number VARCHAR(50),
    email VARCHAR(255),
    is_synthetic BOOLEAN NOT NULL DEFAULT FALSE,
    provenance VARCHAR(255) NOT NULL DEFAULT 'admin-import',
    imported_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, nin)
);

INSERT INTO bvn_registry (tenant_id, bvn, full_name, date_of_birth, phone_number, email, is_synthetic, provenance) VALUES
    ('default', '22345678901', 'SYNTHETIC Adaeze Eze',  '1990-05-20', '+2348012345678', 'adaeze.syn@example.test', TRUE, 'seed-synthetic'),
    ('default', '22345678902', 'SYNTHETIC Bola Ahmed',  '1985-11-02', '+2348098765432', 'bola.syn@example.test',   TRUE, 'seed-synthetic'),
    ('default', '22345678903', 'SYNTHETIC Chidi Okafor','1978-01-15', '+2348012345678', 'chidi.syn@example.test',  TRUE, 'seed-synthetic')
ON CONFLICT (tenant_id, bvn) DO NOTHING;

INSERT INTO nin_registry (tenant_id, nin, full_name, date_of_birth, phone_number, email, is_synthetic, provenance) VALUES
    ('default', '12345678901', 'SYNTHETIC Adaeze Eze',  '1990-05-20', '+2348012345678', 'adaeze.syn@example.test', TRUE, 'seed-synthetic'),
    ('default', '12345678902', 'SYNTHETIC Danladi Musa','1992-07-30', '+2347055550001', 'danladi.syn@example.test', TRUE, 'seed-synthetic')
ON CONFLICT (tenant_id, nin) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. customer_identifiers: the identity graph edges used by
--    cross_reference_check (phone/email/device/nin/bvn -> customer_id)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS customer_identifiers (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    customer_id VARCHAR(255) NOT NULL,
    id_type VARCHAR(20) NOT NULL CHECK (id_type IN ('phone', 'email', 'device', 'nin', 'bvn')),
    id_value VARCHAR(500) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id_type, id_value, customer_id)
);
CREATE INDEX IF NOT EXISTS customer_identifiers_lookup_idx
    ON customer_identifiers (tenant_id, id_type, id_value);

INSERT INTO customer_identifiers (tenant_id, customer_id, id_type, id_value) VALUES
    ('default', 'cust-syn-1', 'phone',  '+2348012345678'),
    ('default', 'cust-syn-1', 'email',  'adaeze.syn@example.test'),
    ('default', 'cust-syn-1', 'device', 'dev-syn-001'),
    ('default', 'cust-syn-2', 'phone',  '+2348012345678'),  -- shared phone: cluster
    ('default', 'cust-syn-2', 'device', 'dev-syn-002'),
    ('default', 'cust-syn-3', 'email',  'bola.syn@example.test')
ON CONFLICT (tenant_id, id_type, id_value, customer_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 4. land-verification-service: lands registry records (file-import fallback)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lands_registry_records (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    state VARCHAR(50) NOT NULL,
    plot_number VARCHAR(100),
    certificate_number VARCHAR(100),
    owner_name VARCHAR(500),
    property_address TEXT,
    lga VARCHAR(100),
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    transfer_type VARCHAR(50) NOT NULL DEFAULT 'registration',  -- registration|sale|assignment|allocation
    transfer_date TIMESTAMPTZ,
    provenance VARCHAR(255) NOT NULL DEFAULT 'file-import',  -- e.g. 'file-import:lagos-2026-08.csv'
    imported_by VARCHAR(255),
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, state, certificate_number)
);
CREATE INDEX IF NOT EXISTS lands_registry_records_cert_idx
    ON lands_registry_records (tenant_id, state, certificate_number);
CREATE INDEX IF NOT EXISTS lands_registry_records_addr_idx
    ON lands_registry_records (tenant_id, state, property_address);

-- Synthetic seed parcel (clearly marked) so dev/test journeys hit real rows.
INSERT INTO lands_registry_records (tenant_id, state, plot_number, certificate_number, owner_name,
                                    property_address, lga, status, transfer_type, transfer_date, provenance) VALUES
    ('default', 'Lagos', 'SYN-PLT-001', 'SYN-CERT-001', 'SYNTHETIC Landowner One',
     '1 SYNTHETIC Close, Ikoyi', 'Eti-Osa', 'active', 'registration', now() - INTERVAL '2 years', 'seed-synthetic')
ON CONFLICT (tenant_id, state, certificate_number) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 5. journey-34 evidence: parcel claimants + court disputes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS parcel_claimants (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    state VARCHAR(50) NOT NULL,
    property_address TEXT,
    certificate_number VARCHAR(100),
    claimant_name VARCHAR(500) NOT NULL,
    claim_date TIMESTAMPTZ NOT NULL DEFAULT now(),
    document_type VARCHAR(100),
    document_ref VARCHAR(255),
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    conflicting BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS parcel_claimants_parcel_idx
    ON parcel_claimants (tenant_id, state, certificate_number);

CREATE TABLE IF NOT EXISTS court_disputes (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    case_number VARCHAR(100) NOT NULL,
    state VARCHAR(50) NOT NULL,
    property_address TEXT,
    parties TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    description TEXT,
    court_location VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'filed'
        CHECK (status IN ('filed', 'active', 'judgement', 'settled', 'struck_out')),
    filed_date TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, case_number)
);

-- ---------------------------------------------------------------------------
-- 6. journey-37: professional directory, availability, bookings, notifications
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS professional_registry (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    name VARCHAR(500) NOT NULL,
    professional_type VARCHAR(50) NOT NULL
        CHECK (professional_type IN ('lawyer', 'surveyor', 'estate_agent')),
    license_number VARCHAR(100),
    license_verified BOOLEAN NOT NULL DEFAULT FALSE,
    rating DOUBLE PRECISION NOT NULL DEFAULT 0,
    review_count INT NOT NULL DEFAULT 0,
    specialization VARCHAR(255),
    years_experience INT NOT NULL DEFAULT 0,
    state VARCHAR(50) NOT NULL,
    contact JSONB NOT NULL DEFAULT '{}'::jsonb,
    consultation_fee NUMERIC NOT NULL DEFAULT 0,
    languages TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    success_rate DOUBLE PRECISION,
    cases_handled INT,
    certifications TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    profile_url VARCHAR(500),
    source VARCHAR(100) NOT NULL DEFAULT 'seed-synthetic',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS professional_registry_type_state_idx
    ON professional_registry (tenant_id, professional_type, state, rating DESC);

CREATE TABLE IF NOT EXISTS professional_availability (
    id BIGSERIAL PRIMARY KEY,
    professional_id VARCHAR(255) NOT NULL REFERENCES professional_registry (id) ON DELETE CASCADE,
    slot_date DATE NOT NULL,
    start_time VARCHAR(5) NOT NULL,
    end_time VARCHAR(5) NOT NULL,
    slot_type VARCHAR(20) NOT NULL CHECK (slot_type IN ('virtual', 'in_person', 'phone')),
    is_available BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (professional_id, slot_date, start_time, slot_type)
);

CREATE TABLE IF NOT EXISTS professional_bookings (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    professional_id VARCHAR(255) NOT NULL REFERENCES professional_registry (id),
    booking_date DATE NOT NULL,
    start_time VARCHAR(5) NOT NULL,
    end_time VARCHAR(5) NOT NULL,
    consultation_type VARCHAR(20) NOT NULL CHECK (consultation_type IN ('virtual', 'in_person', 'phone')),
    issue_description TEXT,
    urgency_level VARCHAR(20),
    status VARCHAR(24) NOT NULL DEFAULT 'confirmed'
        CHECK (status IN ('confirmed', 'cancelled', 'completed')),
    meeting_link VARCHAR(500),
    location VARCHAR(500),
    instructions TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- No double-booking: one confirmed booking per professional per slot.
CREATE UNIQUE INDEX IF NOT EXISTS professional_bookings_slot_uidx
    ON professional_bookings (professional_id, booking_date, start_time)
    WHERE status = 'confirmed';

-- Notification outbox: booking notifications are recorded here for the
-- delivery workers; the API reports the honest queued/recorded status.
CREATE TABLE IF NOT EXISTS notification_requests (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    booking_id VARCHAR(255),
    user_id VARCHAR(255),
    professional_id VARCHAR(255),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    delivery_status VARCHAR(24) NOT NULL DEFAULT 'queued'
        CHECK (delivery_status IN ('queued', 'sent', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Synthetic directory seed so journey 37 exercises the real DB path in dev.
-- source='seed-synthetic' marks these; production rows come from the
-- professional registry import (Nigerian Bar Association / SURCON etc.).
INSERT INTO professional_registry (id, tenant_id, name, professional_type, license_number, license_verified,
                                   rating, review_count, specialization, years_experience, state, contact,
                                   consultation_fee, languages, success_rate, cases_handled, certifications, profile_url, source) VALUES
    ('pro-syn-law-1', 'default', 'SYNTHETIC Folake Balogun', 'lawyer', 'NBA/SYN/001', TRUE,
     4.8, 132, 'Property Law', 14, 'Lagos',
     '{"phone": "+2348011110001", "email": "folake.syn@example.test", "office": "12 SYNTHETIC Way, Ikoyi, Lagos"}'::jsonb,
     50000, ARRAY['en', 'yo'], 0.92, 210, ARRAY['NBA'], 'https://fraudfusion.io/professionals/pro-syn-law-1', 'seed-synthetic'),
    ('pro-syn-law-2', 'default', 'SYNTHETIC Emeka Nwosu', 'lawyer', 'NBA/SYN/002', TRUE,
     4.5, 87, 'Property Law', 9, 'Lagos',
     '{"phone": "+2348011110002", "email": "emeka.syn@example.test", "office": "4 SYNTHETIC Close, Lekki, Lagos"}'::jsonb,
     35000, ARRAY['en', 'ig'], 0.88, 120, ARRAY['NBA'], 'https://fraudfusion.io/professionals/pro-syn-law-2', 'seed-synthetic'),
    ('pro-syn-sur-1', 'default', 'SYNTHETIC Musa Abdullahi', 'surveyor', 'SURCON/SYN/001', TRUE,
     4.6, 54, 'Cadastral Surveys', 11, 'Lagos',
     '{"phone": "+2348011110003", "email": "musa.syn@example.test", "office": "8 SYNTHETIC Road, Ikeja, Lagos"}'::jsonb,
     40000, ARRAY['en', 'ha'], NULL, NULL, ARRAY['SURCON'], 'https://fraudfusion.io/professionals/pro-syn-sur-1', 'seed-synthetic'),
    ('pro-syn-est-1', 'default', 'SYNTHETIC Yetunde Alabi', 'estate_agent', 'NIESV/SYN/001', TRUE,
     4.3, 41, 'Residential Sales', 7, 'Lagos',
     '{"phone": "+2348011110004", "email": "yetunde.syn@example.test", "office": "21 SYNTHETIC Ave, Yaba, Lagos"}'::jsonb,
     25000, ARRAY['en', 'yo'], NULL, NULL, ARRAY['NIESV'], 'https://fraudfusion.io/professionals/pro-syn-est-1', 'seed-synthetic')
ON CONFLICT (id) DO NOTHING;

-- Availability: next 14 days, 09:00/11:00/14:00 virtual+in_person slots for
-- each seeded professional (idempotent via ON CONFLICT).
INSERT INTO professional_availability (professional_id, slot_date, start_time, end_time, slot_type, is_available)
SELECT p.id,
       CURRENT_DATE + d.days,
       t.start_time, t.end_time, t.slot_type, TRUE
FROM professional_registry p
CROSS JOIN generate_series(0, 13) AS d(days)
CROSS JOIN (VALUES ('09:00', '10:00', 'virtual'), ('11:00', '12:00', 'in_person'),
                   ('14:00', '15:00', 'virtual'), ('10:00', '11:00', 'phone')) AS t(start_time, end_time, slot_type)
WHERE p.source = 'seed-synthetic'
ON CONFLICT (professional_id, slot_date, start_time, slot_type) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 7. kyc-api: canonical kyc_requests mirror + re-KYC schedule + appeals
-- ---------------------------------------------------------------------------
-- kyc-api wrote kyc_requests only into its SQLite mirror; this is the
-- canonical PostgreSQL table (same column names plus tenant/override/rekyc
-- columns, all defaulted so existing INSERT column lists keep working).
CREATE TABLE IF NOT EXISTS kyc_requests (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    customer_id VARCHAR(255) NOT NULL,
    level VARCHAR(20) NOT NULL CHECK (level IN ('basic', 'enhanced', 'premium')),
    tier VARCHAR(20) NOT NULL DEFAULT 'tier_1' CHECK (tier IN ('tier_1', 'tier_2', 'tier_3')),
    status VARCHAR(24) NOT NULL DEFAULT 'received' CHECK (status IN ('received', 'screening', 'completed')),
    decision VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (decision IN ('pending', 'approved', 'manual_review', 'rejected')),
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    risk_level VARCHAR(24) NOT NULL DEFAULT 'low',
    results_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    actor_sub VARCHAR(255) NOT NULL DEFAULT '',
    -- re-KYC linkage
    rekyc_of VARCHAR(255),
    rekyc_reason TEXT,
    rekyc_deadline TIMESTAMPTZ,
    -- backoffice override (dual control enforced in backoffice-api)
    override_by VARCHAR(255),
    override_reason TEXT,
    override_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kyc_requests_customer_idx ON kyc_requests (tenant_id, customer_id);

CREATE TABLE IF NOT EXISTS kyc_review_schedule (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    customer_id VARCHAR(255) NOT NULL,
    review_type VARCHAR(50) NOT NULL DEFAULT 'periodic'
        CHECK (review_type IN ('periodic', 'rekyc', 'triggered')),
    tier VARCHAR(20),
    due_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_progress', 'completed', 'overdue')),
    reason TEXT,
    last_reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, customer_id, review_type, due_at)
);
CREATE INDEX IF NOT EXISTS kyc_review_schedule_due_idx
    ON kyc_review_schedule (status, due_at) WHERE status IN ('pending', 'overdue');

-- Appeals: decided by an independent reviewer (never the original reviewer;
-- enforced in kyc-api code and re-checked by the trigger below).
CREATE TABLE IF NOT EXISTS kyc_appeals (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    customer_id VARCHAR(255) NOT NULL,
    kyc_request_id VARCHAR(255),
    grounds TEXT NOT NULL,
    submitted_by VARCHAR(255) NOT NULL,
    original_reviewer VARCHAR(255),
    assigned_reviewer VARCHAR(255),
    status VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'under_review', 'upheld', 'overturned', 'dismissed')),
    decision_reason TEXT,
    decided_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION kyc_appeals_independence_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'kyc_appeals is regulated evidence; DELETE denied';
    END IF;
    IF NEW.status IN ('upheld', 'overturned', 'dismissed') THEN
        IF NEW.decided_by IS NULL THEN
            RAISE EXCEPTION 'appeal % decision requires decided_by', NEW.id;
        END IF;
        IF NEW.original_reviewer IS NOT NULL AND NEW.decided_by = NEW.original_reviewer THEN
            RAISE EXCEPTION 'appeal independence violated: decided_by equals original reviewer (appeal %)', NEW.id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS kyc_appeals_independence_guard ON kyc_appeals;
CREATE TRIGGER kyc_appeals_independence_guard BEFORE UPDATE OR DELETE ON kyc_appeals
FOR EACH ROW EXECUTE FUNCTION kyc_appeals_independence_guard();

-- ---------------------------------------------------------------------------
-- 8. onboarding-service: CBN agent-banking agents (stakeholder)
-- ---------------------------------------------------------------------------
-- BVN is captured BY REFERENCE ONLY: only a salted SHA-256 hash is stored
-- (per-agent random salt), never the plaintext BVN.
CREATE TABLE IF NOT EXISTS agent_applications (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    agent_code VARCHAR(100) NOT NULL,
    full_name VARCHAR(500) NOT NULL,
    principal_fintech VARCHAR(255) NOT NULL,
    principal_reference VARCHAR(255) NOT NULL,
    bvn_hash CHAR(64),
    bvn_salt VARCHAR(64),
    float_account_number VARCHAR(20),
    float_account_bank VARCHAR(10),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    cbn_tier VARCHAR(20) NOT NULL DEFAULT 'tier_1'
        CHECK (cbn_tier IN ('tier_1', 'tier_2', 'tier_3')),
    status VARCHAR(24) NOT NULL DEFAULT 'submitted'
        CHECK (status IN ('submitted', 'screening', 'pending_approval', 'approved', 'rejected', 'suspended')),
    screening_status VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (screening_status IN ('pending', 'clear', 'hit', 'unavailable')),
    screening_result JSONB,
    submitted_by VARCHAR(255) NOT NULL,
    reviewed_by VARCHAR(255),
    approved_by VARCHAR(255),
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, agent_code)
);
CREATE INDEX IF NOT EXISTS agent_applications_status_idx
    ON agent_applications (tenant_id, status);

-- Dual control for agent approval, enforced in the database as well as in
-- the service: approver must differ from submitter and reviewer.
CREATE OR REPLACE FUNCTION agent_applications_dual_control_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'agent_applications is regulated evidence; DELETE denied';
    END IF;
    IF NEW.status = 'approved' THEN
        IF NEW.approved_by IS NULL
           OR NEW.approved_by = NEW.submitted_by
           OR (NEW.reviewed_by IS NOT NULL AND NEW.approved_by = NEW.reviewed_by) THEN
            RAISE EXCEPTION 'dual control violated: agent approver must differ from submitter and reviewer (agent %)', NEW.id;
        END IF;
        IF NEW.screening_status NOT IN ('clear') THEN
            RAISE EXCEPTION 'agent % cannot be approved before sanctions/PEP screening is clear (status %)', NEW.id, NEW.screening_status;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agent_applications_dual_control_guard ON agent_applications;
CREATE TRIGGER agent_applications_dual_control_guard BEFORE UPDATE OR DELETE ON agent_applications
FOR EACH ROW EXECUTE FUNCTION agent_applications_dual_control_guard();

-- ---------------------------------------------------------------------------
-- 9. events-consumer: durable event archive + weekly aggregates hook
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events_archive (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    topic VARCHAR(255) NOT NULL DEFAULT 'fraudfusion-events',
    partition INT,
    kafka_offset BIGINT,
    event_key VARCHAR(500),
    event_type VARCHAR(100),
    payload JSONB NOT NULL,
    source VARCHAR(20) NOT NULL CHECK (source IN ('kafka', 'filetail')),
    event_ts TIMESTAMPTZ,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (topic, partition, kafka_offset)
);
CREATE INDEX IF NOT EXISTS events_archive_type_ts_idx
    ON events_archive (tenant_id, event_type, event_ts);

-- Weekly per-type event counts (the intel_state_weekly-style aggregate hook;
-- the intel service itself is owned by another lane and reads this table).
CREATE TABLE IF NOT EXISTS events_aggregates_weekly (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    week_start DATE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, week_start, event_type)
);

-- ---------------------------------------------------------------------------
-- 10. backoffice-api tables
-- ---------------------------------------------------------------------------

-- Canonical fraud alert queue for the backoffice (status machine:
-- open -> investigating -> resolved | false_positive).
CREATE TABLE IF NOT EXISTS fraud_alerts (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    alert_type VARCHAR(50) NOT NULL
        CHECK (alert_type IN ('transaction', 'identity', 'account_takeover', 'document_fraud', 'money_laundering')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status VARCHAR(24) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    customer_id VARCHAR(255),
    customer_name VARCHAR(500),
    description TEXT,
    amount NUMERIC,
    currency VARCHAR(10),
    location VARCHAR(255),
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    assigned_to VARCHAR(255),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    resolution_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS fraud_alerts_status_idx
    ON fraud_alerts (tenant_id, status, detected_at DESC);

-- Document review queue (state machine:
-- pending -> in_review -> approved | rejected | escalated | needs_info;
-- needs_info -> in_review; escalated -> in_review).
CREATE TABLE IF NOT EXISTS document_reviews (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    document_id VARCHAR(255) NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_review', 'approved', 'rejected', 'escalated', 'needs_info')),
    customer_id VARCHAR(255),
    customer_name VARCHAR(500),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    reviewer_id VARCHAR(255),
    submitter_id VARCHAR(255),
    ocr_result JSONB,
    fraud_indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    decision VARCHAR(24),
    decision_reason TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS document_reviews_status_idx
    ON document_reviews (tenant_id, status, submitted_at DESC);

-- Raw document binaries for the review UI image endpoint.
CREATE TABLE IF NOT EXISTS document_store (
    document_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    content_type VARCHAR(100) NOT NULL DEFAULT 'application/octet-stream',
    content BYTEA NOT NULL,
    uploaded_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Temporal journey execution mirror + step log for the backoffice console.
CREATE TABLE IF NOT EXISTS journey_executions (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    journey_id INT NOT NULL,
    journey_name VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    status VARCHAR(24) NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed', 'paused', 'cancelled')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    current_step INT NOT NULL DEFAULT 0,
    total_steps INT NOT NULL DEFAULT 0,
    final_decision VARCHAR(100),
    risk_score DOUBLE PRECISION,
    cancel_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS journey_steps (
    id BIGSERIAL PRIMARY KEY,
    execution_id VARCHAR(255) NOT NULL REFERENCES journey_executions (id) ON DELETE CASCADE,
    step_number INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result JSONB,
    error TEXT,
    UNIQUE (execution_id, step_number)
);

-- Hash-chained audit ledger for every backoffice mutation. entry_hash =
-- sha256(prev_hash || canonical entry fields); append-only (immutable).
CREATE TABLE IF NOT EXISTS backoffice_audit_ledger (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
    actor_id VARCHAR(255),
    actor_type VARCHAR(50),
    actor_ip VARCHAR(100),
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    outcome VARCHAR(50) NOT NULL DEFAULT 'success',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash CHAR(64) NOT NULL,
    entry_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS backoffice_audit_ledger_resource_idx
    ON backoffice_audit_ledger (tenant_id, resource_type, resource_id, created_at DESC);
SELECT antiwipe_attach_immutable('backoffice_audit_ledger');

-- Chain verifier: returns the number of broken links (0 = intact).
CREATE OR REPLACE FUNCTION verify_backoffice_audit_chain(p_tenant_id VARCHAR DEFAULT 'default')
RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE
    broken BIGINT := 0;
    prev CHAR(64) := repeat('0', 64);
    r RECORD;
BEGIN
    FOR r IN
        SELECT id, event_type, severity, actor_id, resource_type, resource_id,
               action, outcome, details, prev_hash, entry_hash, created_at
        FROM backoffice_audit_ledger
        WHERE tenant_id = p_tenant_id
        ORDER BY id
    LOOP
        IF r.prev_hash <> prev THEN
            broken := broken + 1;
        END IF;
        IF r.entry_hash <> encode(sha256(convert_to(
                r.prev_hash || '|' || r.event_type || '|' || r.severity || '|' ||
                coalesce(r.actor_id, '') || '|' || r.resource_type || '|' ||
                r.resource_id || '|' || r.action || '|' || r.outcome || '|' ||
                r.details::text || '|' || to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                'UTF8')), 'hex') THEN
            broken := broken + 1;
        END IF;
        prev := r.entry_hash;
    END LOOP;
    RETURN broken;
END;
$$;

-- Revoked sessions/tokens (logout + admin revocation), checked by auth.
CREATE TABLE IF NOT EXISTS backoffice_session_revocations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    jti VARCHAR(255) NOT NULL,
    sub VARCHAR(255) NOT NULL,
    revoked_by VARCHAR(255) NOT NULL,
    reason TEXT,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    UNIQUE (tenant_id, jti)
);

COMMIT;
