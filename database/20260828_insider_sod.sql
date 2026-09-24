-- Segregation-of-duties (SoD) enforcement, ghost-employee/ghost-vendor
-- overlap detection, and mandatory-vacation / access-review tracking.
-- Consumed by services/go/insider-fraud-detector (sod-check, embezzlement
-- endpoints) and by the insider-threat program (docs/INSIDER_THREAT_PROGRAM.md).
-- Idempotent: safe to re-run. Fresh-DB safe: creates only new tables and
-- functions, no dependency on service-created base tables.

BEGIN;

-- ---------------------------------------------------------------------------
-- SoD matrix: incompatible duty pairs. tenant_id NULL = global default rule
-- applying to every tenant; tenant rows can add stricter pairs or disable a
-- global pair via active=false (tenant-specific row shadows the global one).
-- duty_a/duty_b are stored canonically (duty_a < duty_b) so the pair is
-- order-independent; enforced by CHECK + UNIQUE.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sod_matrix (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   VARCHAR(255),                 -- NULL = global default
    duty_a      VARCHAR(100) NOT NULL,
    duty_b      VARCHAR(100) NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    severity    VARCHAR(20) NOT NULL DEFAULT 'high'
                CHECK (severity IN ('low','medium','high','critical')),
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (duty_a < duty_b)
);
CREATE UNIQUE INDEX IF NOT EXISTS sod_matrix_tenant_pair_idx
    ON sod_matrix (COALESCE(tenant_id, ''), duty_a, duty_b);

-- Seed the global incompatible-duty matrix (canonical order, idempotent).
INSERT INTO sod_matrix (tenant_id, duty_a, duty_b, reason, severity) VALUES
    (NULL, 'approve_payment',   'initiate_payment',   'maker-checker on outbound payments; self-approval enables embezzlement', 'critical'),
    (NULL, 'approve_refund',    'initiate_refund',    'refund abuse via self-approved refunds', 'high'),
    (NULL, 'approve_user',      'create_user',        'self-approved account creation enables ghost users', 'critical'),
    (NULL, 'approve_vendor',    'create_vendor',      'self-approved vendor creation enables ghost vendors', 'critical'),
    (NULL, 'approve_payroll',   'modify_payroll',     'payroll padding via self-approved salary changes', 'critical'),
    (NULL, 'delete_audit',      'export_data',        'exfiltration followed by evidence destruction', 'critical'),
    (NULL, 'file_sar',          'modify_watchlist',   'insider could strip own associates from watchlist then suppress SARs', 'high'),
    (NULL, 'modify_ledger',     'reconcile_ledger',   'ledger tampering hidden by self-reconciliation', 'critical'),
    (NULL, 'approve_kyc',       'onboard_customer',   'self-approved onboarding enables mule account planting', 'high'),
    (NULL, 'manage_permissions', 'manage_roles',      'one operator granting both role and scope defeats least privilege', 'high')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Duty assignments: which duties a subject (user or role) currently holds.
-- The BEFORE INSERT trigger enforces the matrix fail-closed at the DB layer.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sod_assignments (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    VARCHAR(255) NOT NULL,
    subject_type VARCHAR(20) NOT NULL DEFAULT 'user'
                 CHECK (subject_type IN ('user','role')),
    subject_id   VARCHAR(255) NOT NULL,
    duty         VARCHAR(100) NOT NULL,
    granted_by   VARCHAR(255) NOT NULL,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    active       BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS sod_assignments_tenant_subject_idx
    ON sod_assignments (tenant_id, subject_type, subject_id) WHERE active;
CREATE UNIQUE INDEX IF NOT EXISTS sod_assignments_active_unique
    ON sod_assignments (tenant_id, subject_type, subject_id, duty) WHERE active;

-- ---------------------------------------------------------------------------
-- SoD violations: recorded on every denied assignment attempt (audit trail)
-- and by batch scans of pre-existing assignments.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sod_violations (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    subject_type VARCHAR(20) NOT NULL DEFAULT 'user',
    subject_id  VARCHAR(255) NOT NULL,
    duty_a      VARCHAR(100) NOT NULL,
    duty_b      VARCHAR(100) NOT NULL,
    rule_id     BIGINT REFERENCES sod_matrix (id) ON DELETE SET NULL,
    severity    VARCHAR(20) NOT NULL DEFAULT 'high',
    status      VARCHAR(20) NOT NULL DEFAULT 'open'
                CHECK (status IN ('open','acknowledged','exempted','resolved')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    resolved_by VARCHAR(255),
    notes       TEXT NOT NULL DEFAULT ''
);
-- one OPEN violation per (subject, pair): re-detection is idempotent
CREATE UNIQUE INDEX IF NOT EXISTS sod_violations_open_unique
    ON sod_violations (tenant_id, subject_type, subject_id, duty_a, duty_b)
    WHERE status = 'open';
CREATE INDEX IF NOT EXISTS sod_violations_tenant_status_idx
    ON sod_violations (tenant_id, status, detected_at DESC);

-- ---------------------------------------------------------------------------
-- Enforcement function: return active matrix rules the proposed duty would
-- violate given the subject's current assignments. Tenant rows shadow global
-- rules with the same pair.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sod_check_assignment(
    p_tenant_id    VARCHAR,
    p_subject_type VARCHAR,
    p_subject_id   VARCHAR,
    p_duty         VARCHAR
) RETURNS TABLE (conflict_duty VARCHAR, rule_id BIGINT, severity VARCHAR, reason TEXT) AS $$
    SELECT a.duty, m.id, m.severity, m.reason
      FROM sod_matrix m
      JOIN sod_assignments a
        ON a.tenant_id = p_tenant_id
       AND a.subject_type = p_subject_type
       AND a.subject_id = p_subject_id
       AND a.active
       AND (a.expires_at IS NULL OR a.expires_at > now())
       AND ((a.duty = m.duty_a AND m.duty_b = p_duty)
         OR (a.duty = m.duty_b AND m.duty_a = p_duty))
     WHERE m.active
       AND m.id IN (  -- tenant-specific row shadows the global row for a pair
            SELECT DISTINCT ON (m2.duty_a, m2.duty_b) m2.id
              FROM sod_matrix m2
             WHERE m2.tenant_id IS NULL OR m2.tenant_id = p_tenant_id
             ORDER BY m2.duty_a, m2.duty_b, (m2.tenant_id IS NULL)
           );
$$ LANGUAGE sql STABLE;

-- Trigger: fail-closed enforcement on new/reactivated assignments. On
-- violation the attempt is recorded in sod_violations (idempotent per open
-- pair), a WARNING is raised, and RETURN NULL skips the assignment row so
-- the privilege is never granted. (Raising EXCEPTION would roll back the
-- violation audit row along with the assignment, so denial is expressed by
-- skipping the row; callers must check rows-affected.)
CREATE OR REPLACE FUNCTION sod_enforce_assignment() RETURNS trigger AS $$
DECLARE
    conflict RECORD;
    canon_a VARCHAR(100);
    canon_b VARCHAR(100);
BEGIN
    IF NOT NEW.active THEN
        RETURN NEW;
    END IF;
    FOR conflict IN
        SELECT * FROM sod_check_assignment(NEW.tenant_id, NEW.subject_type,
                                           NEW.subject_id, NEW.duty)
    LOOP
        canon_a := LEAST(conflict.conflict_duty, NEW.duty::VARCHAR);
        canon_b := GREATEST(conflict.conflict_duty, NEW.duty::VARCHAR);
        INSERT INTO sod_violations (tenant_id, subject_type, subject_id,
                                    duty_a, duty_b, rule_id, severity, notes)
        VALUES (NEW.tenant_id, NEW.subject_type, NEW.subject_id,
                canon_a, canon_b, conflict.rule_id, conflict.severity,
                'denied assignment attempt by ' || NEW.granted_by)
        ON CONFLICT (tenant_id, subject_type, subject_id, duty_a, duty_b)
        WHERE status = 'open'
        DO UPDATE SET detected_at = now(),
                      notes = EXCLUDED.notes;
        RAISE WARNING 'SoD violation: % already holds %, cannot grant % (rule %, severity %)',
            NEW.subject_id, conflict.conflict_duty, NEW.duty,
            conflict.rule_id, conflict.severity;
        RETURN NULL;  -- fail closed: assignment is not created
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sod_assignments_enforce ON sod_assignments;
CREATE TRIGGER sod_assignments_enforce
    BEFORE INSERT OR UPDATE OF active, duty ON sod_assignments
    FOR EACH ROW EXECUTE FUNCTION sod_enforce_assignment();

-- ---------------------------------------------------------------------------
-- Ghost-employee / ghost-vendor overlap: shared identity artefacts between
-- an employee and a vendor (or a payroll identity and a real employee).
-- Populated by insider-fraud-detector's ghost-vendor detection and by batch
-- jobs; overlap_score drives alerting.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS employee_vendor_overlap (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           VARCHAR(255) NOT NULL,
    employee_id         VARCHAR(255) NOT NULL,
    vendor_id           VARCHAR(255) NOT NULL,
    shared_bank_account BOOLEAN NOT NULL DEFAULT FALSE,
    shared_device       BOOLEAN NOT NULL DEFAULT FALSE,
    shared_address      BOOLEAN NOT NULL DEFAULT FALSE,
    shared_tax_id       BOOLEAN NOT NULL DEFAULT FALSE,
    overlap_score       INT NOT NULL DEFAULT 0,
    status              VARCHAR(20) NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','confirmed_ghost','cleared','investigating')),
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    notes               TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS employee_vendor_overlap_pair_idx
    ON employee_vendor_overlap (tenant_id, employee_id, vendor_id);
CREATE INDEX IF NOT EXISTS employee_vendor_overlap_tenant_score_idx
    ON employee_vendor_overlap (tenant_id, overlap_score DESC);

-- ---------------------------------------------------------------------------
-- Mandatory-vacation and access-review campaigns: every privileged-duty
-- holder must (a) take an uninterrupted mandatory-vacation block each year
-- with access suspended, and (b) pass a periodic access review. Rows track
-- obligation, scheduling, completion and reviewer sign-off.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_review_campaigns (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        VARCHAR(255) NOT NULL,
    campaign_type    VARCHAR(30) NOT NULL
                     CHECK (campaign_type IN ('mandatory_vacation','access_review')),
    employee_id      VARCHAR(255) NOT NULL,
    period_start     DATE NOT NULL,
    period_end       DATE NOT NULL,
    days_required    INT NOT NULL DEFAULT 5 CHECK (days_required >= 1),
    days_taken       INT NOT NULL DEFAULT 0 CHECK (days_taken >= 0),
    access_suspended BOOLEAN NOT NULL DEFAULT FALSE,
    reviewer_id      VARCHAR(255),
    status           VARCHAR(20) NOT NULL DEFAULT 'scheduled'
                     CHECK (status IN ('scheduled','in_progress','completed','overdue','exempted')),
    completed_at     TIMESTAMPTZ,
    evidence         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS access_review_campaigns_unique
    ON access_review_campaigns (tenant_id, campaign_type, employee_id, period_start);
CREATE INDEX IF NOT EXISTS access_review_campaigns_status_idx
    ON access_review_campaigns (tenant_id, status, period_end);

-- ---------------------------------------------------------------------------
-- Expense claims: raw claim feed for insider-fraud-detector's expense-abuse
-- velocity detection (claims/24h, amount/30d, duplicate merchant bursts).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS expense_claims (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    employee_id VARCHAR(255) NOT NULL,
    amount      NUMERIC(19,2) NOT NULL CHECK (amount > 0),
    merchant    VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS expense_claims_tenant_employee_created_idx
    ON expense_claims (tenant_id, employee_id, created_at DESC);

-- Helper: mandatory-vacation compliance percentage per tenant over a window
-- (program metric, cited in docs/INSIDER_THREAT_PROGRAM.md).
CREATE OR REPLACE FUNCTION vacation_compliance_pct(
    p_tenant_id VARCHAR,
    p_since     DATE DEFAULT (now()::date - 365)
) RETURNS NUMERIC AS $$
    SELECT CASE WHEN COUNT(*) = 0 THEN 100.0
                ELSE ROUND(100.0 * COUNT(*) FILTER (
                        WHERE status = 'completed'
                          AND days_taken >= days_required
                          AND access_suspended
                     ) / COUNT(*), 2)
           END
      FROM access_review_campaigns
     WHERE tenant_id = p_tenant_id
       AND campaign_type = 'mandatory_vacation'
       AND period_start >= p_since;
$$ LANGUAGE sql STABLE;

COMMIT;
