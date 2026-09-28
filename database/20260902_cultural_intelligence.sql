-- 20260902_cultural_intelligence.sql
-- Cultural Intelligence layer: 2026 cultural calendar seed, opt-in ajo/esusu
-- group declarations (monitored-not-whitelisted), and the audit table every
-- cultural anomaly-score adjustment MUST write to.
-- Fresh-DB-safe, idempotent, guarded DDL (to_regclass DO blocks, matching
-- 20260820_*_persistence_hardening.sql / 20260901_national_intelligence.sql
-- style). Seeds use ON CONFLICT DO NOTHING so repeated application is safe.
--
-- ETHICS: pattern-level data only. No per-individual ethnicity, religion,
-- tribe, or language attributes are stored anywhere in this schema;
-- calendar/market/giving context is zone-level aggregate information.

-- cultural_calendar_events: Nigerian cultural calendar with expected uplift
-- context. Lunar events are Gregorian APPROXIMATIONS (lunar_approx=true)
-- and must be re-seeded when official dates are announced.
DO $$
BEGIN
    IF to_regclass('cultural_calendar_events') IS NULL THEN
        CREATE TABLE cultural_calendar_events (
            event_id        VARCHAR(64)  NOT NULL,
            name            VARCHAR(128) NOT NULL,
            start_date      DATE         NOT NULL,
            end_date        DATE         NOT NULL,
            lunar_approx    BOOLEAN      NOT NULL DEFAULT FALSE,
            recurring_rule  VARCHAR(64),          -- e.g. 'month_end_pm3d'
            notes           TEXT,
            created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            PRIMARY KEY (event_id, start_date),
            CHECK (end_date >= start_date)
        );
    END IF;
END $$;

INSERT INTO cultural_calendar_events
    (event_id, name, start_date, end_date, lunar_approx, recurring_rule, notes)
VALUES
    ('new_year',          'New Year',                              DATE '2026-01-01', DATE '2026-01-02', FALSE, NULL, 'Public holiday spend surge; sits inside salary week (fitted uplift absorbs the overlap)'),
    ('eid_al_fitr',       'Eid al-Fitr (Sallah)',                  DATE '2026-03-20', DATE '2026-03-22', TRUE,  NULL, 'LUNAR APPROXIMATION — re-seed on official moon-sighting announcement'),
    ('easter',            'Easter (Good Friday-Easter Monday)',    DATE '2026-04-03', DATE '2026-04-06', FALSE, NULL, 'Easter Sunday 2026-04-05'),
    ('eid_al_adha',       'Eid al-Adha (Big Sallah)',              DATE '2026-05-27', DATE '2026-05-29', TRUE,  NULL, 'LUNAR APPROXIMATION — re-seed on official announcement'),
    ('independence_day',  'Independence Day',                      DATE '2026-10-01', DATE '2026-10-02', FALSE, NULL, 'Sits inside salary week (fitted uplift absorbs the overlap)'),
    ('detty_december',    'Detty December season',                 DATE '2026-12-15', DATE '2026-12-31', FALSE, NULL, 'Season uplift; Christmas days take precedence (nested, not double-counted)'),
    ('christmas',         'Christmas',                             DATE '2026-12-24', DATE '2026-12-26', FALSE, NULL, 'Nested inside Detty December; takes precedence Dec 24-26'),
    ('salary_week',       'Salary week (month-end +/-3d)',         DATE '2026-01-01', DATE '2026-12-31', FALSE, 'month_end_pm3d', 'Recurring monthly: last 3 / first 3 days of each month; lowest precedence')
ON CONFLICT (event_id, start_date) DO NOTHING;

-- ajo_groups: OPT-IN declarations of rotating savings clubs (ajo / esusu /
-- adashe) by users or cooperatives. Declared groups get
-- MONITORED-NOT-WHITELISTED treatment: declaration adjusts anomaly context
-- via the legitimacy posterior; it never exempts a group from monitoring.
DO $$
BEGIN
    IF to_regclass('ajo_groups') IS NULL THEN
        CREATE TABLE ajo_groups (
            group_id            VARCHAR(64)  NOT NULL PRIMARY KEY,
            principal           VARCHAR(64)  NOT NULL,  -- declaring customer/coop ref
            members_count       INTEGER      NOT NULL CHECK (members_count BETWEEN 2 AND 500),
            contribution_kobo   BIGINT       NOT NULL CHECK (contribution_kobo > 0),
            cadence_days        INTEGER      NOT NULL CHECK (cadence_days BETWEEN 1 AND 92),
            status              VARCHAR(16)  NOT NULL DEFAULT 'declared'
                                CHECK (status IN ('declared', 'monitoring', 'verified',
                                                  'flagged', 'closed')),
            declared_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
            updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
            notes               TEXT
        );
    END IF;
END $$;

-- cultural_adjustment_audit: EVERY anomaly-score adjustment applied by
-- /v1/intel/cultural/adjustment is written here (who/what/why/when) —
-- adjustments are auditable or they do not happen.
DO $$
BEGIN
    IF to_regclass('cultural_adjustment_audit') IS NULL THEN
        CREATE TABLE cultural_adjustment_audit (
            id             BIGSERIAL PRIMARY KEY,
            request_id     UUID          NOT NULL,
            on_date        DATE          NOT NULL,
            state          VARCHAR(32)   NOT NULL,
            channel        VARCHAR(32),
            factor         DOUBLE PRECISION NOT NULL CHECK (factor > 0),
            components     JSONB         NOT NULL,
            reason         TEXT          NOT NULL,
            model_version  VARCHAR(32),
            created_at     TIMESTAMPTZ   NOT NULL DEFAULT now()
        );
    END IF;
END $$;

-- Indexes (guarded on table existence).
DO $$
BEGIN
    IF to_regclass('cultural_calendar_events') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS cultural_calendar_events_dates_idx ON cultural_calendar_events (start_date, end_date);';
    END IF;
    IF to_regclass('ajo_groups') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS ajo_groups_principal_idx ON ajo_groups (principal);';
        EXECUTE 'CREATE INDEX IF NOT EXISTS ajo_groups_status_idx ON ajo_groups (status);';
    END IF;
    IF to_regclass('cultural_adjustment_audit') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS cultural_adjustment_audit_date_idx ON cultural_adjustment_audit (on_date DESC);';
        EXECUTE 'CREATE INDEX IF NOT EXISTS cultural_adjustment_audit_request_idx ON cultural_adjustment_audit (request_id);';
    END IF;
END $$;
