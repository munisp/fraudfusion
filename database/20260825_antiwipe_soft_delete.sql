-- 20260825_antiwipe_soft_delete.sql
-- Anti-wipe hardening (lane B3 / P1-1, P1-2): row-level soft-delete columns,
-- dual-control deletion_approvals ledger, deferred hard-delete janitor
-- function, and v_active_* views hiding tombstoned rows.
--
-- Idempotent: safe to run repeatedly. Migrations execute in filename order
-- (this file sorts before 20260825_regulated_tables_immutable.sql), so the
-- shared helpers are (re)defined here with identical bodies.

BEGIN;

-- Shared helpers (identical definitions exist in
-- 20260825_regulated_tables_immutable.sql; CREATE OR REPLACE keeps both files
-- independently runnable and idempotent).
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
-- 1. Soft-delete (tombstone) columns on mutable-but-deletable operational tables
-- ---------------------------------------------------------------------------
-- Helper to add tombstone columns only to tables that exist.
CREATE OR REPLACE FUNCTION antiwipe_add_soft_delete_columns(target_table TEXT)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF to_regclass(target_table) IS NULL THEN
        RAISE NOTICE 'table % does not exist yet; skipping soft-delete columns', target_table;
        RETURN;
    END IF;
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ', target_table);
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS deleted_by VARCHAR(255)', target_table);
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS deletion_reason TEXT', target_table);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (deleted_at) WHERE deleted_at IS NULL',
                   target_table || '_active_idx', target_table);
END;
$$;

SELECT antiwipe_add_soft_delete_columns('dispute_records');
SELECT antiwipe_add_soft_delete_columns('security_users');
SELECT antiwipe_add_soft_delete_columns('security_login_failures');
SELECT antiwipe_add_soft_delete_columns('chargeback_transactions');
SELECT antiwipe_add_soft_delete_columns('settlement_items');
SELECT antiwipe_add_soft_delete_columns('reconciliation_breaks');

-- security_login_failures: soft-clear support so successful logins stop
-- hard-deleting attack evidence (replaces DELETE FROM in security_manager).
DO $$
BEGIN
    IF to_regclass('security_login_failures') IS NOT NULL THEN
        ALTER TABLE security_login_failures ADD COLUMN IF NOT EXISTS cleared_at TIMESTAMPTZ;
        ALTER TABLE security_login_failures ADD COLUMN IF NOT EXISTS cleared_by VARCHAR(255);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. deletion_approvals: dual-control ledger for destructive operations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS deletion_approvals (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255),
    table_name VARCHAR(255) NOT NULL,
    row_id VARCHAR(255) NOT NULL,
    requester_id VARCHAR(255) NOT NULL,
    approver_id VARCHAR(255),
    reason TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected','executed')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    hard_delete_after TIMESTAMPTZ NOT NULL,  -- grace window; janitor waits for this
    executed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS deletion_approvals_status_due_idx
    ON deletion_approvals (status, hard_delete_after) WHERE status = 'approved';
CREATE INDEX IF NOT EXISTS deletion_approvals_target_idx
    ON deletion_approvals (table_name, row_id);

-- deletion_approvals itself: rows are insert-only except for the guarded
-- pending -> approved/rejected/executed status transitions, and requester must
-- differ from approver (4-eyes, enforced in the database as well as in code).
CREATE OR REPLACE FUNCTION deletion_approvals_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'deletion_approvals is an append-only control ledger; DELETE denied';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.table_name IS DISTINCT FROM OLD.table_name
       OR NEW.row_id IS DISTINCT FROM OLD.row_id
       OR NEW.requester_id IS DISTINCT FROM OLD.requester_id
       OR NEW.requested_at IS DISTINCT FROM OLD.requested_at THEN
        RAISE EXCEPTION 'deletion_approvals identity columns are immutable (id %)', OLD.id;
    END IF;
    IF NEW.status = 'approved' THEN
        IF NEW.approver_id IS NULL OR NEW.approver_id = OLD.requester_id THEN
            RAISE EXCEPTION 'dual control violated: approver must be a different principal than requester (id %)', OLD.id;
        END IF;
        IF OLD.status <> 'pending' THEN
            RAISE EXCEPTION 'deletion_approvals illegal transition % -> approved (id %)', OLD.status, OLD.id;
        END IF;
        NEW.approved_at := now();
    ELSIF NEW.status IN ('rejected','executed') THEN
        IF OLD.status NOT IN ('pending','approved') THEN
            RAISE EXCEPTION 'deletion_approvals illegal transition % -> % (id %)', OLD.status, NEW.status, OLD.id;
        END IF;
    ELSIF NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'deletion_approvals illegal status % (id %)', NEW.status, OLD.id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS deletion_approvals_guard ON deletion_approvals;
CREATE TRIGGER deletion_approvals_guard BEFORE UPDATE OR DELETE ON deletion_approvals
FOR EACH ROW EXECUTE FUNCTION deletion_approvals_guard();

-- ---------------------------------------------------------------------------
-- 3. Deferred hard-delete janitor function
-- ---------------------------------------------------------------------------
-- Executes a hard delete ONLY when ALL barriers pass:
--   * deletion_approvals row exists, status='approved'
--   * requester_id <> approver_id (defense-in-depth re-check)
--   * hard_delete_after < now() (grace window elapsed)
--   * the row is past the regulatory retention floor (p_retention_floor_days,
--     default 2555 = 7 years) measured from created_at
--   * the row is already soft-deleted (tombstoned)
-- Every execution is recorded in the append-only deletion_execution_log.
CREATE TABLE IF NOT EXISTS deletion_execution_log (
    id BIGSERIAL PRIMARY KEY,
    approval_id UUID NOT NULL,
    table_name VARCHAR(255) NOT NULL,
    row_id VARCHAR(255) NOT NULL,
    executed_by VARCHAR(255) NOT NULL,
    requester_id VARCHAR(255) NOT NULL,
    approver_id VARCHAR(255) NOT NULL,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT antiwipe_attach_immutable('deletion_execution_log');

CREATE OR REPLACE FUNCTION execute_approved_hard_delete(
    p_approval_id UUID,
    p_executor VARCHAR(255),
    p_retention_floor_days INTEGER DEFAULT 2555
) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
    v_approval deletion_approvals%ROWTYPE;
    v_created_at TIMESTAMPTZ;
    v_deleted_at TIMESTAMPTZ;
BEGIN
    SELECT * INTO v_approval FROM deletion_approvals WHERE id = p_approval_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'deletion approval % not found', p_approval_id;
    END IF;
    IF v_approval.status <> 'approved' THEN
        RAISE EXCEPTION 'deletion approval % is %, not approved', p_approval_id, v_approval.status;
    END IF;
    IF v_approval.requester_id = v_approval.approver_id THEN
        RAISE EXCEPTION 'dual control violated on approval %', p_approval_id;
    END IF;
    IF v_approval.hard_delete_after >= now() THEN
        RAISE EXCEPTION 'grace window for approval % runs until %', p_approval_id, v_approval.hard_delete_after;
    END IF;
    IF to_regclass(v_approval.table_name) IS NULL THEN
        RAISE EXCEPTION 'table % does not exist', v_approval.table_name;
    END IF;

    EXECUTE format('SELECT created_at, deleted_at FROM %I WHERE id::text = $1', v_approval.table_name)
       INTO v_created_at, v_deleted_at
      USING v_approval.row_id;
    IF v_created_at IS NULL THEN
        RAISE EXCEPTION 'row %.% not found', v_approval.table_name, v_approval.row_id;
    END IF;
    IF v_deleted_at IS NULL THEN
        RAISE EXCEPTION 'row %.% is not soft-deleted; hard delete requires a tombstone first',
            v_approval.table_name, v_approval.row_id;
    END IF;
    IF v_created_at > now() - make_interval(days => p_retention_floor_days) THEN
        RAISE EXCEPTION 'row %.% is younger than the % day regulatory retention floor',
            v_approval.table_name, v_approval.row_id, p_retention_floor_days;
    END IF;

    EXECUTE format('DELETE FROM %I WHERE id::text = $1', v_approval.table_name)
      USING v_approval.row_id;

    UPDATE deletion_approvals
       SET status = 'executed', executed_at = now()
     WHERE id = p_approval_id;

    INSERT INTO deletion_execution_log
        (approval_id, table_name, row_id, executed_by, requester_id, approver_id)
    VALUES
        (p_approval_id, v_approval.table_name, v_approval.row_id, p_executor,
         v_approval.requester_id, v_approval.approver_id);
    RETURN TRUE;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. v_active_* views hiding tombstoned rows
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION antiwipe_create_active_view(target_table TEXT)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF to_regclass(target_table) IS NULL THEN
        RAISE NOTICE 'table % does not exist yet; skipping active view', target_table;
        RETURN;
    END IF;
    EXECUTE format(
        'CREATE OR REPLACE VIEW %I AS SELECT * FROM %I WHERE deleted_at IS NULL',
        'v_active_' || target_table, target_table);
END;
$$;

SELECT antiwipe_create_active_view('dispute_records');
SELECT antiwipe_create_active_view('security_users');
SELECT antiwipe_create_active_view('security_login_failures');
SELECT antiwipe_create_active_view('chargeback_transactions');
SELECT antiwipe_create_active_view('settlement_items');
SELECT antiwipe_create_active_view('reconciliation_breaks');

COMMIT;
