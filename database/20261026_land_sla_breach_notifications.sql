-- 20261026_land_sla_breach_notifications.sql
-- Round 12: exactly-once SLA-breach notification flag on dispute_cases
-- (the sweeper emits dispute.sla.breached webhooks only for newly breached
-- cases). Idempotent; mirrors the SQLite column-migration in
-- services/land-verification-service/api/data_store.py.

BEGIN;

ALTER TABLE dispute_cases
    ADD COLUMN IF NOT EXISTS breach_notified BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;
