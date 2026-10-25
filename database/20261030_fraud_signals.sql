-- Fraud Signals service (Round 19): event store + hash-chained eval audit.
-- Mirrors services/python/fraud-signals/store.py SCHEMA exactly; the
-- service also self-applies this DDL at boot (idempotent).

CREATE TABLE IF NOT EXISTS signal_events (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    subject_id  TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS signal_events_idx
    ON signal_events (kind, subject_id, created_at);

CREATE TABLE IF NOT EXISTS signal_evals (
    id          TEXT PRIMARY KEY,
    detector    TEXT NOT NULL,
    subject_id  TEXT NOT NULL,
    score       DOUBLE PRECISION NOT NULL,
    verdict     TEXT NOT NULL,
    factors     TEXT NOT NULL DEFAULT '[]',
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS signal_evals_idx
    ON signal_evals (detector, subject_id, created_at);
