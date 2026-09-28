"""Storage layer for backoffice-api.

PostgreSQL (via psycopg) when DATABASE_URL=postgres(ql)://... is configured;
otherwise a local SQLite file (BACKOFFICE_DB, default ./data/backoffice.db)
for local dev/tests. Canonical PostgreSQL schema:
database/20260901_python_services_caveats.sql. SQLITE_SCHEMA is the
SQLite-compatible mirror (JSONB -> TEXT, TIMESTAMPTZ -> TEXT, BYTEA -> BLOB).

Queries use :name bind parameters (SQLite native); for PostgreSQL they are
rewritten to %(name)s for psycopg.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DEFAULT_SQLITE_PATH = os.getenv(
    "BACKOFFICE_DB",
    str(Path(__file__).resolve().parent.parent / "data" / "backoffice.db"),
)

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS fraud_alerts (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    alert_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','investigating','resolved','false_positive')),
    customer_id     TEXT,
    customer_name   TEXT,
    description     TEXT,
    amount          REAL,
    currency        TEXT,
    location        TEXT,
    risk_score      REAL NOT NULL DEFAULT 0,
    indicators      TEXT NOT NULL DEFAULT '[]',
    assigned_to     TEXT,
    detected_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    resolved_at     TEXT,
    resolution_note TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS document_reviews (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL DEFAULT 'default',
    document_id      TEXT NOT NULL,
    document_type    TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','in_review','approved','rejected','escalated','needs_info')),
    customer_id      TEXT,
    customer_name    TEXT,
    submitted_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    reviewed_at      TEXT,
    reviewer_id      TEXT,
    submitter_id     TEXT,
    ocr_result       TEXT,
    fraud_indicators TEXT NOT NULL DEFAULT '[]',
    risk_score       REAL NOT NULL DEFAULT 0,
    decision         TEXT,
    decision_reason  TEXT,
    notes            TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS document_store (
    document_id  TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    content      BLOB NOT NULL,
    uploaded_by  TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS journey_executions (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL DEFAULT 'default',
    journey_id     INTEGER NOT NULL,
    journey_name   TEXT NOT NULL,
    customer_id    TEXT,
    status         TEXT NOT NULL DEFAULT 'running'
                   CHECK (status IN ('running','completed','failed','paused','cancelled')),
    started_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at   TEXT,
    current_step   INTEGER NOT NULL DEFAULT 0,
    total_steps    INTEGER NOT NULL DEFAULT 0,
    final_decision TEXT,
    risk_score     REAL,
    cancel_reason  TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS journey_steps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT NOT NULL REFERENCES journey_executions (id) ON DELETE CASCADE,
    step_number  INTEGER NOT NULL,
    name         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','running','completed','failed','skipped')),
    started_at   TEXT,
    completed_at TEXT,
    result       TEXT,
    error        TEXT,
    UNIQUE (execution_id, step_number)
);

CREATE TABLE IF NOT EXISTS backoffice_audit_ledger (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    event_type    TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','critical')),
    actor_id      TEXT,
    actor_type    TEXT,
    actor_ip      TEXT,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    action        TEXT NOT NULL,
    outcome       TEXT NOT NULL DEFAULT 'success',
    details       TEXT NOT NULL DEFAULT '{}',
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backoffice_session_revocations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL DEFAULT 'default',
    jti        TEXT NOT NULL,
    sub        TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    reason     TEXT,
    revoked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT,
    UNIQUE (tenant_id, jti)
);

-- Canonical PG kyc_requests is created by the migration; this mirror covers
-- the columns the backoffice override flow touches.
CREATE TABLE IF NOT EXISTS kyc_requests (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    customer_id     TEXT NOT NULL,
    level           TEXT NOT NULL,
    tier            TEXT NOT NULL DEFAULT 'tier_1',
    status          TEXT NOT NULL DEFAULT 'received',
    decision        TEXT NOT NULL DEFAULT 'pending',
    risk_score      REAL NOT NULL DEFAULT 0,
    risk_level      TEXT NOT NULL DEFAULT 'low',
    results_json    TEXT NOT NULL DEFAULT '{}',
    actor_sub       TEXT NOT NULL DEFAULT '',
    rekyc_of        TEXT,
    rekyc_reason    TEXT,
    rekyc_deadline  TEXT,
    override_by     TEXT,
    override_reason TEXT,
    override_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    return _NAMED_PARAM.sub(r"%(\1)s", query)


class Database:
    def __init__(self, database_url: str = DATABASE_URL, sqlite_path: str = DEFAULT_SQLITE_PATH):
        self._lock = threading.Lock()
        self._is_pg = database_url.startswith(("postgres://", "postgresql://"))
        if self._is_pg:
            import psycopg
            from psycopg.rows import dict_row

            self._psycopg = psycopg
            self._dict_row = dict_row
            self._dsn = database_url
            self._conn = None
        else:
            Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(sqlite_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            with self._lock, self._conn:
                self._conn.executescript(SQLITE_SCHEMA)

    def _pg_conn(self):
        return self._psycopg.connect(self._dsn, row_factory=self._dict_row)

    def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        params = params or {}
        if self._is_pg:
            with self._pg_conn() as conn:
                rows = conn.execute(_to_pg(sql), params).fetchall()
            return [dict(r) for r in rows]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> int:
        params = params or {}
        if self._is_pg:
            with self._pg_conn() as conn:
                count = conn.execute(_to_pg(sql), params).rowcount
                conn.commit()
            return count
        with self._lock, self._conn:
            return self._conn.execute(sql, params).rowcount

    def query_one(self, sql: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    @staticmethod
    def as_list(value: Any) -> list:
        import json

        if value is None:
            return []
        if isinstance(value, list):
            return value
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return []

    @staticmethod
    def as_dict(value: Any) -> dict:
        import json

        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return {}


_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db


def reset_db_for_tests(db: Database | None) -> None:
    global _db
    _db = db
