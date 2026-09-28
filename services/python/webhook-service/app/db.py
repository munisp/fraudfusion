"""Storage layer for the webhook service.

PostgreSQL (via psycopg) when DATABASE_URL=postgres(ql)://... is configured;
otherwise a local SQLite file (WEBHOOK_DB_PATH, default ./data/webhooks.db)
for local dev/tests.

The canonical PostgreSQL schema lives in database/20260930_webhooks.sql;
SQLITE_SCHEMA below is the SQLite-compatible mirror (same columns so
dual-driver code paths stay identical; JSON payloads are TEXT in both).

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
    "WEBHOOK_DB_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "webhooks.db"),
)

SQLITE_SCHEMA = """
-- Canonical PG: database/20260930_webhooks.sql
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL DEFAULT 'default',
    url                  TEXT NOT NULL,
    event_types          TEXT NOT NULL DEFAULT '[]',
    secret_hash          TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active', 'disabled')),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS webhook_endpoints_tenant_idx
    ON webhook_endpoints (tenant_id, status);

CREATE TABLE IF NOT EXISTS webhook_events (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    payload     TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS webhook_events_tenant_type_idx
    ON webhook_events (tenant_id, type);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                TEXT PRIMARY KEY,
    event_id          TEXT NOT NULL,
    endpoint_id       TEXT NOT NULL,
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'success', 'failed', 'dead_letter')),
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   REAL NOT NULL DEFAULT 0,
    attempts_json     TEXT NOT NULL DEFAULT '[]',
    last_status_code  INTEGER,
    last_error        TEXT,
    prev_hash         TEXT NOT NULL,
    entry_hash        TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at      TEXT
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
    ON webhook_deliveries (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS webhook_deliveries_endpoint_idx
    ON webhook_deliveries (endpoint_id, created_at);
CREATE INDEX IF NOT EXISTS webhook_deliveries_tenant_idx
    ON webhook_deliveries (tenant_id, id);
"""

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    return _NAMED_PARAM.sub(r"%(\1)s", query)


class Database:
    """Minimal synchronous DB helper (FastAPI runs sync endpoints in a
    threadpool; a lock serializes SQLite access). Same pattern as
    kyc-api/app/db.py."""

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


_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db


def reset_db_for_tests(db: Database | None) -> None:
    global _db
    _db = db
