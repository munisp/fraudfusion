"""Storage layer for the onboarding service.

PostgreSQL (via psycopg) when DATABASE_URL=postgres(ql)://... is configured;
otherwise a local SQLite file (ONBOARDING_DB_PATH, default
./data/onboarding.db) for local development and tests.

The canonical PostgreSQL schema lives in
database/20260826_tenants_onboarding.sql; SQLITE_SCHEMA below is the
SQLite-compatible mirror used only when no DATABASE_URL is set.

Queries are written with :name bind parameters (SQLite native); for
PostgreSQL they are rewritten to %(name)s for psycopg.
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
    "ONBOARDING_DB_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "onboarding.db"),
)

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT PRIMARY KEY,
    organization  TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    owner_sub     TEXT NOT NULL,
    use_case      TEXT NOT NULL DEFAULT '',
    environment   TEXT NOT NULL DEFAULT 'sandbox'
                  CHECK (environment IN ('sandbox', 'production')),
    kyc_tier      TEXT NOT NULL DEFAULT 'basic'
                  CHECK (kyc_tier IN ('basic', 'enhanced', 'premium')),
    state         TEXT NOT NULL DEFAULT 'in_progress'
                  CHECK (state IN ('not_started', 'in_progress', 'pending_review', 'active', 'suspended')),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS tenants_owner_org_idx ON tenants (owner_sub, organization);

CREATE TABLE IF NOT EXISTS tenant_api_keys (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    label            TEXT NOT NULL DEFAULT '',
    environment      TEXT NOT NULL DEFAULT 'sandbox'
                     CHECK (environment IN ('sandbox', 'production')),
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'reviewed', 'approved', 'rejected', 'revoked')),
    key_hash         TEXT,
    key_prefix       TEXT,
    requested_by     TEXT NOT NULL,
    reviewed_by      TEXT,
    approved_by      TEXT,
    rejection_reason TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS tenant_api_keys_tenant_idx ON tenant_api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS tenant_api_keys_status_idx ON tenant_api_keys (status);

CREATE TABLE IF NOT EXISTS onboarding_checklist_items (
    tenant_id  TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    item_id    TEXT NOT NULL,
    label      TEXT NOT NULL,
    required   INTEGER NOT NULL DEFAULT 1,
    done       INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (tenant_id, item_id)
);

CREATE TABLE IF NOT EXISTS onboarding_approval_events (
    id         TEXT PRIMARY KEY,
    api_key_id TEXT NOT NULL REFERENCES tenant_api_keys (id) ON DELETE CASCADE,
    action     TEXT NOT NULL CHECK (action IN ('request', 'review', 'approve', 'reject', 'revoke')),
    actor_sub  TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS onboarding_approval_events_key_idx ON onboarding_approval_events (api_key_id);
"""

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    """Rewrite :name bind parameters to psycopg's %(name)s form."""
    return _NAMED_PARAM.sub(r"%(\1)s", query)


class Database:
    """Minimal synchronous DB helper (FastAPI runs sync endpoints in a
    threadpool; a lock serializes SQLite access)."""

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
            self._conn.execute("PRAGMA foreign_keys = ON")
            with self._lock, self._conn:
                self._conn.executescript(SQLITE_SCHEMA)

    def _pg_conn(self):
        # Fresh short-lived connection per call keeps the worker simple and
        # avoids cross-thread connection sharing; Postgres pooling can be
        # added later without changing call sites.
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
        """Run a write statement; returns affected row count."""
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
