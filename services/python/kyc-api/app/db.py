"""Storage layer for the KYC API.

PostgreSQL (via psycopg) when DATABASE_URL=postgres(ql)://... is configured;
otherwise a local SQLite file (KYC_DB_PATH, default ./data/kyc.db) for local
dev/tests.

The canonical PostgreSQL schema for pep_list/watchlist lives in
database/20260827_pep_kyb_merchant.sql; SQLITE_SCHEMA below is the
SQLite-compatible mirror plus the service-local kyc_requests table.

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
    "KYC_DB_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "kyc.db"),
)

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS kyc_requests (
    id           TEXT PRIMARY KEY,
    customer_id  TEXT NOT NULL,
    level        TEXT NOT NULL CHECK (level IN ('basic', 'enhanced', 'premium')),
    tier         TEXT NOT NULL CHECK (tier IN ('tier_1', 'tier_2', 'tier_3')),
    status       TEXT NOT NULL DEFAULT 'received'
                 CHECK (status IN ('received', 'screening', 'completed')),
    decision     TEXT NOT NULL DEFAULT 'pending'
                 CHECK (decision IN ('pending', 'approved', 'manual_review', 'rejected')),
    risk_score   REAL NOT NULL DEFAULT 0,
    risk_level   TEXT NOT NULL DEFAULT 'low',
    results_json TEXT NOT NULL DEFAULT '{}',
    actor_sub    TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS kyc_requests_customer_idx ON kyc_requests (customer_id);

-- Local PEP list (canonical Postgres version + seed rules in
-- database/20260827_pep_kyb_merchant.sql). Screening matches against this
-- table; it is refreshed by compliance batch jobs, never by this service.
CREATE TABLE IF NOT EXISTS pep_list (
    id           TEXT PRIMARY KEY,
    full_name    TEXT NOT NULL,
    date_of_birth TEXT,
    nationality  TEXT,
    position     TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT 'seed',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Local sanctions watchlist cache (mirrors the JSON seed in data/watchlist.json
-- when imported; the canonical store is the `watchlist` Postgres table).
CREATE TABLE IF NOT EXISTS watchlist (
    id           TEXT PRIMARY KEY,
    full_name    TEXT NOT NULL,
    date_of_birth TEXT,
    nationality  TEXT,
    program      TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT 'local',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""

# Demo seed so local/dev screening exercises a real match path. Production
# rows are loaded by compliance batch jobs into the Postgres tables.
PEP_SEED = [
    ("pep-seed-1", "Ngozi Okonjo-Iweala", "1954-06-13", "NG", "Former Minister of Finance (Nigeria)", "seed-demo"),
    ("pep-seed-2", "Godwin Emefiele", "1961-06-04", "NG", "Former Governor, Central Bank of Nigeria", "seed-demo"),
]

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
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
                self._seed_pep()

    def _seed_pep(self) -> None:
        count = self._conn.execute("SELECT COUNT(*) AS c FROM pep_list").fetchone()["c"]
        if count:
            return
        for row in PEP_SEED:
            self._conn.execute(
                "INSERT OR IGNORE INTO pep_list (id, full_name, date_of_birth, nationality, position, source)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                row,
            )

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
