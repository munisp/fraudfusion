"""Storage layer for the onboarding service — PostgreSQL only.

DATABASE_URL must point at PostgreSQL (psycopg). Canonical schema:
database/20260826_tenants_onboarding.sql and follow-up migrations. This
layer assumes the migrations have been applied and fails fast otherwise.
Tests boot a real embedded PostgreSQL (pgserver) via
services/python/integration/embedded_pg.py.

Queries use :name bind parameters, rewritten to %(name)s for psycopg.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

# KYB document-content verification columns (canonical PG columns added by
# database/20260929_kyb_verification.sql). Previously applied to the SQLite mirror via
# guarded ALTER TABLE below so pre-existing dev databases upgrade in place.
KYB_EXTRA_COLUMNS = {
    "verification_json": "TEXT",   # full verdict JSON from app/kyb_verification.py
    "verified_at": "TEXT",
}

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    """Rewrite :name bind parameters to psycopg's %(name)s form."""
    return _NAMED_PARAM.sub(r"%(\1)s", query)


class Database:
    """Minimal synchronous DB helper (FastAPI runs sync endpoints in a
    threadpool)."""

    def __init__(self, database_url: str = DATABASE_URL):
        if not database_url.startswith(("postgres://", "postgresql://")):
            raise RuntimeError(
                "PostgreSQL is required: set DATABASE_URL=postgresql://... — "
                "this service has no SQLite fallback.")
        import psycopg
        from psycopg.rows import dict_row

        self._lock = threading.Lock()
        self._psycopg = psycopg
        self._dict_row = dict_row
        self._dsn = database_url
        self._is_pg = True

    def _pg_conn(self):
        # Fresh short-lived connection per call keeps the worker simple and
        # avoids cross-thread connection sharing; Postgres pooling can be
        # added later without changing call sites.
        return self._psycopg.connect(self._dsn, row_factory=self._dict_row)

    def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        params = params or {}
        with self._pg_conn() as conn:
            rows = conn.execute(_to_pg(sql), params).fetchall()
        return [dict(r) for r in rows]

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> int:
        """Run a write statement; returns affected row count."""
        params = params or {}
        with self._pg_conn() as conn:
            count = conn.execute(_to_pg(sql), params).rowcount
            conn.commit()
        return count

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
