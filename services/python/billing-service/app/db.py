"""Storage layer for the billing service — PostgreSQL only.

DATABASE_URL must point at PostgreSQL (psycopg). The canonical schema
lives in database/20260901_billing_monetization.sql and follow-up
migrations; this layer assumes they have been applied and fails fast
otherwise. Tests boot a real embedded PostgreSQL (pgserver) via
services/python/integration/embedded_pg.py — no stand-in engines.

Queries use :name bind parameters, rewritten to %(name)s for psycopg.
Money is integer kobo everywhere.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

_PARAM_RE = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    """Rewrite :name bind parameters to psycopg's %(name)s form."""
    return _PARAM_RE.sub(r"%(\1)s", query)


class Database:
    def __init__(self, database_url: str = DATABASE_URL):
        if not database_url.startswith(("postgres://", "postgresql://")):
            raise RuntimeError(
                "PostgreSQL is required: set DATABASE_URL=postgresql://... — "
                "the billing service has no SQLite fallback.")
        import psycopg
        from psycopg.rows import dict_row

        self._psycopg = psycopg
        self._dict_row = dict_row
        self._dsn = database_url
        self._lock = threading.Lock()
        self._is_pg = True

    @property
    def backend(self) -> str:
        return "postgres"

    def _pg_conn(self):
        # Fresh short-lived connection per call; mirrors onboarding-service.
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

    def insert_idempotent(self, sql: str, params: dict[str, Any]) -> bool:
        """INSERT that returns False instead of raising on unique conflict."""
        sql = sql.rstrip().rstrip(";")
        if "ON CONFLICT" not in sql.upper():
            sql += " ON CONFLICT DO NOTHING"
        return self.execute(sql, params) > 0

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
