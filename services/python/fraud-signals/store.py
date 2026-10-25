"""Dual-driver event store for fraud-signals-service.

Postgres is the source of record (FRAUDFUSION_REQUIRE_POSTGRES=1 makes the
SQLite fallback a boot-time error); SQLite serves dev/tests. Two generic
tables back all eight detectors:

  signal_events  — ingested facts (transactions, sessions, applications,
                   issuance records, payroll rows, claims) keyed by
                   (kind, subject_id); velocity/pattern detectors query
                   these windows.
  signal_evals   — hash-chained audit of every evaluation (verdict +
                   factors), tamper-evident like the doc-intel chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DEFAULT_SQLITE_PATH = os.getenv(
    "FRAUD_SIGNALS_SQLITE", str(Path(__file__).parent / "fraud_signals.db"))

SCHEMA = """
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
    score       REAL NOT NULL,
    verdict     TEXT NOT NULL,
    factors     TEXT NOT NULL DEFAULT '[]',
    mode        TEXT NOT NULL DEFAULT 'enforce',
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS signal_evals_idx
    ON signal_evals (detector, subject_id, created_at);
"""

# Existing deployments: add the shadow-mode column idempotently.
_MIGRATIONS = (
    "ALTER TABLE signal_evals ADD COLUMN mode TEXT NOT NULL DEFAULT 'enforce'",
)

_NAMED = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(sql: str) -> str:
    return _NAMED.sub(r"%(\1)s", sql)


class SignalStore:
    def __init__(self, database_url: str = DATABASE_URL,
                 sqlite_path: str = DEFAULT_SQLITE_PATH):
        self._lock = threading.Lock()
        self._is_pg = database_url.startswith(("postgres://", "postgresql://"))
        if (not self._is_pg and os.getenv("FRAUDFUSION_REQUIRE_POSTGRES", "")
                .strip().lower() in ("1", "true", "yes")):
            raise RuntimeError(
                "FRAUDFUSION_REQUIRE_POSTGRES is set: the SQLite fallback is "
                "disabled — PostgreSQL is the source of record.")
        if self._is_pg:
            import psycopg
            from psycopg.rows import dict_row
            self._psycopg, self._dict_row, self._dsn = psycopg, dict_row, database_url
            self._conn = None
            with self._pg_conn() as conn:
                conn.execute(_to_pg(SCHEMA))
                conn.commit()
        else:
            Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(sqlite_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            with self._lock, self._conn:
                self._conn.executescript(SCHEMA)
        self._apply_migrations()

    def _apply_migrations(self) -> None:
        """Idempotent column additions (SQLite has no IF NOT EXISTS for
        columns, so duplicate-column errors are swallowed)."""
        for sql in _MIGRATIONS:
            try:
                self.execute(sql)
            except Exception as exc:
                msg = str(exc).lower()
                if "duplicate column" not in msg and "already exists" not in msg:
                    raise

    def _pg_conn(self):
        return self._psycopg.connect(self._dsn, row_factory=self._dict_row)

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> int:
        params = params or {}
        if self._is_pg:
            with self._pg_conn() as conn:
                n = conn.execute(_to_pg(sql), params).rowcount
                conn.commit()
            return n
        with self._lock, self._conn:
            return self._conn.execute(sql, params).rowcount

    def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        params = params or {}
        if self._is_pg:
            with self._pg_conn() as conn:
                return [dict(r) for r in conn.execute(_to_pg(sql), params).fetchall()]
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    # -- domain helpers -----------------------------------------------------

    def record_event(self, event_id: str, kind: str, subject_id: str,
                     payload: dict, created_at: str) -> None:
        self.execute(
            "INSERT INTO signal_events (id, kind, subject_id, payload, created_at)"
            " VALUES (:i, :k, :s, :p, :c)",
            {"i": event_id, "k": kind, "s": subject_id,
             "p": json.dumps(payload), "c": created_at})

    def events(self, kind: str, subject_id: str, since_iso: str) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT payload, created_at FROM signal_events"
            " WHERE kind = :k AND subject_id = :s AND created_at >= :since"
            " ORDER BY created_at",
            {"k": kind, "s": subject_id, "since": since_iso})
        return [{"payload": json.loads(r["payload"]), "created_at": r["created_at"]}
                for r in rows]

    def append_eval(self, eval_id: str, detector: str, subject_id: str,
                    score: float, verdict: str, factors: list[dict],
                    created_at: str, mode: str = "enforce") -> str:
        """Hash-chained audit append; returns the entry hash. ``mode`` is
        metadata ('enforce' | 'shadow') and deliberately NOT part of the
        hashed body, so toggling shadow mode never breaks an existing chain."""
        last = self.query(
            "SELECT entry_hash FROM signal_evals WHERE detector = :d"
            " ORDER BY created_at DESC, id DESC LIMIT 1", {"d": detector})
        prev = last[0]["entry_hash"] if last else "GENESIS"
        body = json.dumps({"detector": detector, "subject_id": subject_id,
                           "score": score, "verdict": verdict,
                           "factors": factors, "created_at": created_at},
                          sort_keys=True)
        entry = hashlib.sha256(
            f"{prev}|{hashlib.sha256(body.encode()).hexdigest()}|{detector}"
            .encode()).hexdigest()
        self.execute(
            "INSERT INTO signal_evals (id, detector, subject_id, score, verdict,"
            " factors, mode, prev_hash, entry_hash, created_at)"
            " VALUES (:i, :d, :s, :sc, :v, :f, :m, :p, :e, :c)",
            {"i": eval_id, "d": detector, "s": subject_id, "sc": score,
             "v": verdict, "f": json.dumps(factors), "m": mode, "p": prev,
             "e": entry, "c": created_at})
        return entry

    def verify_chain(self, detector: str) -> dict[str, Any]:
        rows = self.query(
            "SELECT * FROM signal_evals WHERE detector = :d"
            " ORDER BY created_at, id", {"d": detector})
        prev = "GENESIS"
        for r in rows:
            body = json.dumps({"detector": r["detector"],
                               "subject_id": r["subject_id"],
                               "score": r["score"], "verdict": r["verdict"],
                               "factors": json.loads(r["factors"]),
                               "created_at": r["created_at"]}, sort_keys=True)
            expect = hashlib.sha256(
                f"{prev}|{hashlib.sha256(body.encode()).hexdigest()}|"
                f"{r['detector']}".encode()).hexdigest()
            if expect != r["entry_hash"] or r["prev_hash"] != prev:
                return {"valid": False, "broken_at": r["id"]}
            prev = r["entry_hash"]
        return {"valid": True, "entries": len(rows)}


_store: Optional[SignalStore] = None


def get_store() -> SignalStore:
    global _store
    if _store is None:
        _store = SignalStore()
    return _store


def reset_store_for_tests(store: Optional[SignalStore]) -> None:
    global _store
    _store = store


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
