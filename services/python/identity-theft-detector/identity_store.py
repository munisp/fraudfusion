"""Storage layer for the identity-theft-detector.

PostgreSQL (via psycopg) when DATABASE_URL=postgres(ql)://... is configured;
otherwise a local SQLite file (IDENTITY_DB_PATH) for local dev/tests.

Canonical PostgreSQL schema: database/20260901_python_services_caveats.sql
(bvn_registry, nin_registry, customer_identifiers) and
database/20260827_service_base_tables.sql (identity_theft_alerts).
SQLITE_SCHEMA below is the SQLite-compatible mirror.

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
    "IDENTITY_DB_PATH",
    str(Path(__file__).resolve().parent / "data" / "identity_theft.db"),
)

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS bvn_registry (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    bvn           TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    date_of_birth TEXT,
    phone_number  TEXT,
    email         TEXT,
    is_synthetic  INTEGER NOT NULL DEFAULT 0,
    provenance    TEXT NOT NULL DEFAULT 'admin-import',
    imported_by   TEXT,
    -- enrollment-source tracing: where/how this identifier was enrolled
    -- (bank_branch, sim_registration_agent, nimc_fep, self_service, unknown).
    enrollment_source   TEXT NOT NULL DEFAULT 'unknown',
    enrollment_agent_id TEXT,
    enrollment_channel  TEXT,
    enrolled_at         TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, bvn)
);

CREATE TABLE IF NOT EXISTS nin_registry (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    nin           TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    date_of_birth TEXT,
    phone_number  TEXT,
    email         TEXT,
    is_synthetic  INTEGER NOT NULL DEFAULT 0,
    provenance    TEXT NOT NULL DEFAULT 'admin-import',
    imported_by   TEXT,
    enrollment_source   TEXT NOT NULL DEFAULT 'unknown',
    enrollment_agent_id TEXT,
    enrollment_channel  TEXT,
    enrolled_at         TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, nin)
);

CREATE TABLE IF NOT EXISTS customer_identifiers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    customer_id TEXT NOT NULL,
    id_type     TEXT NOT NULL CHECK (id_type IN ('phone', 'email', 'device', 'nin', 'bvn')),
    id_value    TEXT NOT NULL,
    enrollment_source   TEXT NOT NULL DEFAULT 'unknown',
    enrollment_agent_id TEXT,
    enrollment_channel  TEXT,
    enrolled_at         TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, id_type, id_value, customer_id)
);

CREATE TABLE IF NOT EXISTS identity_theft_alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL DEFAULT 'default',
    alert_id   TEXT,
    user_id    TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    details    TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Victim-exposure detection (lane I1): lawfully obtained breach/leak
-- indicator batches (e.g. EFCC account-supplier crackdown, telco reports).
-- NDPA posture: identifiers are stored ONLY as sha256 hashes, never plaintext.
CREATE TABLE IF NOT EXISTS exposure_import_batches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    batch_id      TEXT NOT NULL,
    source_note   TEXT,
    row_count     INTEGER NOT NULL DEFAULT 0,
    matched_count INTEGER NOT NULL DEFAULT 0,
    imported_by   TEXT,
    imported_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, batch_id)
);

CREATE TABLE IF NOT EXISTS exposure_indicators (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    batch_id        TEXT NOT NULL,
    identifier_type TEXT NOT NULL CHECK (identifier_type IN ('phone', 'email', 'device', 'nin', 'bvn')),
    identifier_hash TEXT NOT NULL,  -- sha256 of the normalised identifier; plaintext is NEVER persisted
    breach_ref      TEXT NOT NULL,
    observed_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, identifier_type, identifier_hash, breach_ref)
);
"""

# Columns added after the initial schema shipped; existing SQLite DB files get
# them via guarded ALTERs (CREATE TABLE IF NOT EXISTS does not upgrade them).
_ENROLLMENT_COLUMNS = (
    ("enrollment_source", "TEXT NOT NULL DEFAULT 'unknown'"),
    ("enrollment_agent_id", "TEXT"),
    ("enrollment_channel", "TEXT"),
    ("enrolled_at", "TEXT"),
)
_ENROLLMENT_TABLES = ("bvn_registry", "nin_registry", "customer_identifiers")

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    return _NAMED_PARAM.sub(r"%(\1)s", query)


class IdentityStore:
    """Minimal synchronous DB helper (dual SQLite/PostgreSQL driver)."""

    def __init__(self, database_url: str = DATABASE_URL, sqlite_path: str = DEFAULT_SQLITE_PATH,
                 seed: bool = True):
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
                self._upgrade_sqlite_schema()
                if seed:
                    self._seed_synthetic()

    def _upgrade_sqlite_schema(self) -> None:
        """Backward-compatible column upgrades for pre-existing SQLite files
        (CREATE TABLE IF NOT EXISTS never alters an existing table)."""
        for table in _ENROLLMENT_TABLES:
            existing = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            for col, ddl in _ENROLLMENT_COLUMNS:
                if col not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")

    def _seed_synthetic(self) -> None:
        """Clearly-marked SYNTHETIC rows so dev/tests exercise real match
        paths. Production rows arrive via the admin CSV import endpoint."""
        bvn_seed = [
            ("22345678901", "SYNTHETIC Adaeze Eze", "1990-05-20", "+2348012345678", "adaeze.syn@example.test"),
            ("22345678902", "SYNTHETIC Bola Ahmed", "1985-11-02", "+2348098765432", "bola.syn@example.test"),
            ("22345678903", "SYNTHETIC Chidi Okafor", "1978-01-15", "+2348012345678", "chidi.syn@example.test"),
        ]
        nin_seed = [
            ("12345678901", "SYNTHETIC Adaeze Eze", "1990-05-20", "+2348012345678", "adaeze.syn@example.test"),
            ("12345678902", "SYNTHETIC Danladi Musa", "1992-07-30", "+2347055550001", "danladi.syn@example.test"),
        ]
        ident_seed = [
            ("cust-syn-1", "phone", "+2348012345678"),
            ("cust-syn-1", "email", "adaeze.syn@example.test"),
            ("cust-syn-1", "device", "dev-syn-001"),
            ("cust-syn-2", "phone", "+2348012345678"),  # shared phone: cluster
            ("cust-syn-2", "device", "dev-syn-002"),
            ("cust-syn-3", "email", "bola.syn@example.test"),
        ]
        for bvn, name, dob, phone, email in bvn_seed:
            self._conn.execute(
                "INSERT OR IGNORE INTO bvn_registry (bvn, full_name, date_of_birth, phone_number, email,"
                " is_synthetic, provenance) VALUES (?, ?, ?, ?, ?, 1, 'seed-synthetic')",
                (bvn, name, dob, phone, email),
            )
        for nin, name, dob, phone, email in nin_seed:
            self._conn.execute(
                "INSERT OR IGNORE INTO nin_registry (nin, full_name, date_of_birth, phone_number, email,"
                " is_synthetic, provenance) VALUES (?, ?, ?, ?, ?, 1, 'seed-synthetic')",
                (nin, name, dob, phone, email),
            )
        for cid, typ, val in ident_seed:
            self._conn.execute(
                "INSERT OR IGNORE INTO customer_identifiers (customer_id, id_type, id_value)"
                " VALUES (?, ?, ?)",
                (cid, typ, val),
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

    # ------------------- dialect helpers for JSON details -------------------

    def alert_matches_identifier(self, tenant_id: str, field: str, value: str) -> list[dict[str, Any]]:
        """Find identity_theft_alerts whose details JSON carries this identifier."""
        if self._is_pg:
            return self.query(
                "SELECT id, alert_id, user_id, alert_type, risk_level, created_at"
                " FROM identity_theft_alerts WHERE tenant_id = :t AND details ->> :f = :v",
                {"t": tenant_id, "f": field, "v": value},
            )
        return self.query(
            "SELECT id, alert_id, user_id, alert_type, risk_level, created_at"
            " FROM identity_theft_alerts WHERE tenant_id = :t"
            " AND json_extract(details, '$.' || :f) = :v",
            {"t": tenant_id, "f": field, "v": value},
        )

    def exposure_alert_exists(self, tenant_id: str, user_id: str,
                              identifier_hash: str, breach_ref: str) -> bool:
        """Dedupe key for exposure alerts: customer + identifier + breach_ref
        (the identifier itself is only ever compared as a sha256 hash)."""
        if self._is_pg:
            row = self.query_one(
                "SELECT id FROM identity_theft_alerts WHERE tenant_id = :t"
                " AND user_id = :u AND alert_type = 'exposure_detected'"
                " AND details ->> 'identifier_hash' = :h AND details ->> 'breach_ref' = :b LIMIT 1",
                {"t": tenant_id, "u": user_id, "h": identifier_hash, "b": breach_ref},
            )
        else:
            row = self.query_one(
                "SELECT id FROM identity_theft_alerts WHERE tenant_id = :t"
                " AND user_id = :u AND alert_type = 'exposure_detected'"
                " AND json_extract(details, '$.identifier_hash') = :h"
                " AND json_extract(details, '$.breach_ref') = :b LIMIT 1",
                {"t": tenant_id, "u": user_id, "h": identifier_hash, "b": breach_ref},
            )
        return row is not None

    def enrollments_for_identifier(self, tenant_id: str, id_type: str,
                                   id_value: str) -> list[dict[str, Any]]:
        """Enrollment-source provenance for every customer holding this
        identifier — the trace-to-source evidence for duplicate clusters."""
        return self.query(
            "SELECT customer_id, id_type, id_value, enrollment_source,"
            " enrollment_agent_id, enrollment_channel, enrolled_at"
            " FROM customer_identifiers"
            " WHERE tenant_id = :t AND id_type = :ty AND id_value = :v",
            {"t": tenant_id, "ty": id_type, "v": id_value},
        )


_store: IdentityStore | None = None


def get_store() -> IdentityStore:
    global _store
    if _store is None:
        _store = IdentityStore()
    return _store


def reset_store_for_tests(store: IdentityStore | None) -> None:
    global _store
    _store = store
