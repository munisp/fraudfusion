"""Storage layer for the billing service.

PostgreSQL (via psycopg) when DATABASE_URL=postgres(ql)://... is configured;
otherwise a local SQLite file (BILLING_DB_PATH, default ./data/billing.db)
for local development and tests.

The canonical PostgreSQL schema lives in
database/20260901_billing_monetization.sql; SQLITE_SCHEMA below is the
SQLite-compatible mirror used only when no DATABASE_URL is set.

Queries are written with :name bind parameters (SQLite native); for
PostgreSQL they are rewritten to %(name)s for psycopg.

Money is integer kobo everywhere; JSONB columns are stored as TEXT (JSON
strings) in SQLite and decoded at the boundary.
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
    "BILLING_DB_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "billing.db"),
)

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT PRIMARY KEY,
    organization  TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    owner_sub     TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS billing_plans (
    id                     TEXT PRIMARY KEY,
    display_name           TEXT NOT NULL,
    monthly_fee_kobo       INTEGER NOT NULL DEFAULT 0 CHECK (monthly_fee_kobo >= 0),
    included_units         TEXT NOT NULL DEFAULT '{}',
    overage_rates_kobo     TEXT NOT NULL DEFAULT '{}',
    allowed_scopes         TEXT NOT NULL DEFAULT '[]',
    default_rate_limit_rpm INTEGER NOT NULL DEFAULT 60 CHECK (default_rate_limit_rpm > 0),
    is_active              INTEGER NOT NULL DEFAULT 1,
    created_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS billing_subscriptions (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    plan_id              TEXT NOT NULL REFERENCES billing_plans (id),
    status               TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('trialing', 'active', 'past_due', 'suspended', 'cancelled')),
    current_period_start TEXT NOT NULL,
    current_period_end   TEXT NOT NULL,
    overrides            TEXT NOT NULL DEFAULT '{}',
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS billing_subscriptions_tenant_active_idx
    ON billing_subscriptions (tenant_id) WHERE status IN ('trialing', 'active', 'past_due');
CREATE INDEX IF NOT EXISTS billing_subscriptions_plan_idx ON billing_subscriptions (plan_id);

CREATE TABLE IF NOT EXISTS api_keys (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name           TEXT NOT NULL DEFAULT '',
    key_prefix     TEXT NOT NULL,
    key_hash       TEXT NOT NULL CHECK (length(key_hash) = 64),
    scopes         TEXT NOT NULL DEFAULT '[]',
    -- live | test (ffk_test_ keys never meter revenue usage)
    key_type       TEXT NOT NULL DEFAULT 'live'
                   CHECK (key_type IN ('live', 'test')),
    rate_limit_rpm INTEGER NOT NULL DEFAULT 60 CHECK (rate_limit_rpm > 0),
    status         TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'suspended', 'revoked')),
    expires_at     TEXT,
    last_used_at   TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS api_keys_hash_idx ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS api_keys_status_idx ON api_keys (status);

CREATE TABLE IF NOT EXISTS usage_events (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    api_key_id      TEXT REFERENCES api_keys (id) ON DELETE SET NULL,
    service         TEXT NOT NULL,
    operation       TEXT NOT NULL,
    units           INTEGER NOT NULL DEFAULT 1 CHECK (units > 0),
    amount_kobo     INTEGER NOT NULL DEFAULT 0 CHECK (amount_kobo >= 0),
    idempotency_key TEXT NOT NULL,
    occurred_at     TEXT NOT NULL,
    -- live | test: 'test' rows are audit-only, excluded from usage_rollups
    environment     TEXT NOT NULL DEFAULT 'live'
                    CHECK (environment IN ('live', 'test')),
    ingested_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS usage_events_tenant_idem_idx
    ON usage_events (tenant_id, idempotency_key);
CREATE INDEX IF NOT EXISTS usage_events_tenant_op_time_idx
    ON usage_events (tenant_id, operation, occurred_at);
CREATE INDEX IF NOT EXISTS usage_events_key_idx ON usage_events (api_key_id);

CREATE TABLE IF NOT EXISTS usage_rollups (
    tenant_id   TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    period      TEXT NOT NULL CHECK (length(period) = 7),
    operation   TEXT NOT NULL,
    units       INTEGER NOT NULL DEFAULT 0 CHECK (units >= 0),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (tenant_id, period, operation)
);

CREATE TABLE IF NOT EXISTS billing_invoices (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    subscription_id       TEXT REFERENCES billing_subscriptions (id) ON DELETE SET NULL,
    period                TEXT NOT NULL CHECK (length(period) = 7),
    line_items            TEXT NOT NULL DEFAULT '[]',
    subtotal_kobo         INTEGER NOT NULL DEFAULT 0 CHECK (subtotal_kobo >= 0),
    vat_kobo              INTEGER NOT NULL DEFAULT 0 CHECK (vat_kobo >= 0),
    total_kobo            INTEGER NOT NULL DEFAULT 0 CHECK (total_kobo >= 0),
    currency              TEXT NOT NULL DEFAULT 'NGN',
    status                TEXT NOT NULL DEFAULT 'draft'
                          CHECK (status IN ('draft', 'issued', 'paid', 'void')),
    due_date              TEXT,
    issued_at             TEXT,
    paid_at               TEXT,
    settlement_journal_id TEXT,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, period)
);
CREATE INDEX IF NOT EXISTS billing_invoices_status_idx ON billing_invoices (status);
CREATE INDEX IF NOT EXISTS billing_invoices_tenant_idx ON billing_invoices (tenant_id, period);

CREATE TABLE IF NOT EXISTS billing_dunning_events (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    invoice_id TEXT REFERENCES billing_invoices (id) ON DELETE SET NULL,
    action     TEXT NOT NULL CHECK (action IN ('reminder', 'past_due', 'suspend_keys', 'grace', 'resume', 'write_off')),
    detail     TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS billing_dunning_events_tenant_idx
    ON billing_dunning_events (tenant_id, created_at);
"""

# Plan seed mirrors database/20260901_billing_monetization.sql.
PLAN_SEED = [
    (
        "developer_sandbox", "Developer Sandbox", 0,
        '{"fraud_score": 1000, "aml_score": 200, "kyc_verify": 20, "kgqa_query": 500, "land_verification": 0}',
        "{}",
        '["fraud_score", "aml_score", "kyc_verify", "kgqa_query"]', 30,
    ),
    (
        "growth", "Growth", 15000000,
        '{"fraud_score": 50000, "aml_score": 10000, "kyc_verify": 500, "kgqa_query": 20000, "land_verification": 10}',
        '{"fraud_score": 40, "aml_score": 90, "kyc_verify": 12000, "kgqa_query": 250, "land_verification": 500000}',
        '["fraud_score", "aml_score", "kyc_verify", "kgqa_query", "land_verification"]', 120,
    ),
    (
        "scale", "Scale", 60000000,
        '{"fraud_score": 300000, "aml_score": 60000, "kyc_verify": 3000, "kgqa_query": 120000, "land_verification": 60}',
        '{"fraud_score": 30, "aml_score": 70, "kyc_verify": 10000, "kgqa_query": 200, "land_verification": 450000}',
        '["fraud_score", "aml_score", "kyc_verify", "kgqa_query", "land_verification"]', 600,
    ),
    (
        "enterprise", "Enterprise", 0,
        "{}",
        "{}",
        '["fraud_score", "aml_score", "kyc_verify", "kgqa_query", "land_verification"]', 1200,
    ),
]

_PARAM_RE = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    """Rewrite :name bind parameters to psycopg's %(name)s form."""
    return _PARAM_RE.sub(r"%(\1)s", query)


class Database:
    def __init__(self, database_url: str = DATABASE_URL, sqlite_path: str = DEFAULT_SQLITE_PATH):
        self._is_pg = database_url.startswith("postgres")
        self._lock = threading.Lock()
        if self._is_pg:
            import psycopg
            from psycopg.rows import dict_row

            self._psycopg = psycopg
            self._dict_row = dict_row
            self._dsn = database_url
        else:
            path = Path(sqlite_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            with self._lock, self._conn:
                self._conn.executescript(SQLITE_SCHEMA)
                self._migrate_sqlite()
            self._seed_plans()

    @property
    def backend(self) -> str:
        return "postgres" if self._is_pg else "sqlite"

    def _migrate_sqlite(self) -> None:
        """Idempotent column adds for pre-existing SQLite dev databases
        (canonical PG: database/20260930_api_key_types.sql)."""
        for table, col, ddl in (
            ("api_keys", "key_type",
             "TEXT NOT NULL DEFAULT 'live' CHECK (key_type IN ('live', 'test'))"),
            ("usage_events", "environment",
             "TEXT NOT NULL DEFAULT 'live' CHECK (environment IN ('live', 'test'))"),
        ):
            existing = {row["name"] for row in
                        self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if col not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")

    def _seed_plans(self) -> None:
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT OR IGNORE INTO billing_plans "
                "(id, display_name, monthly_fee_kobo, included_units, overage_rates_kobo, allowed_scopes, default_rate_limit_rpm) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                PLAN_SEED,
            )

    def _pg_conn(self):
        # Fresh short-lived connection per call; mirrors onboarding-service.
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

    def insert_idempotent(self, sql: str, params: dict[str, Any]) -> bool:
        """INSERT that returns False instead of raising on unique conflict."""
        if self._is_pg:
            sql = sql.rstrip().rstrip(";")
            if "ON CONFLICT" not in sql.upper():
                sql += " ON CONFLICT DO NOTHING"
            return self.execute(sql, params) > 0
        try:
            return self.execute(sql, params) > 0
        except sqlite3.IntegrityError:
            return False

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
