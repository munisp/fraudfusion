"""Storage layer for the identity-theft-detector — PostgreSQL only.

Canonical schema: database/20260901_python_services_caveats.sql
(bvn_registry, nin_registry, customer_identifiers) and
database/20260827_service_base_tables.sql (identity_theft_alerts).
Tests boot a real embedded PostgreSQL (pgserver) via
services/python/integration/embedded_pg.py — no stand-in engines.

Queries use :name bind parameters, rewritten to %(name)s for psycopg.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()


_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    return _NAMED_PARAM.sub(r"%(\1)s", query)


class IdentityStore:
    """Minimal synchronous DB helper (PostgreSQL only)."""

    def __init__(self, database_url: str = DATABASE_URL, seed: bool = True):
        if not database_url.startswith(("postgres://", "postgresql://")):
            raise RuntimeError(
                "PostgreSQL is required: set DATABASE_URL=postgresql://... — "
                "the identity store has no SQLite fallback.")
        import psycopg
        from psycopg.rows import dict_row

        self._lock = threading.Lock()
        self._psycopg = psycopg
        self._dict_row = dict_row
        self._dsn = database_url
        self._is_pg = True
        if seed:
            self._seed_synthetic()

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
            self.execute(
                "INSERT INTO bvn_registry (bvn, full_name, date_of_birth, phone_number, email,"
                " is_synthetic, provenance) VALUES (:v, :n, :d, :p, :e, TRUE, 'seed-synthetic')"
                " ON CONFLICT DO NOTHING",
                {"v": bvn, "n": name, "d": dob, "p": phone, "e": email},
            )
        for nin, name, dob, phone, email in nin_seed:
            self.execute(
                "INSERT INTO nin_registry (nin, full_name, date_of_birth, phone_number, email,"
                " is_synthetic, provenance) VALUES (:v, :n, :d, :p, :e, TRUE, 'seed-synthetic')"
                " ON CONFLICT DO NOTHING",
                {"v": nin, "n": name, "d": dob, "p": phone, "e": email},
            )
        for cid, typ, val in ident_seed:
            self.execute(
                "INSERT INTO customer_identifiers (customer_id, id_type, id_value)"
                " VALUES (:c, :t, :v) ON CONFLICT DO NOTHING",
                {"c": cid, "t": typ, "v": val},
            )

    def _pg_conn(self):
        return self._psycopg.connect(self._dsn, row_factory=self._dict_row)

    def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        params = params or {}
        with self._pg_conn() as conn:
            rows = conn.execute(_to_pg(sql), params).fetchall()
        return [dict(r) for r in rows]

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> int:
        params = params or {}
        with self._pg_conn() as conn:
            count = conn.execute(_to_pg(sql), params).rowcount
            conn.commit()
        return count

    def query_one(self, sql: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # ------------------- dialect helpers for JSON details -------------------

    def alert_matches_identifier(self, tenant_id: str, field: str, value: str) -> list[dict[str, Any]]:
        """Find identity_theft_alerts whose details JSON carries this identifier."""
        return self.query(
            "SELECT id, alert_id, user_id, alert_type, risk_level, created_at"
            " FROM identity_theft_alerts WHERE tenant_id = :t AND details ->> :f = :v",
            {"t": tenant_id, "f": field, "v": value},
        )

    def exposure_alert_exists(self, tenant_id: str, user_id: str,
                              identifier_hash: str, breach_ref: str) -> bool:
        """Dedupe key for exposure alerts: customer + identifier + breach_ref
        (the identifier itself is only ever compared as a sha256 hash)."""
        row = self.query_one(
            "SELECT id FROM identity_theft_alerts WHERE tenant_id = :t"
            " AND user_id = :u AND alert_type = 'exposure_detected'"
            " AND details ->> 'identifier_hash' = :h AND details ->> 'breach_ref' = :b LIMIT 1",
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
