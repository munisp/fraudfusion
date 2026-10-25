"""Data store for the land-verification-service journey endpoints.

PostgreSQL only (via psycopg): DATABASE_URL must point at Postgres —
the platform has no SQLite fallback. Canonical schema:
database/20260901_python_services_caveats.sql.

Queries use :name bind parameters, rewritten to %(name)s for psycopg.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    return _NAMED_PARAM.sub(r"%(\1)s", query)


def _now() -> str:
    return datetime.utcnow().isoformat()


class LandDataStore:
    """Minimal synchronous DB helper (PostgreSQL only)."""

    def __init__(self, database_url: str = DATABASE_URL, seed: bool = True):
        if not database_url.startswith(("postgres://", "postgresql://")):
            raise RuntimeError(
                "PostgreSQL is required: set DATABASE_URL=postgresql://... — "
                "the land-verification store has no SQLite fallback.")
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
        """SYNTHETIC professional directory + one registry parcel so dev/test
        journeys exercise the real DB path. Production data arrives via the
        registry file imports / professional onboarding, never from here."""
        pros = [
            ("pro-syn-law-1", "SYNTHETIC Folake Balogun", "lawyer", "NBA/SYN/001", True, 4.8, 132,
             "Property Law", 14, "Lagos",
             {"phone": "+2348011110001", "email": "folake.syn@example.test",
              "office": "12 SYNTHETIC Way, Ikoyi, Lagos"},
             50000, ["en", "yo"], 0.92, 210, ["NBA"],
             "https://fraudfusion.io/professionals/pro-syn-law-1"),
            ("pro-syn-law-2", "SYNTHETIC Emeka Nwosu", "lawyer", "NBA/SYN/002", True, 4.5, 87,
             "Property Law", 9, "Lagos",
             {"phone": "+2348011110002", "email": "emeka.syn@example.test",
              "office": "4 SYNTHETIC Close, Lekki, Lagos"},
             35000, ["en", "ig"], 0.88, 120, ["NBA"],
             "https://fraudfusion.io/professionals/pro-syn-law-2"),
            ("pro-syn-sur-1", "SYNTHETIC Musa Abdullahi", "surveyor", "SURCON/SYN/001", True, 4.6, 54,
             "Cadastral Surveys", 11, "Lagos",
             {"phone": "+2348011110003", "email": "musa.syn@example.test",
              "office": "8 SYNTHETIC Road, Ikeja, Lagos"},
             40000, ["en", "ha"], None, None, ["SURCON"],
             "https://fraudfusion.io/professionals/pro-syn-sur-1"),
            ("pro-syn-est-1", "SYNTHETIC Yetunde Alabi", "estate_agent", "NIESV/SYN/001", True, 4.3, 41,
             "Residential Sales", 7, "Lagos",
             {"phone": "+2348011110004", "email": "yetunde.syn@example.test",
              "office": "21 SYNTHETIC Ave, Yaba, Lagos"},
             25000, ["en", "yo"], None, None, ["NIESV"],
             "https://fraudfusion.io/professionals/pro-syn-est-1"),
        ]
        for (pid, name, ptype, lic, lver, rating, reviews, spec, years, state, contact,
             fee, langs, sr, cases, certs, url) in pros:
            self.execute(
                "INSERT INTO professional_registry (id, name, professional_type,"
                " license_number, license_verified, rating, review_count, specialization,"
                " years_experience, state, contact, consultation_fee, languages, success_rate,"
                " cases_handled, certifications, profile_url, source)"
                " VALUES (:id, :name, :ptype, :lic, :lver, :rating, :reviews, :spec, :years,"
                " :state, :contact, :fee, :langs, :sr, :cases, :certs, :url, 'seed-synthetic')"
                " ON CONFLICT DO NOTHING",
                {"id": pid, "name": name, "ptype": ptype, "lic": lic, "lver": lver,
                 "rating": rating, "reviews": reviews, "spec": spec, "years": years,
                 "state": state, "contact": json.dumps(contact), "fee": fee,
                 "langs": list(langs), "sr": sr, "cases": cases,
                 "certs": list(certs), "url": url},
            )
        today = datetime.utcnow().date()
        for (pid, *_rest) in pros:
            for d in range(14):
                day = (today + timedelta(days=d)).isoformat()
                for start, end, typ in (("09:00", "10:00", "virtual"), ("11:00", "12:00", "in_person"),
                                        ("14:00", "15:00", "virtual"), ("10:00", "11:00", "phone")):
                    self.execute(
                        "INSERT INTO professional_availability"
                        " (professional_id, slot_date, start_time, end_time, slot_type, is_available)"
                        " VALUES (:pid, :day, :start, :end, :typ, TRUE) ON CONFLICT DO NOTHING",
                        {"pid": pid, "day": day, "start": start, "end": end, "typ": typ},
                    )
        self.execute(
            "INSERT INTO lands_registry_records (tenant_id, state, plot_number,"
            " certificate_number, owner_name, property_address, lga, status, transfer_type,"
            " transfer_date, provenance) VALUES ('default','Lagos','SYN-PLT-001','SYN-CERT-001',"
            " 'SYNTHETIC Landowner One','1 SYNTHETIC Close, Ikoyi','Eti-Osa','active',"
            " 'registration', :td, 'seed-synthetic') ON CONFLICT DO NOTHING",
            {"td": (datetime.utcnow() - timedelta(days=730)).isoformat()},
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

    # ------------------------------------------------------------------
    # JSON/array normalization helpers (defensive: accept both decoded and
    # serialized forms; Postgres-only since Round 27)
    # ------------------------------------------------------------------
    @staticmethod
    def as_list(value: Any) -> list:
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
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return {}


_store: LandDataStore | None = None


def get_land_store() -> LandDataStore:
    global _store
    if _store is None:
        _store = LandDataStore()
    return _store


def reset_land_store_for_tests(store: LandDataStore | None) -> None:
    global _store
    _store = store
