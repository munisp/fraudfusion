"""Data store for the land-verification-service journey endpoints.

PostgreSQL (via psycopg) when DATABASE_URL=postgres(ql)://... is configured;
otherwise a local SQLite file (LAND_DATA_DB, default ./data/land_data.db) for
local dev/tests. Canonical PostgreSQL schema:
database/20260901_python_services_caveats.sql; SQLITE_SCHEMA below is the
SQLite-compatible mirror (TEXT[] -> JSON text, JSONB -> TEXT).

Queries use :name bind parameters (SQLite native); for PostgreSQL they are
rewritten to %(name)s for psycopg.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DEFAULT_SQLITE_PATH = os.getenv(
    "LAND_DATA_DB",
    str(Path(__file__).resolve().parent.parent / "data" / "land_data.db"),
)

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS lands_registry_records (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id          TEXT NOT NULL DEFAULT 'default',
    state              TEXT NOT NULL,
    plot_number        TEXT,
    certificate_number TEXT,
    owner_name         TEXT,
    property_address   TEXT,
    lga                TEXT,
    status             TEXT NOT NULL DEFAULT 'active',
    transfer_type      TEXT NOT NULL DEFAULT 'registration',
    transfer_date      TEXT,
    provenance         TEXT NOT NULL DEFAULT 'file-import',
    imported_by        TEXT,
    imported_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, state, certificate_number)
);

CREATE TABLE IF NOT EXISTS parcel_claimants (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id          TEXT NOT NULL DEFAULT 'default',
    state              TEXT NOT NULL,
    property_address   TEXT,
    certificate_number TEXT,
    claimant_name      TEXT NOT NULL,
    claim_date         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    document_type      TEXT,
    document_ref       TEXT,
    verified           INTEGER NOT NULL DEFAULT 0,
    conflicting        INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS court_disputes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        TEXT NOT NULL DEFAULT 'default',
    case_number      TEXT NOT NULL,
    state            TEXT NOT NULL,
    property_address TEXT,
    parties          TEXT NOT NULL DEFAULT '[]',
    description      TEXT,
    court_location   TEXT,
    status           TEXT NOT NULL DEFAULT 'filed'
                     CHECK (status IN ('filed','active','judgement','settled','struck_out')),
    filed_date       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, case_number)
);

CREATE TABLE IF NOT EXISTS professional_registry (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    name              TEXT NOT NULL,
    professional_type TEXT NOT NULL CHECK (professional_type IN ('lawyer','surveyor','estate_agent')),
    license_number    TEXT,
    license_verified  INTEGER NOT NULL DEFAULT 0,
    rating            REAL NOT NULL DEFAULT 0,
    review_count      INTEGER NOT NULL DEFAULT 0,
    specialization    TEXT,
    years_experience  INTEGER NOT NULL DEFAULT 0,
    state             TEXT NOT NULL,
    contact           TEXT NOT NULL DEFAULT '{}',
    consultation_fee  REAL NOT NULL DEFAULT 0,
    languages         TEXT NOT NULL DEFAULT '[]',
    success_rate      REAL,
    cases_handled     INTEGER,
    certifications    TEXT NOT NULL DEFAULT '[]',
    profile_url       TEXT,
    source            TEXT NOT NULL DEFAULT 'seed-synthetic',
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS professional_availability (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    professional_id TEXT NOT NULL REFERENCES professional_registry (id) ON DELETE CASCADE,
    slot_date       TEXT NOT NULL,
    start_time      TEXT NOT NULL,
    end_time        TEXT NOT NULL,
    slot_type       TEXT NOT NULL CHECK (slot_type IN ('virtual','in_person','phone')),
    is_available    INTEGER NOT NULL DEFAULT 1,
    UNIQUE (professional_id, slot_date, start_time, slot_type)
);

CREATE TABLE IF NOT EXISTS professional_bookings (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    user_id           TEXT NOT NULL,
    professional_id   TEXT NOT NULL REFERENCES professional_registry (id),
    booking_date      TEXT NOT NULL,
    start_time        TEXT NOT NULL,
    end_time          TEXT NOT NULL,
    consultation_type TEXT NOT NULL CHECK (consultation_type IN ('virtual','in_person','phone')),
    issue_description TEXT,
    urgency_level     TEXT,
    status            TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed','cancelled','completed')),
    meeting_link      TEXT,
    location          TEXT,
    instructions      TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS professional_bookings_slot_uidx
    ON professional_bookings (professional_id, booking_date, start_time) WHERE status = 'confirmed';

CREATE TABLE IF NOT EXISTS notification_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    booking_id      TEXT,
    user_id         TEXT,
    professional_id TEXT,
    payload         TEXT NOT NULL DEFAULT '{}',
    delivery_status TEXT NOT NULL DEFAULT 'queued' CHECK (delivery_status IN ('queued','sent','failed')),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""

_NAMED_PARAM = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


def _to_pg(query: str) -> str:
    return _NAMED_PARAM.sub(r"%(\1)s", query)


def _now() -> str:
    return datetime.utcnow().isoformat()


class LandDataStore:
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
                if seed:
                    self._seed_synthetic()

    def _seed_synthetic(self) -> None:
        """SYNTHETIC professional directory + one registry parcel so dev/test
        journeys exercise the real DB path. Production data arrives via the
        registry file imports / professional onboarding, never from here."""
        pros = [
            ("pro-syn-law-1", "SYNTHETIC Folake Balogun", "lawyer", "NBA/SYN/001", 1, 4.8, 132,
             "Property Law", 14, "Lagos",
             {"phone": "+2348011110001", "email": "folake.syn@example.test",
              "office": "12 SYNTHETIC Way, Ikoyi, Lagos"},
             50000, ["en", "yo"], 0.92, 210, ["NBA"],
             "https://fraudfusion.io/professionals/pro-syn-law-1"),
            ("pro-syn-law-2", "SYNTHETIC Emeka Nwosu", "lawyer", "NBA/SYN/002", 1, 4.5, 87,
             "Property Law", 9, "Lagos",
             {"phone": "+2348011110002", "email": "emeka.syn@example.test",
              "office": "4 SYNTHETIC Close, Lekki, Lagos"},
             35000, ["en", "ig"], 0.88, 120, ["NBA"],
             "https://fraudfusion.io/professionals/pro-syn-law-2"),
            ("pro-syn-sur-1", "SYNTHETIC Musa Abdullahi", "surveyor", "SURCON/SYN/001", 1, 4.6, 54,
             "Cadastral Surveys", 11, "Lagos",
             {"phone": "+2348011110003", "email": "musa.syn@example.test",
              "office": "8 SYNTHETIC Road, Ikeja, Lagos"},
             40000, ["en", "ha"], None, None, ["SURCON"],
             "https://fraudfusion.io/professionals/pro-syn-sur-1"),
            ("pro-syn-est-1", "SYNTHETIC Yetunde Alabi", "estate_agent", "NIESV/SYN/001", 1, 4.3, 41,
             "Residential Sales", 7, "Lagos",
             {"phone": "+2348011110004", "email": "yetunde.syn@example.test",
              "office": "21 SYNTHETIC Ave, Yaba, Lagos"},
             25000, ["en", "yo"], None, None, ["NIESV"],
             "https://fraudfusion.io/professionals/pro-syn-est-1"),
        ]
        for (pid, name, ptype, lic, lver, rating, reviews, spec, years, state, contact,
             fee, langs, sr, cases, certs, url) in pros:
            self._conn.execute(
                "INSERT OR IGNORE INTO professional_registry (id, name, professional_type,"
                " license_number, license_verified, rating, review_count, specialization,"
                " years_experience, state, contact, consultation_fee, languages, success_rate,"
                " cases_handled, certifications, profile_url, source)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'seed-synthetic')",
                (pid, name, ptype, lic, lver, rating, reviews, spec, years, state,
                 json.dumps(contact), fee, json.dumps(langs), sr, cases, json.dumps(certs), url),
            )
        today = datetime.utcnow().date()
        for (pid, *_rest) in pros:
            for d in range(14):
                day = (today + timedelta(days=d)).isoformat()
                for start, end, typ in (("09:00", "10:00", "virtual"), ("11:00", "12:00", "in_person"),
                                        ("14:00", "15:00", "virtual"), ("10:00", "11:00", "phone")):
                    self._conn.execute(
                        "INSERT OR IGNORE INTO professional_availability"
                        " (professional_id, slot_date, start_time, end_time, slot_type, is_available)"
                        " VALUES (?,?,?,?,?,1)",
                        (pid, day, start, end, typ),
                    )
        self._conn.execute(
            "INSERT OR IGNORE INTO lands_registry_records (tenant_id, state, plot_number,"
            " certificate_number, owner_name, property_address, lga, status, transfer_type,"
            " transfer_date, provenance) VALUES ('default','Lagos','SYN-PLT-001','SYN-CERT-001',"
            " 'SYNTHETIC Landowner One','1 SYNTHETIC Close, Ikoyi','Eti-Osa','active',"
            " 'registration', ?, 'seed-synthetic')",
            ((datetime.utcnow() - timedelta(days=730)).isoformat(),),
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
            try:
                with self._pg_conn() as conn:
                    count = conn.execute(_to_pg(sql), params).rowcount
                    conn.commit()
                return count
            except Exception:
                raise
        with self._lock, self._conn:
            return self._conn.execute(sql, params).rowcount

    def query_one(self, sql: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # ------------------------------------------------------------------
    # JSON/array normalization helpers (SQLite stores JSON as TEXT)
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
