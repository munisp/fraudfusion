"""Test environment: embedded PostgreSQL, no SQLite anywhere."""
import os

# --- embedded PostgreSQL bootstrap (Postgres-only platform) ---------------
import sys as _sys

_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "..", "integration"))
from embedded_pg import fresh_database  # noqa: E402

os.environ["DATABASE_URL"] = fresh_database("eventsenv")
