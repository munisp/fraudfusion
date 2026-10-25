"""Test environment: embedded PostgreSQL, no SQLite anywhere."""
import os

# --- embedded PostgreSQL bootstrap (Postgres-only platform) ---------------
import sys as _sys

_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "..", "python", "integration"))
from embedded_pg import clone_migrated  # noqa: E402

# Canonical migrations applied: service internals resolve DATABASE_URL and
# touch platform tables (professional_registry etc.), not just land schema.
os.environ["DATABASE_URL"] = clone_migrated("landenv")
