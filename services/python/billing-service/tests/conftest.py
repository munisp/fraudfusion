"""Billing tests run against a real embedded PostgreSQL (pgserver) with the
canonical migrations applied — the platform has no SQLite fallback."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "integration"))

from embedded_pg import fresh_database  # noqa: E402

os.environ["DATABASE_URL"] = fresh_database("billingenv")
