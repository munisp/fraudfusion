import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "integration"))

from embedded_pg import fresh_database  # noqa: E402

# Postgres-only: point the service at a real embedded PostgreSQL database
# BEFORE importing store/main (they read DATABASE_URL at import time).
os.environ["DATABASE_URL"] = fresh_database("fraudsignals")

import pytest  # noqa: E402

from store import SignalStore, reset_store_for_tests  # noqa: E402


@pytest.fixture()
def fresh_store():
    s = SignalStore(database_url=fresh_database("fraudsignals"))
    reset_store_for_tests(s)
    yield s
    reset_store_for_tests(None)
