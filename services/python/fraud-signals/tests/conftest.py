import os
import sys

os.environ.setdefault("FRAUD_SIGNALS_SQLITE", "/tmp/fraud_signals_test.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import store as store_mod  # noqa: E402
from store import SignalStore, reset_store_for_tests  # noqa: E402


@pytest.fixture()
def fresh_store(tmp_path):
    s = SignalStore(sqlite_path=str(tmp_path / "fs.db"))
    reset_store_for_tests(s)
    yield s
    reset_store_for_tests(None)
