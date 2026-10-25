"""Shared embedded-PostgreSQL test harness.

FraudFusion is Postgres-only: the platform has no SQLite fallback in any
service. Tests that need a database boot a real embedded PostgreSQL via
pgserver (no docker, no system packages) instead of reaching for a lighter
stand-in that would drift from production semantics.

Usage in a conftest.py (set DATABASE_URL *before* importing service modules
that read it at import time):

    import os
    import sys
    sys.path.insert(0, <path to services/python/integration>)
    from embedded_pg import fresh_database

    os.environ["DATABASE_URL"] = fresh_database("myservice")

Per-test isolation fixtures should call ``fresh_database()`` again — each
call creates a brand-new database on the shared server, so tests never
share tables.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

_server = None


def _boot():
    """Boot (once per process) the shared embedded PostgreSQL server.

    cleanup_mode='delete': the data directory is removed when the test
    process exits. With per-test fresh databases the WAL would otherwise
    accumulate gigabytes per suite on disk.
    """
    global _server
    if _server is None:
        xdg = Path("/tmp/xdg")
        xdg.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("XDG_RUNTIME_DIR", str(xdg))
        import pgserver  # imported lazily so XDG_RUNTIME_DIR lands first
        _server = pgserver.get_server(f"/tmp/ff-embedpg-{os.getpid()}",
                                      cleanup_mode="delete")
    return _server


def embedded_dsn() -> str:
    """DSN of the shared server's maintenance database."""
    return _boot().get_uri()


def _db_uri(dbname: str) -> str:
    """URI-form DSN for a database on the shared server.

    pgserver serves over a Unix socket (postgresql://postgres:@/postgres?host=/tmp/...);
    build URIs manually so the DSN keeps the postgresql:// scheme that
    service stores require.
    """
    base = _boot().get_uri()
    head, _, query = base.partition("?")
    head = head.rsplit("/", 1)[0] + "/" + dbname
    return f"{head}?{query}" if query else head


def fresh_database(prefix: str = "test") -> str:
    """Create a fresh, empty database on the shared server; return its DSN.

    A new database per store construction gives perfect test isolation
    without any table-dropping bookkeeping.
    """
    import psycopg

    name = f"{prefix}_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(_boot().get_uri(), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    return _db_uri(name)


def _dbname(dsn: str) -> str:
    import psycopg

    return psycopg.conninfo.conninfo_to_dict(dsn)["dbname"]


_migrated: dict[str, str] = {}


def migrated_database(prefix: str = "test") -> str:
    """A database with every canonical database/*.sql migration applied.

    Created once per process and cached; use ``clone_migrated`` for
    per-test isolation.
    """
    if prefix not in _migrated:
        import glob
        import psycopg

        dsn = fresh_database(prefix)
        repo = Path(__file__).resolve().parents[3]
        with psycopg.connect(dsn, autocommit=True) as conn:
            for f in sorted(glob.glob(str(repo / "database" / "*.sql"))):
                conn.execute(open(f, encoding="utf-8").read())
        _migrated[prefix] = _dbname(dsn)
    return _db_uri(_migrated[prefix])


def clone_migrated(prefix: str = "test") -> str:
    """Fresh database cloned from the migrated template (fast: CREATE
    DATABASE .. TEMPLATE). Ideal for per-test store fixtures."""
    import psycopg

    template = _migrated.get(prefix) or _dbname(migrated_database(prefix))
    name = f"{prefix}_c{uuid.uuid4().hex[:10]}"
    with psycopg.connect(_boot().get_uri(), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}" TEMPLATE "{template}"')
    return _db_uri(name)
