#!/usr/bin/env python3
"""Gazetteer loader verification on a real embedded PostgreSQL.

Applies all migrations once, runs database/geo/load_gazetteer.py TWICE
(idempotency), and asserts the known-answer geo queries. Complements
run_migrations_embedded_pg.py (which covers SQL migrations only).

Usage:
    pip install pgserver psycopg[binary]
    XDG_RUNTIME_DIR=/tmp/xdg python3 database/tests/test_gazetteer_loader.py
"""
import glob
import os
import sys

import pgserver
import psycopg

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "database", "geo"))


def main() -> int:
    import load_gazetteer

    srv = pgserver.get_server(os.environ.get("PG_TEST_DATA", "/tmp/fraudfusion-geotest"))
    dsn = srv.get_uri()

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        for f in sorted(glob.glob(os.path.join(REPO, "database", "*.sql"))):
            cur.execute(open(f, encoding="utf-8").read())
        cur.execute("SELECT count(*) FROM geo_gazetteer")
        seed = cur.fetchone()[0]
        assert seed == 72, f"expected 72 seed rows, got {seed}"

    run1 = load_gazetteer.load_gazetteer(dsn)
    run2 = load_gazetteer.load_gazetteer(dsn)
    assert run1["staged"] == 108_807, run1
    assert run1["inserted"] > 108_000, run1
    assert run2["inserted"] == 0 and run2["updated"] == 0, f"not idempotent: {run2}"
    assert run1["total"] == run2["total"]

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT geo_distance_km('lagos', 'london')")
        d = cur.fetchone()[0]
        assert d is not None and 4_800 < d < 5_200, f"lagos-london {d}"
        cur.execute("SELECT lat, lon FROM geo_resolve('Ado-Ekiti')")  # hyphen normalised
        assert cur.fetchone() is not None, "Ado-Ekiti did not resolve"
        cur.execute("SELECT geo_distance_km('lagos', 'no such place xyz')")
        assert cur.fetchone()[0] is None, "unknown place must be NULL"
        cur.execute("SELECT lat FROM geo_gazetteer WHERE name = 'lagos'")
        assert abs(cur.fetchone()[0] - 6.45407) < 0.01, "seed not upgraded to GeoNames coords"

    print(f"gazetteer loader verified: run1={run1} run2={run2}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
