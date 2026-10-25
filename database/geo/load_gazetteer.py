#!/usr/bin/env python3
"""Idempotent loader for the full GeoNames gazetteer into geo_gazetteer.

Applies database/geo/gazetteer.csv.gz (108,807 populated places: every
Nigerian P-class feature plus every world city with population >= 5,000;
GeoNames CC-BY 4.0, geonames.org) into the geo_gazetteer table created by
database/20261026_postgis_geo.sql and extended by
database/20261101_geonames_full_gazetteer.sql.

Merge policy (deterministic, safe to re-run any number of times):
  * rows are staged in a temp table via COPY, then merged with one
    INSERT .. ON CONFLICT (name) DO UPDATE
  * an incoming row replaces an existing one only when its population is
    strictly greater — so the hand-curated seed never loses to a GeoNames
    row with no population data, and re-runs converge to the same state
  * when PostGIS is present, the geography column is backfilled for rows
    that lack it

Usage:
    python database/geo/load_gazetteer.py --dsn postgresql://user:pass@host/db
    DATABASE_URL=postgresql://... python database/geo/load_gazetteer.py

Exits non-zero with a clear message when the database is unreachable or the
schema is missing; never partially applies (single transaction).
"""
from __future__ import annotations

import argparse
import csv
import gzip
import os
import sys

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gazetteer.csv.gz")

KIND_SQL = "CASE WHEN population >= 100000 THEN 'city' WHEN population >= 1000 THEN 'town' ELSE 'village' END"


def _load_rows(path: str) -> list[tuple[str, str, float, float, int]]:
    with gzip.open(path, "rt", newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if header != ["name", "country", "lat", "lon", "population"]:
            raise SystemExit(f"unexpected gazetteer header in {path}: {header!r}")
        rows = []
        for name, country, lat, lon, pop in reader:
            rows.append((name, country, float(lat), float(lon), int(pop)))
    return rows


def load_gazetteer(dsn: str, path: str = DATA_FILE) -> dict:
    import psycopg  # psycopg 3

    rows = _load_rows(path)
    stats: dict = {"staged": len(rows), "inserted": 0, "updated": 0, "geo_backfilled": 0}

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = 'geo_gazetteer'"
        )
        if cur.fetchone() is None:
            raise SystemExit(
                "geo_gazetteer table missing — run the SQL migrations first "
                "(20261026_postgis_geo.sql, 20261101_geonames_full_gazetteer.sql)"
            )

        cur.execute(
            """
            CREATE TEMP TABLE gazetteer_stage (
                name text, country text, lat double precision,
                lon double precision, population integer
            ) ON COMMIT DROP
            """
        )
        with cur.copy(
            "COPY gazetteer_stage (name, country, lat, lon, population) FROM STDIN"
        ) as copy:
            for row in rows:
                copy.write_row(row)

        cur.execute(
            f"""
            WITH merged AS (
                INSERT INTO geo_gazetteer (name, lat, lon, kind, country, population)
                SELECT s.name, s.lat, s.lon, {KIND_SQL}, s.country, s.population
                FROM gazetteer_stage s
                ON CONFLICT (name) DO UPDATE SET
                    lat = EXCLUDED.lat,
                    lon = EXCLUDED.lon,
                    kind = EXCLUDED.kind,
                    country = EXCLUDED.country,
                    population = EXCLUDED.population
                WHERE EXCLUDED.population > geo_gazetteer.population
                RETURNING (xmax = 0) AS inserted
            )
            SELECT
                count(*) FILTER (WHERE inserted),
                count(*) FILTER (WHERE NOT inserted)
            FROM merged
            """
        )
        stats["inserted"], stats["updated"] = cur.fetchone()

        # PostGIS present? Backfill the geography column for merged rows.
        cur.execute(
            """
            SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis')
               AND EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_name = 'geo_gazetteer' AND column_name = 'geo')
            """
        )
        if cur.fetchone()[0]:
            cur.execute(
                """
                UPDATE geo_gazetteer
                   SET geo = ST_SetSRID(ST_MakePoint(lon, lat), 4326)::geography
                 WHERE geo IS NULL
                """
            )
            stats["geo_backfilled"] = cur.rowcount

        cur.execute("SELECT count(*) FROM geo_gazetteer")
        stats["total"] = cur.fetchone()[0]

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dsn",
        default=os.environ.get("DATABASE_URL"),
        help="PostgreSQL DSN (default: $DATABASE_URL)",
    )
    parser.add_argument("--data", default=DATA_FILE, help="path to gazetteer.csv.gz")
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("provide --dsn or set DATABASE_URL")

    stats = load_gazetteer(args.dsn, args.data)
    print(
        "gazetteer loaded: "
        f"staged={stats['staged']} inserted={stats['inserted']} "
        f"updated={stats['updated']} total={stats['total']} "
        f"geo_backfilled={stats['geo_backfilled']}"
    )


if __name__ == "__main__":
    sys.exit(main())
