# Geospatial Stack — PostGIS + Libre Gazetteer + Apache Sedona

**Round 25.** Closes the audit's R4 residual ("a curated city table is not a
geo database") with a three-layer geospatial stack, all fail-closed and
honest about capability.

## Layers

### 1. PostGIS (database) — `database/20261026_postgis_geo.sql`

- The platform Postgres image is now `postgis/postgis:16-3.4` (drop-in).
- The migration **probes honestly**: with the extension present it creates
  `geography(Point,4326)` columns + GiST indexes (`geo_gazetteer`,
  `login_patterns`); without it (e.g. embedded pgserver in CI) it warns and
  still applies — distance math falls back to a SQL haversine inside the
  same `geo_distance_km()` function. Verified idempotent by the embedded-PG
  harness (double-apply, 39/39 migrations).
- `geo_gazetteer` (72 seeded places: all Nigerian state capitals + major
  cities + regional/global fraud-corridor hubs) is the **single source of
  truth** for place → coordinate resolution. Public-domain coordinates; no
  licensed dataset.
- SQL API: `geo_resolve(name) → (lat, lon)` and
  `geo_distance_km(a, b) → km | NULL` (NULL = unknown, never a silent 0).
- `login_patterns` persists resolved `lat`/`lon` per login (backfilled from
  the gazetteer), enabling future spatial audit queries
  (`ST_Distance`, `ST_ClusterWithin` over raw history).

### 2. Libre geo layer (service) — `account-takeover-detector/geo.py`

`GeoResolver` binds a detected mode at startup and reports it on `/health`:

| Mode | When | Behavior |
|---|---|---|
| `postgis` | extension + functions present | DB gazetteer, ST_Distance |
| `sql-haversine` | functions present, no extension | DB gazetteer, SQL haversine |
| `embedded-fallback` | DB/geo functions unreachable | bundled gazetteer + Python haversine |

The embedded gazetteer is **pinned byte-for-value** to the migration seed
by `TestGazetteerParity` — the two layers cannot drift. Mid-run DB geo
failures degrade to the embedded layer per-call (detection keeps working;
tested). Impossible travel now resolves ~70 places instead of 6 and flags
`location_unresolved` honestly for anything else.

### 3. Apache Sedona (analytics) — `intelligence/geo_analytics/`

Platform-scale geo analytics that the request-path services should never
run synchronously:

- `reference.py` — pure-Python reference implementations (haversine
  DBSCAN, off-location rollups), unit-tested, correct on small extracts.
- `sedona_jobs.py` — the same analytics as Spark/Sedona SQL jobs:
  - `mule_ring_geo_clusters` — `ST_ClusterDBSCAN` over event coordinates;
    clusters dense with *distinct subjects* are flagged (mule rings
    physically co-locate).
  - `agent_offlocation_rollup` — per-agent share of events beyond the
    registered radius via `ST_DistanceSphere`.
- **Fail-closed**: missing pyspark/Sedona raises an honest RuntimeError
  naming the dependency; unresolved coordinates are excluded and counted,
  never placed. The km→degrees eps conversion for `ST_ClusterDBSCAN` on
  EPSG:4326 is documented (reproject to a metric SRID for
  latitude-accurate work).

## Honest limits (unchanged posture)

- The gazetteer is 72 curated places, not a geocoder: arbitrary towns and
  IP-derived locations still resolve to `location_unresolved`. A GeoNames
  dump import into `geo_gazetteer` is a data-load operation, not code.
- Sedona jobs are wired for the analytics environment (Spark cluster /
  lakehouse); they are not part of request-path latency budgets.
- The `agent` fraud-signals detector still takes `distance_from_registered_km`
  as an input — callers can now compute it from `geo_distance_km` instead
  of self-reporting.
