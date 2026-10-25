# Geospatial Stack — PostGIS + GeoNames Gazetteer + Apache Sedona

**Round 25** closed the audit's R4 residual ("a curated city table is not a
geo database") with a three-layer geospatial stack, all fail-closed and
honest about capability. **Round 26** closed the remaining data/runtime
gaps: the gazetteer is now the full GeoNames populated-places dump
(108,807 places), the agent detector measures its own distances, and the
Sedona jobs have a runnable compose profile.

## Layers

### 1. PostGIS (database) — `database/20261026_postgis_geo.sql`

- The platform Postgres image is now `postgis/postgis:16-3.4` (drop-in).
- The migration **probes honestly**: with the extension present it creates
  `geography(Point,4326)` columns + GiST indexes (`geo_gazetteer`,
  `login_patterns`); without it (e.g. embedded pgserver in CI) it warns and
  still applies — distance math falls back to a SQL haversine inside the
  same `geo_distance_km()` function. Verified idempotent by the embedded-PG
  harness (double-apply, 39/39 migrations).
- `geo_gazetteer` is the **single source of truth** for place → coordinate
  resolution. It ships with a 72-place hand seed (Nigerian state capitals +
  major cities + regional/global fraud-corridor hubs; public-domain
  coordinates) and is extended to the **full GeoNames populated-places dump
  (108,807 unique names: every Nigerian P-class feature + every world city
  with population ≥ 5,000; GeoNames CC-BY 4.0)** by
  `database/geo/load_gazetteer.py`, an idempotent loader over
  `database/geo/gazetteer.csv.gz` (COPY → temp table → single
  `INSERT .. ON CONFLICT (name) DO UPDATE`, strictly-greater population
  wins). Prepared by `database/20261101_geonames_full_gazetteer.sql`
  (adds `population`, `geo_normalize_name()`).
- SQL API: `geo_resolve(name) → (lat, lon)` and
  `geo_distance_km(a, b) → km | NULL` (NULL = unknown, never a silent 0).
  Name matching normalises case, hyphens and whitespace on both sides, so
  GeoNames' "Ado-Ekiti" resolves from "ado ekiti".
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
tested). Impossible travel resolves ~70 places embedded and the full
108,807-place GeoNames gazetteer in the DB modes, flagging
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
- **Runtime (Round 26)**: `python -m geo_analytics` CLI runner
  (`mule-clusters`, `agent-offlocation`), packaged as
  `deploy/geo-analytics.Dockerfile` (official `apache/sedona` base) and a
  `geo-analytics` compose profile:
  ```
  docker compose -f deploy/docker-compose.platform.yml --profile geo-analytics \
    run --rm geo-analytics mule-clusters \
      --events /data/events.parquet --out /data/out/mule_clusters
  ```
  The CLI exits 2 with a named-dependency message when the Sedona runtime
  is absent — never a silent pass (tested).

### 4. Service-side agent distance (Round 26) — `fraud-signals/geo_enrich.py`

The `agent` detector used to trust caller-reported
`distance_from_registered_km`. Now, when the payload carries
`registered_location` + `operating_location` instead, the service measures
the distance itself: `geo_distance_km()` on Postgres (full GeoNames
gazetteer), or the embedded 72-place gazetteer + Python haversine when the
geo functions are unreachable (e.g. un-migrated database). A caller-supplied distance always
wins (never overwritten); unknown places produce a zero-weight
`geo_enrichment: geo_unresolved` factor — an honest skip, never a silent 0.
The audited event keeps the caller's original payload.

## Honest limits (unchanged posture)

- The gazetteer is a place-name lookup, not a geocoder: street addresses,
  coordinates-as-text and IP-derived locations still resolve to
  `geo_unresolved` / `location_unresolved`. Extending coverage is a data
  operation (rebuild `gazetteer.csv.gz` from a fresher GeoNames dump), not
  code.
- Place names are unique-per-name with highest-population-wins: "Lagos"
  resolves to Lagos, Nigeria (15.4M) over Lagos, Portugal. Disambiguation
  beyond that needs country-aware callers.
- Sedona jobs run in the analytics environment (compose profile / Spark
  cluster); they are not part of request-path latency budgets.
