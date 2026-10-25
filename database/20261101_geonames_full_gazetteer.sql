-- ============================================================================
-- FraudFusion — full GeoNames gazetteer support (2026-11-01)
--
-- Extends the 72-place hand seed from 20261026_postgis_geo.sql with the full
-- GeoNames populated-places dump (all NG P-class features + every world city
-- with population >= 5000; 108,807 unique place names, CC-BY 4.0, geonames.org).
--
-- The bulk data itself is NOT embedded in SQL: it ships as the compressed CSV
-- database/geo/gazetteer.csv.gz and is applied idempotently by
-- database/geo/load_gazetteer.py (COPY into a temp table, then a single
-- INSERT .. ON CONFLICT (name) DO UPDATE — highest-population entry wins).
-- This migration only prepares the schema and hardens name matching.
-- ============================================================================

-- Population lets the resolver rank duplicates and the loader merge safely.
ALTER TABLE geo_gazetteer ADD COLUMN IF NOT EXISTS population integer NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- Name normalisation: GeoNames stores hyphenated names ("Ado-Ekiti") while
-- users type "ado ekiti". Normalise hyphens -> spaces (and collapse repeats)
-- on both the lookup side and, in the loader, the storage side.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION geo_normalize_name(p_name text)
RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT regexp_replace(lower(replace(trim(p_name), '-', ' ')), '\s+', ' ', 'g')
$$;

CREATE OR REPLACE FUNCTION geo_resolve(p_name text)
RETURNS TABLE(lat double precision, lon double precision)
LANGUAGE sql STABLE AS $$
    SELECT g.lat, g.lon FROM geo_gazetteer g WHERE g.name = geo_normalize_name(p_name)
$$;

-- Haversine fallback — correct everywhere, used when PostGIS is absent.
-- Returns NULL for unknown places: an honest unknown, never a silent 0.
CREATE OR REPLACE FUNCTION geo_distance_km(a_name text, b_name text)
RETURNS double precision
LANGUAGE plpgsql STABLE AS $$
DECLARE
    a RECORD; b RECORD;
    lat1 double precision; lon1 double precision;
    lat2 double precision; lon2 double precision;
    h double precision;
BEGIN
    SELECT g.lat, g.lon INTO a FROM geo_gazetteer g WHERE g.name = geo_normalize_name(a_name);
    SELECT g.lat, g.lon INTO b FROM geo_gazetteer g WHERE g.name = geo_normalize_name(b_name);
    IF a IS NULL OR b IS NULL THEN
        RETURN NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'geo_gazetteer' AND column_name = 'geo') THEN
        RETURN ST_Distance(
            (SELECT geo FROM geo_gazetteer WHERE name = geo_normalize_name(a_name)),
            (SELECT geo FROM geo_gazetteer WHERE name = geo_normalize_name(b_name))
        ) / 1000.0;
    END IF;
    lat1 := radians(a.lat); lon1 := radians(a.lon);
    lat2 := radians(b.lat); lon2 := radians(b.lon);
    h := sin((lat2 - lat1) / 2) ^ 2 + cos(lat1) * cos(lat2) * sin((lon2 - lon1) / 2) ^ 2;
    RETURN 6371.0 * 2 * asin(sqrt(h));
END $$;

-- Keep the login_patterns backfill consistent with the normalised matching.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'login_patterns' AND column_name = 'geo') THEN
        UPDATE login_patterns p
           SET lat = g.lat, lon = g.lon, geo = g.geo
          FROM geo_gazetteer g
         WHERE p.lat IS NULL AND g.name = geo_normalize_name(p.location);
    ELSE
        UPDATE login_patterns p
           SET lat = g.lat, lon = g.lon
          FROM geo_gazetteer g
         WHERE p.lat IS NULL AND g.name = geo_normalize_name(p.location);
    END IF;
END $$;
