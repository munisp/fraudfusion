-- Round 25: geospatial stack — PostGIS + libre gazetteer (geo_libre layer).
--
-- Design:
--   * PostGIS is OPTIONAL and honestly probed: where the extension is
--     installed (platform compose uses postgis/postgis:16-3.4) we get
--     geography columns + GiST indexes + ST_Distance; where it is not
--     (e.g. embedded pgserver in CI) the migration still applies cleanly
--     and distance math falls back to a SQL haversine — services detect
--     the mode at runtime and report it (never silent).
--   * geo_gazetteer is the platform's single source of truth for place ->
--     coordinate resolution (replaces the per-service embedded tables).
--     Libre data: public-domain coordinates, no licensed dataset.
--
-- Idempotent: safe to apply twice (the embedded-PG harness does).

DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS postgis;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'postgis unavailable (%); geo stack runs in haversine fallback mode', SQLERRM;
END $$;

-- ---------------------------------------------------------------------------
-- Gazetteer: place name -> coordinates
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS geo_gazetteer (
    name        TEXT PRIMARY KEY,          -- lowercased canonical place name
    lat         DOUBLE PRECISION NOT NULL,
    lon         DOUBLE PRECISION NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'city',   -- city | town | hub
    country     TEXT NOT NULL DEFAULT 'NG'
);

-- Nigerian state capitals + major cities (public-domain coordinates).
INSERT INTO geo_gazetteer (name, lat, lon, kind, country) VALUES
    ('abuja', 9.0765, 7.3986, 'city', 'NG'),
    ('lagos', 6.5244, 3.3792, 'city', 'NG'),
    ('kano', 12.0022, 8.5920, 'city', 'NG'),
    ('ibadan', 7.3775, 3.9470, 'city', 'NG'),
    ('port harcourt', 4.8156, 7.0498, 'city', 'NG'),
    ('benin city', 6.3350, 5.6037, 'city', 'NG'),
    ('kaduna', 10.5105, 7.4165, 'city', 'NG'),
    ('jos', 9.8965, 8.8583, 'city', 'NG'),
    ('ilorin', 8.4966, 4.5426, 'city', 'NG'),
    ('enugu', 6.4403, 7.4942, 'city', 'NG'),
    ('aba', 5.1166, 7.3667, 'city', 'NG'),
    ('onitsha', 6.1667, 6.7833, 'city', 'NG'),
    ('warri', 5.5167, 5.7500, 'city', 'NG'),
    ('owerri', 5.4833, 7.0333, 'city', 'NG'),
    ('calabar', 4.9517, 8.3220, 'city', 'NG'),
    ('uyo', 5.0333, 7.9167, 'city', 'NG'),
    ('akure', 7.2571, 5.2058, 'city', 'NG'),
    ('osogbo', 7.7667, 4.5667, 'city', 'NG'),
    ('abeokuta', 7.1475, 3.3619, 'city', 'NG'),
    ('maiduguri', 11.8311, 13.1510, 'city', 'NG'),
    ('zaria', 11.0855, 7.7199, 'city', 'NG'),
    ('sokoto', 13.0059, 5.2476, 'city', 'NG'),
    ('katsina', 12.9908, 7.6018, 'city', 'NG'),
    ('bauchi', 10.3158, 9.8442, 'city', 'NG'),
    ('gombe', 10.2897, 11.1673, 'city', 'NG'),
    ('yola', 9.2000, 12.4833, 'city', 'NG'),
    ('makurdi', 7.7322, 8.5391, 'city', 'NG'),
    ('minna', 9.6136, 6.5569, 'city', 'NG'),
    ('lafia', 8.4833, 8.5167, 'city', 'NG'),
    ('asaba', 6.1833, 6.7333, 'city', 'NG'),
    ('awka', 6.2167, 7.0833, 'city', 'NG'),
    ('lokoja', 7.8023, 6.7333, 'city', 'NG'),
    ('dutse', 11.7594, 9.3392, 'city', 'NG'),
    ('damaturu', 11.7469, 11.9609, 'city', 'NG'),
    ('birnin kebbi', 12.4539, 4.1975, 'city', 'NG'),
    ('jalingo', 8.8833, 11.3667, 'city', 'NG'),
    ('yenegoa', 4.9267, 6.2676, 'city', 'NG'),
    ('ado ekiti', 7.6167, 5.2167, 'city', 'NG'),
    ('ogbomosho', 8.1333, 4.2667, 'city', 'NG'),
    ('nsukka', 6.8567, 7.3958, 'city', 'NG'),
    -- regional + global hubs (fraud corridors)
    ('accra', 5.6037, -0.1870, 'hub', 'GH'),
    ('abidjan', 5.3600, -4.0083, 'hub', 'CI'),
    ('dakar', 14.7167, -17.4677, 'hub', 'SN'),
    ('nairobi', -1.2921, 36.8219, 'hub', 'KE'),
    ('johannesburg', -26.2041, 28.0473, 'hub', 'ZA'),
    ('cairo', 30.0444, 31.2357, 'hub', 'EG'),
    ('london', 51.5072, -0.1276, 'hub', 'GB'),
    ('paris', 48.8566, 2.3522, 'hub', 'FR'),
    ('frankfurt', 50.1109, 8.6821, 'hub', 'DE'),
    ('amsterdam', 52.3676, 4.9041, 'hub', 'NL'),
    ('madrid', 40.4168, -3.7038, 'hub', 'ES'),
    ('rome', 41.9028, 12.4964, 'hub', 'IT'),
    ('istanbul', 41.0082, 28.9784, 'hub', 'TR'),
    ('dubai', 25.2048, 55.2708, 'hub', 'AE'),
    ('doha', 25.2854, 51.5310, 'hub', 'QA'),
    ('riyadh', 24.7136, 46.6753, 'hub', 'SA'),
    ('mumbai', 19.0760, 72.8777, 'hub', 'IN'),
    ('delhi', 28.7041, 77.1025, 'hub', 'IN'),
    ('singapore', 1.3521, 103.8198, 'hub', 'SG'),
    ('hong kong', 22.3193, 114.1694, 'hub', 'HK'),
    ('tokyo', 35.6762, 139.6503, 'hub', 'JP'),
    ('beijing', 39.9042, 116.4074, 'hub', 'CN'),
    ('shanghai', 31.2304, 121.4737, 'hub', 'CN'),
    ('sydney', -33.8688, 151.2093, 'hub', 'AU'),
    ('new york', 40.7128, -74.0060, 'hub', 'US'),
    ('los angeles', 34.0522, -118.2437, 'hub', 'US'),
    ('chicago', 41.8781, -87.6298, 'hub', 'US'),
    ('houston', 29.7604, -95.3698, 'hub', 'US'),
    ('atlanta', 33.7490, -84.3880, 'hub', 'US'),
    ('miami', 25.7617, -80.1918, 'hub', 'US'),
    ('toronto', 43.6532, -79.3832, 'hub', 'CA'),
    ('sao paulo', -23.5505, -46.6333, 'hub', 'BR')
ON CONFLICT (name) DO NOTHING;

-- PostGIS-only: geography column + GiST index for spatial queries.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis') THEN
        ALTER TABLE geo_gazetteer ADD COLUMN IF NOT EXISTS geo geography(Point, 4326);
        UPDATE geo_gazetteer SET geo = ST_SetSRID(ST_MakePoint(lon, lat), 4326)::geography
            WHERE geo IS NULL;
        CREATE INDEX IF NOT EXISTS geo_gazetteer_geo_idx ON geo_gazetteer USING gist(geo);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Resolution + distance helpers (work with or without PostGIS)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION geo_resolve(p_name text)
RETURNS TABLE(lat double precision, lon double precision)
LANGUAGE sql STABLE AS $$
    SELECT g.lat, g.lon FROM geo_gazetteer g WHERE g.name = lower(trim(p_name))
$$;

-- Haversine fallback — correct everywhere, used when PostGIS is absent.
CREATE OR REPLACE FUNCTION geo_distance_km(a_name text, b_name text)
RETURNS double precision
LANGUAGE plpgsql STABLE AS $$
DECLARE
    a RECORD; b RECORD;
    lat1 double precision; lon1 double precision;
    lat2 double precision; lon2 double precision;
    h double precision;
BEGIN
    SELECT g.lat, g.lon INTO a FROM geo_gazetteer g WHERE g.name = lower(trim(a_name));
    SELECT g.lat, g.lon INTO b FROM geo_gazetteer g WHERE g.name = lower(trim(b_name));
    IF a IS NULL OR b IS NULL THEN
        RETURN NULL;  -- honest unknown, never a silent 0
    END IF;
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'geo_gazetteer' AND column_name = 'geo') THEN
        RETURN ST_Distance(
            (SELECT geo FROM geo_gazetteer WHERE name = lower(trim(a_name))),
            (SELECT geo FROM geo_gazetteer WHERE name = lower(trim(b_name)))
        ) / 1000.0;
    END IF;
    lat1 := radians(a.lat); lon1 := radians(a.lon);
    lat2 := radians(b.lat); lon2 := radians(b.lon);
    h := sin((lat2 - lat1) / 2) ^ 2 + cos(lat1) * cos(lat2) * sin((lon2 - lon1) / 2) ^ 2;
    RETURN 6371.0 * 2 * asin(sqrt(h));
END $$;

-- ---------------------------------------------------------------------------
-- login_patterns: persist resolved coordinates with each login
-- ---------------------------------------------------------------------------
ALTER TABLE login_patterns ADD COLUMN IF NOT EXISTS lat double precision;
ALTER TABLE login_patterns ADD COLUMN IF NOT EXISTS lon double precision;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis') THEN
        ALTER TABLE login_patterns ADD COLUMN IF NOT EXISTS geo geography(Point, 4326);
        UPDATE login_patterns p
           SET lat = g.lat, lon = g.lon, geo = g.geo
          FROM geo_gazetteer g
         WHERE p.lat IS NULL AND g.name = lower(trim(p.location));
        CREATE INDEX IF NOT EXISTS login_patterns_geo_idx ON login_patterns USING gist(geo);
    ELSE
        UPDATE login_patterns p
           SET lat = g.lat, lon = g.lon
          FROM geo_gazetteer g
         WHERE p.lat IS NULL AND g.name = lower(trim(p.location));
    END IF;
END $$;
