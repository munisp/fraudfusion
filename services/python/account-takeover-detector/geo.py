"""Libre geo layer (geo_libre) for the account-takeover detector.

Layered place resolution and distance, honest about capability:

  1. **db / postgis mode** — resolve and measure through the platform's
     geo_gazetteer + geo_resolve()/geo_distance_km() SQL functions
     (database/20261026_postgis_geo.sql). When the PostGIS extension is
     present the function uses ST_Distance on geography columns; otherwise
     it falls back to a SQL haversine. Either way the DB is the source of
     truth.
  2. **embedded mode** — the same gazetteer bundled here (kept in sync
     with the migration seed; the parity is pinned by tests) with a
     pure-Python haversine. Used when the DB/geo functions are unreachable.
  3. **unknown** — a place in neither layer resolves to None, and callers
     surface ``location_unresolved``; never a silent 0.0.

No licensed dataset (MaxMind etc.) — coordinates are public-domain.
"""
from __future__ import annotations

import logging
import math
from typing import Any, Optional

log = logging.getLogger("account-takeover-detector.geo")

GEO_MODE_POSTGIS = "postgis"
GEO_MODE_SQL = "sql-haversine"
GEO_MODE_EMBEDDED = "embedded-fallback"

# Embedded gazetteer — MUST match the geo_gazetteer seed in
# database/20261026_postgis_geo.sql (parity pinned by tests).
GAZETTEER: dict[str, tuple[float, float]] = {
    # Nigerian state capitals + major cities
    "abuja": (9.0765, 7.3986), "lagos": (6.5244, 3.3792),
    "kano": (12.0022, 8.5920), "ibadan": (7.3775, 3.9470),
    "port harcourt": (4.8156, 7.0498), "benin city": (6.3350, 5.6037),
    "kaduna": (10.5105, 7.4165), "jos": (9.8965, 8.8583),
    "ilorin": (8.4966, 4.5426), "enugu": (6.4403, 7.4942),
    "aba": (5.1166, 7.3667), "onitsha": (6.1667, 6.7833),
    "warri": (5.5167, 5.7500), "owerri": (5.4833, 7.0333),
    "calabar": (4.9517, 8.3220), "uyo": (5.0333, 7.9167),
    "akure": (7.2571, 5.2058), "osogbo": (7.7667, 4.5667),
    "abeokuta": (7.1475, 3.3619), "maiduguri": (11.8311, 13.1510),
    "zaria": (11.0855, 7.7199), "sokoto": (13.0059, 5.2476),
    "katsina": (12.9908, 7.6018), "bauchi": (10.3158, 9.8442),
    "gombe": (10.2897, 11.1673), "yola": (9.2000, 12.4833),
    "makurdi": (7.7322, 8.5391), "minna": (9.6136, 6.5569),
    "lafia": (8.4833, 8.5167), "asaba": (6.1833, 6.7333),
    "awka": (6.2167, 7.0833), "lokoja": (7.8023, 6.7333),
    "dutse": (11.7594, 9.3392), "damaturu": (11.7469, 11.9609),
    "birnin kebbi": (12.4539, 4.1975), "jalingo": (8.8833, 11.3667),
    "yenegoa": (4.9267, 6.2676), "ado ekiti": (7.6167, 5.2167),
    "ogbomosho": (8.1333, 4.2667), "nsukka": (6.8567, 7.3958),
    # Regional + global hubs
    "accra": (5.6037, -0.1870), "abidjan": (5.3600, -4.0083),
    "dakar": (14.7167, -17.4677), "nairobi": (-1.2921, 36.8219),
    "johannesburg": (-26.2041, 28.0473), "cairo": (30.0444, 31.2357),
    "london": (51.5072, -0.1276), "paris": (48.8566, 2.3522),
    "frankfurt": (50.1109, 8.6821), "amsterdam": (52.3676, 4.9041),
    "madrid": (40.4168, -3.7038), "rome": (41.9028, 12.4964),
    "istanbul": (41.0082, 28.9784), "dubai": (25.2048, 55.2708),
    "doha": (25.2854, 51.5310), "riyadh": (24.7136, 46.6753),
    "mumbai": (19.0760, 72.8777), "delhi": (28.7041, 77.1025),
    "singapore": (1.3521, 103.8198), "hong kong": (22.3193, 114.1694),
    "tokyo": (35.6762, 139.6503), "beijing": (39.9042, 116.4074),
    "shanghai": (31.2304, 121.4737), "sydney": (-33.8688, 151.2093),
    "new york": (40.7128, -74.0060), "los angeles": (34.0522, -118.2437),
    "chicago": (41.8781, -87.6298), "houston": (29.7604, -95.3698),
    "atlanta": (33.7490, -84.3880), "miami": (25.7617, -80.1918),
    "toronto": (43.6532, -79.3832), "sao paulo": (-23.5505, -46.6333),
}


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(h))


def embedded_resolve(name: str) -> Optional[tuple[float, float]]:
    return GAZETTEER.get(str(name).strip().lower())


def embedded_distance_km(origin: str, destination: str) -> Optional[float]:
    a, b = embedded_resolve(origin), embedded_resolve(destination)
    if a is None or b is None:
        return None
    return haversine_km(a, b)


async def detect_geo_mode(pool: Any) -> str:
    """Probe the DB's geo capability at startup. Never raises: on any
    failure the service honestly degrades to the embedded gazetteer."""
    try:
        has_ext = await pool.fetchval(
            "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'postgis')")
        await pool.fetchval("SELECT geo_distance_km('lagos', 'abuja')")
        mode = GEO_MODE_POSTGIS if has_ext else GEO_MODE_SQL
        log.info("geo layer: %s (database gazetteer)", mode)
        return mode
    except Exception as exc:  # noqa: BLE001
        log.warning("geo layer: DB gazetteer unavailable (%s) — EMBEDDED fallback",
                    exc.__class__.__name__)
        return GEO_MODE_EMBEDDED


class GeoResolver:
    """Runtime resolver bound to a pool + detected mode."""

    def __init__(self, pool: Any = None, mode: str = GEO_MODE_EMBEDDED):
        self.pool = pool
        self.mode = mode

    @property
    def db_backed(self) -> bool:
        return self.pool is not None and self.mode in (GEO_MODE_POSTGIS, GEO_MODE_SQL)

    async def resolve(self, name: str) -> Optional[tuple[float, float]]:
        if self.db_backed:
            try:
                row = await self.pool.fetchrow(
                    "SELECT lat, lon FROM geo_resolve($1)", str(name))
                if row is not None:
                    return (float(row["lat"]), float(row["lon"]))
                return None
            except Exception as exc:  # noqa: BLE001 — honest degrade
                log.warning("geo resolve via DB failed (%s); embedded fallback",
                            exc.__class__.__name__)
        return embedded_resolve(name)

    async def distance_km(self, origin: str, destination: str) -> Optional[float]:
        if self.db_backed:
            try:
                return await self.pool.fetchval(
                    "SELECT geo_distance_km($1, $2)", str(origin), str(destination))
            except Exception as exc:  # noqa: BLE001
                log.warning("geo distance via DB failed (%s); embedded fallback",
                            exc.__class__.__name__)
        return embedded_distance_km(origin, destination)
