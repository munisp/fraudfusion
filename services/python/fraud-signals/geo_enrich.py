"""Service-side geo enrichment for the agent detector.

The agent detector scores ``distance_from_registered_km`` when the caller
supplies it. Callers should not have to be trusted to measure their own
agents, so when the payload carries place names instead
(``registered_location`` + ``operating_location``) this layer computes the
distance itself:

  1. **Postgres mode** — through the platform's geo_distance_km() SQL
     function (full GeoNames gazetteer, PostGIS ST_Distance when the
     extension is present, SQL haversine otherwise).
  2. **embedded mode** — the 72-place seed gazetteer bundled below with a
     pure-Python haversine, used when the database is unreachable or its
     geo migrations have not been applied.

Honesty rules:
  * an explicit caller-supplied ``distance_from_registered_km`` always wins
    (never overwritten);
  * unknown places yield no distance and a ``geo_unresolved`` factor note —
    never a silent 0.0;
  * the enriched value is used for scoring only; the stored audit event
    keeps the caller's original payload.

The embedded gazetteer MUST match the seed in
database/20261026_postgis_geo.sql (parity pinned by tests).
"""
from __future__ import annotations

import logging
import math
import re
from typing import Any, Optional

log = logging.getLogger("fraud-signals.geo")

# Embedded gazetteer — MUST match the geo_gazetteer seed in
# database/20261026_postgis_geo.sql and the account-takeover detector's
# geo.py (parity pinned by tests).
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

_WS = re.compile(r"\s+")


def normalize_place(name: Any) -> str:
    """Match the DB-side geo_normalize_name(): lowercase, hyphens to
    spaces, whitespace collapsed."""
    return _WS.sub(" ", str(name).strip().lower().replace("-", " "))


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = (math.sin((lat2 - lat1) / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2)
    return 6371.0 * 2 * math.asin(math.sqrt(h))


def embedded_distance_km(origin: str, destination: str) -> Optional[float]:
    a = GAZETTEER.get(normalize_place(origin))
    b = GAZETTEER.get(normalize_place(destination))
    if a is None or b is None:
        return None
    return haversine_km(a, b)


def db_distance_km(store: Any, origin: str, destination: str) -> Optional[float]:
    """Distance via the platform geo_distance_km() SQL function.

    Raises when the database/function is unreachable — callers decide
    whether to fall back to the embedded gazetteer.
    """
    rows = store.query(
        "SELECT geo_distance_km(:a, :b) AS d", {"a": origin, "b": destination})
    if not rows:
        return None
    d = rows[0].get("d")
    return None if d is None else float(d)


def enrich_agent_distance(payload: dict[str, Any], store: Any) -> tuple[dict[str, Any], Optional[str]]:
    """Return (payload_for_scoring, note).

    The returned payload is a copy; the caller's dict is never mutated.
    ``note`` is a human-readable honesty note for a zero-weight factor when
    enrichment was impossible or degraded, else None.
    """
    if payload.get("distance_from_registered_km") is not None:
        return payload, None  # caller-supplied value always wins

    origin = payload.get("registered_location")
    destination = payload.get("operating_location") or payload.get("location")
    if not origin or not destination:
        return payload, None  # nothing to enrich from; detector skips honestly

    distance: Optional[float] = None
    note: Optional[str] = None
    if getattr(store, "_is_pg", False):
        try:
            distance = db_distance_km(store, str(origin), str(destination))
        except Exception as exc:  # noqa: BLE001
            log.warning("geo_distance_km unavailable, embedded fallback: %s", exc)
            note = f"geo database unavailable ({exc}); embedded gazetteer fallback"
    if distance is None:
        embedded = embedded_distance_km(str(origin), str(destination))
        if embedded is not None:
            distance = embedded
            note = note or "resolved via embedded gazetteer (72 places)"
    if distance is None:
        return payload, (f"geo_unresolved: {origin!r} or {destination!r} not in "
                         "the gazetteer — distance_from_registered_km not computed")

    enriched = dict(payload)
    enriched["distance_from_registered_km"] = round(distance, 1)
    return enriched, note
