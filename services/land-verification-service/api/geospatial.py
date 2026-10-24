"""Geospatial parcel-integrity primitives (Round 13, features 1 & 2).

Problem: exact-match conflict detection (certificate number, survey-plan
hash) is trivially evaded — a fraudster re-surveys the same physical plot
under a NEW plan number and registers it as a different parcel. The fix is
to compare the ground itself:

  * ``polygons_overlap`` — exact detection for beacon polygons: bounding-box
    pre-filter, then vertex-in-polygon OR edge-intersection. Any true → the
    parcels share land.
  * ``geohash`` / ``centroid_geohash`` — standard geohash of the parcel
    centroid. Fraudulent re-surveys rarely move the boundary far; a shared
    geohash prefix (default 6 chars ≈ ±0.61km at the equator, tighter in
    latitude) flags near-coincident parcels for review even when polygons
    don't quite touch.

Beacon text format accepted: "6.45N 3.40E, 6.46N 3.41E, ..." (the format
already used in verification fixtures) or JSON [[lat, lon], ...].
Pure python, no dependencies, deterministic.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

Coord = tuple[float, float]  # (lat, lon)

_GEOHASH_ALPHABET = "0123456789bcdefghjkmnpqrstuvwxyz"


def parse_beacons(text: Any) -> list[Coord]:
    """Parse beacon text/JSON into [(lat, lon), ...]. Tolerant: returns []
    on anything unparseable (never raises)."""
    if not text:
        return []
    if isinstance(text, (list, tuple)):
        out = []
        for item in text:
            try:
                lat, lon = float(item[0]), float(item[1])
                out.append((lat, lon))
            except (TypeError, ValueError, IndexError):
                return []
        return out
    s = str(text).strip()
    if s.startswith("["):
        try:
            return parse_beacons(json.loads(s))
        except (ValueError, TypeError):
            return []
    coords: list[Coord] = []
    for m in re.finditer(
            r"(\d+(?:\.\d+)?)\s*([NSns])\s*[,;]?\s*(\d+(?:\.\d+)?)\s*([EWew])", s):
        lat = float(m.group(1)) * (1 if m.group(2).upper() == "N" else -1)
        lon = float(m.group(3)) * (1 if m.group(4).upper() == "E" else -1)
        coords.append((lat, lon))
    return coords


def centroid(poly: list[Coord]) -> Coord:
    if not poly:
        return (0.0, 0.0)
    return (sum(c[0] for c in poly) / len(poly), sum(c[1] for c in poly) / len(poly))


def _bbox(poly: list[Coord]) -> tuple[float, float, float, float]:
    lats = [c[0] for c in poly]
    lons = [c[1] for c in poly]
    return (min(lats), min(lons), max(lats), max(lons))


def _bbox_overlap(a, b) -> bool:
    return not (a[2] < b[0] or b[2] < a[0] or a[3] < b[1] or b[3] < a[1])


def _point_in_polygon(pt: Coord, poly: list[Coord]) -> bool:
    """Ray-casting on (lat, lon) treated as planar (fine at parcel scale)."""
    x, y = pt
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / ((yj - yi) or 1e-12) + xi:
            inside = not inside
        j = i
    return inside


def _segments_intersect(p1: Coord, p2: Coord, p3: Coord, p4: Coord) -> bool:
    def orient(a, b, c):
        return (b[1] - a[1]) * (c[0] - a[0]) - (b[0] - a[0]) * (c[1] - a[1])

    d1 = orient(p3, p4, p1)
    d2 = orient(p3, p4, p2)
    d3 = orient(p1, p2, p3)
    d4 = orient(p1, p2, p4)
    return ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0))


def polygons_overlap(a: list[Coord], b: list[Coord]) -> bool:
    """True iff two beacon polygons share any land (vertex containment or
    edge intersection), with a bounding-box pre-filter."""
    if len(a) < 3 or len(b) < 3:
        return False
    if not _bbox_overlap(_bbox(a), _bbox(b)):
        return False
    if any(_point_in_polygon(p, b) for p in a):
        return True
    if any(_point_in_polygon(p, a) for p in b):
        return True
    na, nb = len(a), len(b)
    for i in range(na):
        for j in range(nb):
            if _segments_intersect(a[i], a[(i + 1) % na], b[j], b[(j + 1) % nb]):
                return True
    return False


def geohash(lat: float, lon: float, precision: int = 6) -> str:
    """Standard geohash encoding."""
    lat_rng, lon_rng = [-90.0, 90.0], [-180.0, 180.0]
    bits = []
    even = True
    while len(bits) < precision * 5:
        if even:
            mid = (lon_rng[0] + lon_rng[1]) / 2
            if lon >= mid:
                bits.append(1)
                lon_rng[0] = mid
            else:
                bits.append(0)
                lon_rng[1] = mid
        else:
            mid = (lat_rng[0] + lat_rng[1]) / 2
            if lat >= mid:
                bits.append(1)
                lat_rng[0] = mid
            else:
                bits.append(0)
                lat_rng[1] = mid
        even = not even
    out = []
    for i in range(0, len(bits), 5):
        chunk = bits[i:i + 5]
        out.append(_GEOHASH_ALPHABET[int("".join(map(str, chunk)), 2)])
    return "".join(out)


def centroid_geohash(poly: list[Coord], precision: int = 6) -> Optional[str]:
    if len(poly) < 1:
        return None
    lat, lon = centroid(poly)
    return geohash(lat, lon, precision)
