"""Geospatial fraud analytics — reference implementations + Sedona jobs.

Two analytics over event coordinates (login_patterns / agent events):

  * **mule-ring geo clustering** — DBSCAN over event (lat, lon): mule
    rings physically co-locate (same campus, same estate). Clusters with
    >= min_samples distinct subjects are flagged for review.
  * **agent off-location rollup** — per agent, the share of events beyond
    the registered operating radius; sustained off-location activity is an
    agent-fraud indicator.

``reference.py`` (this module) is pure Python — correct on small extracts
and used in tests. ``sedona_jobs.py`` runs the same analytics at platform
scale on Apache Sedona/Spark and is honestly unavailable without them.
"""
from __future__ import annotations

import math
from typing import Iterable, Optional

Coord = tuple[float, float]


def haversine_km(a: Coord, b: Coord) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = (math.sin((lat2 - lat1) / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2)
    return 6371.0 * 2 * math.asin(math.sqrt(h))


def dbscan(points: list[Coord], eps_km: float, min_samples: int) -> list[int]:
    """Minimal DBSCAN over haversine km. Returns cluster labels per point
    (-1 = noise). Deterministic: points are visited in input order."""
    n = len(points)
    labels = [-1] * n
    visited = [False] * n
    cluster = 0

    def neighbors(i: int) -> list[int]:
        return [j for j in range(n) if haversine_km(points[i], points[j]) <= eps_km]

    for i in range(n):
        if visited[i]:
            continue
        visited[i] = True
        nbrs = neighbors(i)
        if len(nbrs) < min_samples:
            continue  # noise for now; may be claimed by a later cluster
        labels[i] = cluster
        seeds = [j for j in nbrs if j != i]
        while seeds:
            j = seeds.pop()
            if not visited[j]:
                visited[j] = True
                jn = neighbors(j)
                if len(jn) >= min_samples:
                    seeds.extend(k for k in jn if labels[k] == -1)
            if labels[j] == -1:
                labels[j] = cluster
        cluster += 1
    return labels


def mule_ring_geo_clusters(events: Iterable[dict], eps_km: float = 2.0,
                           min_samples: int = 5) -> dict:
    """Cluster event coordinates; flag clusters dense with DISTINCT subjects.

    events: dicts with subject_id, lat, lon (lat/lon None rows are honestly
    counted as unresolved, never placed)."""
    events = list(events)
    unresolved = sum(1 for e in events if e.get("lat") is None or e.get("lon") is None)
    placed = [e for e in events if e.get("lat") is not None and e.get("lon") is not None]
    points = [(float(e["lat"]), float(e["lon"])) for e in placed]
    labels = dbscan(points, eps_km, min_samples) if points else []
    clusters: dict[int, set[str]] = {}
    for label, event in zip(labels, placed):
        if label >= 0:
            clusters.setdefault(label, set()).add(str(event["subject_id"]))
    flagged = [
        {"cluster": c, "distinct_subjects": sorted(s), "subject_count": len(s)}
        for c, s in sorted(clusters.items()) if len(s) >= min_samples
    ]
    return {"clusters": flagged, "events_total": len(events),
            "events_placed": len(placed), "events_unresolved": unresolved,
            "eps_km": eps_km, "min_samples": min_samples}


def agent_offlocation_rollup(events: Iterable[dict],
                             registered: dict[str, Coord],
                             radius_km: float = 5.0) -> list[dict]:
    """Per-agent share of events outside the registered operating radius.

    events: dicts with agent_id, lat, lon. Agents with no registered
    location are honestly reported as unassessable, not zero."""
    by_agent: dict[str, list[dict]] = {}
    for e in events:
        by_agent.setdefault(str(e["agent_id"]), []).append(e)
    out = []
    for agent_id, rows in sorted(by_agent.items()):
        home = registered.get(agent_id)
        if home is None:
            out.append({"agent_id": agent_id, "assessable": False,
                        "reason": "no registered location"})
            continue
        placed = [r for r in rows if r.get("lat") is not None and r.get("lon") is not None]
        if not placed:
            out.append({"agent_id": agent_id, "assessable": False,
                        "reason": "no resolved events"})
            continue
        off = sum(1 for r in placed
                  if haversine_km((float(r["lat"]), float(r["lon"])), home) > radius_km)
        out.append({"agent_id": agent_id, "assessable": True,
                    "events": len(placed), "off_location": off,
                    "off_location_share": round(off / len(placed), 4)})
    return out
