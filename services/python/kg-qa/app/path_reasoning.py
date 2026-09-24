"""Path reasoning: bounded BFS between linked entities + path scoring.

EPR-KGQA style: entities linked from the question anchor the search; we
enumerate simple paths up to max_hops over the relation graph, score them by
relation evidentiary weight (schema.REL_WEIGHTS) and recency (exponential
decay on the edge timestamp, half-life ~6 months), and keep the top-k.

Two modes:
  * >=2 linked entities: connecting paths between any pair
  * 1 linked entity:     context paths radiating from it (what is connected
                         to this entity and how)
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from .graph_store import GraphStore

RECENCY_HALF_LIFE_DAYS = 180.0
DEFAULT_WEIGHT = 0.35


def _rel_weights() -> dict[str, float]:
    try:
        from intelligence.kg_pipeline.schema import REL_WEIGHTS
        return REL_WEIGHTS
    except ImportError:  # service deployed without the pipeline package
        return {}


def _recency(ts: str | None, now: datetime | None = None) -> float:
    if not ts:
        return 0.5
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return 0.5
    now = now or datetime.now(timezone.utc)
    age_days = max(0.0, (now - dt).total_seconds() / 86400.0)
    return math.exp(-math.log(2) * age_days / RECENCY_HALF_LIFE_DAYS)


def edge_score(edge: dict[str, Any], now: datetime | None = None) -> float:
    w = _rel_weights().get(edge.get("type"), DEFAULT_WEIGHT)
    return w * _recency(edge.get("ts"), now)


def path_score(hops: list[dict[str, Any]], now: datetime | None = None) -> float:
    if not hops:
        return 0.0
    # mean of edge scores, lightly penalized by path length
    s = sum(edge_score(h, now) for h in hops) / len(hops)
    return round(s * (1.0 / (1.0 + 0.1 * (len(hops) - 1))), 6)


def enumerate_paths(store: GraphStore, linked_ids: list[str],
                    max_hops: int = 3, max_paths: int = 5) -> list[dict[str, Any]]:
    """BFS simple paths between linked entities (or context paths for one)."""
    now = datetime.now(timezone.utc)
    targets = set(linked_ids)
    found: list[list[dict[str, Any]]] = []

    if len(linked_ids) >= 2:
        for start in linked_ids:
            _bfs(store, start, targets - {start}, max_hops, found)
    elif len(linked_ids) == 1:
        _bfs(store, linked_ids[0], None, max_hops, found)
    if not found:
        return []
    scored = [{"score": path_score(p, now), "hops": p} for p in found]
    scored.sort(key=lambda x: -x["score"])
    # dedupe identical hop sequences that can arise from symmetric edges
    seen: set[tuple] = set()
    out = []
    for item in scored:
        key = tuple((h["src"], h["type"], h["dst"]) for h in item["hops"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= max_paths:
            break
    return out


def _bfs(store: GraphStore, start: str, targets: set[str] | None,
         max_hops: int, found: list[list[dict[str, Any]]],
         cap: int = 500) -> None:
    """BFS over simple paths from start. When targets is None, every
    frontier path (length >= 1) is collected as a context path."""
    queue: list[tuple[str, list[dict[str, Any]], set[str]]] = [(start, [], {start})]
    while queue and len(found) < cap:
        node, path, visited = queue.pop(0)
        if len(path) >= max_hops:
            continue
        for edge in store.neighbors(node):
            # orient the edge from the perspective of the current node
            if edge["src"] == node:
                nxt, hop = edge["dst"], edge
            else:
                nxt = edge["src"]
                hop = {"src": edge["src"], "dst": edge["dst"], "type": edge["type"],
                       "ts": edge.get("ts"), "count": edge.get("count", 1)}
            if nxt in visited:
                continue
            new_path = path + [hop]
            if targets is None:
                found.append(new_path)          # context path
            elif nxt in targets:
                found.append(new_path)          # connecting path
            queue.append((nxt, new_path, visited | {nxt}))
