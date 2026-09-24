"""Load the KG store into FalkorDB (Redis-graph protocol, openCypher).

Idempotent: entities MERGE on id; relations MERGE on (src,dst,type) and
carry the pipeline-computed absolute `count` (SET, not +=), so reloading
the same store never double-counts.

Client selection (in order):
  1. `falkordb` package (official FalkorDB python client)
  2. `redis` package, raw GRAPH.QUERY commands
Neither installed -> clear RuntimeError (nothing faked).

Env:
  FALKORDB_URL   redis://[:password@]host:port (default redis://localhost:6379)
  FALKORDB_GRAPH graph name (default fraudfusion-kg)
"""
from __future__ import annotations

import os
from typing import Any, Callable
from urllib.parse import urlparse

from .common import batches, cypher_str, props_literal, read_store

QUERY_TIMEOUT_MS = 60000


def _parse_url(url: str) -> tuple[str, int, str | None]:
    p = urlparse(url)
    return p.hostname or "localhost", p.port or 6379, p.password


def _query_fn() -> tuple[Callable[[str], Any], Callable[[], None], str]:
    """Return (query, close, backend_name) for whichever client exists."""
    url = os.environ.get("FALKORDB_URL", "redis://localhost:6379")
    graph = os.environ.get("FALKORDB_GRAPH", "fraudfusion-kg")
    host, port, password = _parse_url(url)
    try:
        from falkordb import FalkorDB  # type: ignore
        db = FalkorDB(host=host, port=port, password=password)
        g = db.select_graph(graph)
        return (lambda q: g.query(q)), db.close, "falkordb-py"
    except ImportError:
        pass
    try:
        import redis  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "FalkorDB target requested but neither `falkordb` nor `redis` "
            "python packages are installed. `pip install falkordb` (preferred) "
            "or `pip install redis`.") from e
    r = redis.Redis(host=host, port=port, password=password, decode_responses=True)
    try:
        r.ping()
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"cannot reach FalkorDB at {url}: {e}") from e

    def query(q: str) -> Any:
        return r.execute_command("GRAPH.QUERY", graph, q, "--timeout", QUERY_TIMEOUT_MS)

    return query, r.close, "redis-py-GRAPH.QUERY"


def _entity_query(label: str, rows: list[dict[str, Any]]) -> str:
    items = []
    for r in rows:
        items.append("{id: %s, props: %s, first_seen: %s, last_seen: %s}" % (
            cypher_str(r["id"]), props_literal(r.get("props")),
            cypher_str(r.get("first_seen")), cypher_str(r.get("last_seen"))))
    return (
        f"UNWIND [{', '.join(items)}] AS r "
        f"MERGE (n:`{label}` {{id: r.id}}) "
        f"SET n += r.props, n.first_seen = r.first_seen, n.last_seen = r.last_seen")


def _relation_query(rtype: str, rows: list[dict[str, Any]]) -> str:
    items = []
    for r in rows:
        items.append("{src: %s, dst: %s, props: %s, ts: %s, count: %d}" % (
            cypher_str(r["src_id"]), cypher_str(r["dst_id"]),
            props_literal(r.get("props")), cypher_str(r.get("ts")),
            int(r.get("count") or 1)))
    return (
        f"UNWIND [{', '.join(items)}] AS r "
        f"MATCH (a {{id: r.src}}), (b {{id: r.dst}}) "
        f"MERGE (a)-[e:`{rtype}`]->(b) "
        f"SET e += r.props, e.ts = r.ts, e.count = r.count")


def load(kg_dir: str, graph: str | None = None) -> dict[str, Any]:
    from collections import defaultdict
    from intelligence.kg_pipeline import schema

    query, close, backend = _query_fn()
    if graph:  # pragma: no cover - graph name is baked into the client
        os.environ["FALKORDB_GRAPH"] = graph
    entities, relations = read_store(kg_dir)

    stats: dict[str, Any] = {"backend": backend, "entities": 0, "relations": 0}
    by_label: dict[str, list[dict]] = defaultdict(list)
    for e in entities:
        label = e["label"] if e["label"] in schema.ENTITY_TYPES else None
        if label is None:
            continue
        by_label[label].append(e)
    for label, rows in by_label.items():
        for chunk in batches(rows):
            query(_entity_query(label, chunk))
            stats["entities"] += len(chunk)

    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in relations:
        if r["type"] in schema.REL_TYPES:
            by_type[r["type"]].append(r)
    for rtype, rows in by_type.items():
        for chunk in batches(rows):
            query(_relation_query(rtype, chunk))
            stats["relations"] += len(chunk)
    close()
    return stats
