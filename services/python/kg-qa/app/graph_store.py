"""Graph store abstraction with graceful degradation.

Resolution order (get_store):
  1. FalkorDB  — if FALKORDB_URL set and reachable (falkordb or redis-py client)
  2. Neo4j     — if NEO4J_URI set and reachable (neo4j driver)
  3. In-memory — built from the parquet KG store at KG_DIR (always available
                 after a pipeline run; this is the fallback mode and is also
                 what tests exercise)
  4. Empty in-memory store — service still answers honestly ("no data")

Interface:
  stats()                    -> {"entities": int, "relations": int}
  get_entities(ids)          -> {id: {"label":..., "props": {...}, ...}}
  search_aliases()           -> iterable of (alias_text, entity_id) for linking
  neighbors(entity_id)       -> list of {"src","dst","type","ts","count"}
                                covering both directions
"""
from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
from typing import Any, Iterable, Protocol

log = logging.getLogger("kg-qa.graph_store")

DEFAULT_KG_DIR = os.environ.get("KG_DIR", "intelligence/data/kg")


class GraphStore(Protocol):
    mode: str

    def stats(self) -> dict[str, int]: ...
    def get_entities(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]: ...
    def search_aliases(self) -> list[tuple[str, str]]: ...
    def neighbors(self, entity_id: str) -> list[dict[str, Any]]: ...


# --- in-memory fallback ------------------------------------------------------

class InMemoryGraphStore:
    """Full KG in memory from the parquet store. Fallback + dev/test mode."""

    mode = "in-memory-parquet"

    def __init__(self, kg_dir: str | Path):
        self.kg_dir = Path(kg_dir)
        self.entities: dict[str, dict[str, Any]] = {}
        self.adj: dict[str, list[dict[str, Any]]] = {}
        self.reload()

    def reload(self) -> None:
        import pandas as pd
        self.entities.clear()
        self.adj.clear()
        e_file = self.kg_dir / "entities.parquet"
        r_file = self.kg_dir / "relations.parquet"
        if e_file.exists():
            for r in pd.read_parquet(e_file).to_dict("records"):
                props = {}
                if r.get("props"):
                    try:
                        props = json.loads(r["props"])
                    except (TypeError, json.JSONDecodeError):
                        props = {}
                self.entities[r["id"]] = {
                    "id": r["id"], "label": r.get("label"), "props": props,
                    "first_seen": _clean(r.get("first_seen")),
                    "last_seen": _clean(r.get("last_seen")),
                }
        if r_file.exists():
            for r in pd.read_parquet(r_file).to_dict("records"):
                edge = {"src": r["src_id"], "dst": r["dst_id"], "type": r["type"],
                        "ts": _clean(r.get("ts")), "count": int(r.get("count") or 1)}
                self.adj.setdefault(edge["src"], []).append(edge)
                self.adj.setdefault(edge["dst"], []).append(edge)

    def stats(self) -> dict[str, int]:
        n_rel = sum(len(v) for v in self.adj.values()) // 2 if self.adj else 0
        return {"entities": len(self.entities), "relations": n_rel}

    def get_entities(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        return {i: self.entities[i] for i in ids if i in self.entities}

    def search_aliases(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for eid, e in self.entities.items():
            out.append((eid, eid))
            for v in e.get("props", {}).values():
                if isinstance(v, str) and len(v) >= 3:
                    out.append((v, eid))
        return out

    def neighbors(self, entity_id: str) -> list[dict[str, Any]]:
        return list(self.adj.get(entity_id, []))


def _clean(v: Any) -> Any:
    if isinstance(v, float) and math.isnan(v):
        return None
    return v


# --- FalkorDB ----------------------------------------------------------------

class FalkorDBGraphStore:
    mode = "falkordb"

    def __init__(self, url: str, graph: str):
        from intelligence.kg_load.falkordb_load import _query_fn  # reuse client selection
        self._query, self._close, self._backend = _query_fn()
        self.graph = graph
        # connectivity check (honest failure -> caller falls back)
        self._query("RETURN 1")

    def stats(self) -> dict[str, int]:
        res = self._query("MATCH (n) RETURN count(n)")
        n = _scalar(res)
        res2 = self._query("MATCH ()-[e]->() RETURN count(e)")
        return {"entities": int(n or 0), "relations": int(_scalar(res2) or 0)}

    def get_entities(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        ids = list(ids)
        if not ids:
            return {}
        id_list = ", ".join("'%s'" % i.replace("'", "\\'") for i in ids)
        res = self._query(
            f"MATCH (n) WHERE n.id IN [{id_list}] "
            "RETURN n.id, labels(n), properties(n)")
        out = {}
        for row in _rows(res):
            eid, labels, props = row[0], row[1], row[2] or {}
            out[eid] = {"id": eid, "label": labels[0] if labels else None,
                        "props": {k: v for k, v in props.items()
                                  if k not in ("id", "first_seen", "last_seen")},
                        "first_seen": props.get("first_seen"),
                        "last_seen": props.get("last_seen")}
        return out

    def search_aliases(self) -> list[tuple[str, str]]:
        res = self._query("MATCH (n) RETURN n.id, properties(n) LIMIT 50000")
        out: list[tuple[str, str]] = []
        for row in _rows(res):
            eid, props = row[0], row[1] or {}
            out.append((eid, eid))
            for v in props.values():
                if isinstance(v, str) and len(v) >= 3:
                    out.append((v, eid))
        return out

    def neighbors(self, entity_id: str) -> list[dict[str, Any]]:
        eid = entity_id.replace("'", "\\'")
        res = self._query(
            f"MATCH (a {{id: '{eid}'}})-[e]-(b) "
            "RETURN a.id, b.id, type(e), e.ts, e.count, "
            "CASE WHEN startNode(e) = a THEN 'out' ELSE 'in' END")
        edges = []
        for row in _rows(res):
            a, b, rtype, ts, count, direction = row
            edges.append({"src": a if direction == "out" else b,
                          "dst": b if direction == "out" else a,
                          "type": rtype, "ts": ts, "count": int(count or 1)})
        return edges


def _rows(res: Any) -> list:
    """Normalize GRAPH.QUERY result shapes across falkordb-py and redis-py."""
    if hasattr(res, "result_set"):   # falkordb-py / redis-graph style
        return list(res.result_set)
    if isinstance(res, list) and len(res) >= 2 and isinstance(res[1], list):
        return res[1]                # raw redis-py GRAPH.QUERY reply
    return []


def _scalar(res: Any) -> Any:
    rows = _rows(res)
    return rows[0][0] if rows and rows[0] else None


# --- Neo4j -------------------------------------------------------------------

class Neo4jGraphStore:
    mode = "neo4j"

    def __init__(self, uri: str, user: str, password: str):
        from neo4j import GraphDatabase  # type: ignore
        self._d = GraphDatabase.driver(uri, auth=(user, password))
        self._d.verify_connectivity()

    def stats(self) -> dict[str, int]:
        with self._d.session() as s:
            n = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            m = s.run("MATCH ()-[e]->() RETURN count(e) AS c").single()["c"]
        return {"entities": n, "relations": m}

    def get_entities(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        ids = list(ids)
        if not ids:
            return {}
        with self._d.session() as s:
            res = s.run("MATCH (n) WHERE n.id IN $ids "
                        "RETURN n.id AS id, labels(n) AS labels, properties(n) AS props",
                        ids=ids)
            out = {}
            for rec in res:
                props = dict(rec["props"] or {})
                out[rec["id"]] = {
                    "id": rec["id"],
                    "label": rec["labels"][0] if rec["labels"] else None,
                    "props": {k: v for k, v in props.items()
                              if k not in ("id", "first_seen", "last_seen")},
                    "first_seen": props.get("first_seen"),
                    "last_seen": props.get("last_seen")}
            return out

    def search_aliases(self) -> list[tuple[str, str]]:
        with self._d.session() as s:
            res = s.run("MATCH (n) RETURN n.id AS id, properties(n) AS props LIMIT 50000")
            out: list[tuple[str, str]] = []
            for rec in res:
                eid, props = rec["id"], dict(rec["props"] or {})
                out.append((eid, eid))
                for v in props.values():
                    if isinstance(v, str) and len(v) >= 3:
                        out.append((v, eid))
            return out

    def neighbors(self, entity_id: str) -> list[dict[str, Any]]:
        with self._d.session() as s:
            res = s.run(
                "MATCH (a {id: $id})-[e]-(b) "
                "RETURN a.id AS a, b.id AS b, type(e) AS t, e.ts AS ts, "
                "e.count AS count, startNode(e) = a AS outgoing",
                id=entity_id)
            edges = []
            for rec in res:
                edges.append({"src": rec["a"] if rec["outgoing"] else rec["b"],
                              "dst": rec["b"] if rec["outgoing"] else rec["a"],
                              "type": rec["t"], "ts": rec["ts"],
                              "count": int(rec["count"] or 1)})
            return edges


# --- resolution ---------------------------------------------------------------

def get_store(kg_dir: str | Path | None = None) -> GraphStore:
    """Resolve the best available graph store, degrading gracefully."""
    kg_dir = kg_dir or DEFAULT_KG_DIR
    falkor_url = os.environ.get("FALKORDB_URL")
    if falkor_url:
        try:
            return FalkorDBGraphStore(falkor_url,
                                      os.environ.get("FALKORDB_GRAPH", "fraudfusion-kg"))
        except Exception as e:  # noqa: BLE001
            log.warning("FalkorDB at %s unavailable (%s); trying next backend", falkor_url, e)
    neo4j_uri = os.environ.get("NEO4J_URI")
    if neo4j_uri:
        try:
            return Neo4jGraphStore(neo4j_uri,
                                   os.environ.get("NEO4J_USER", "neo4j"),
                                   os.environ.get("NEO4J_PASSWORD", "password"))
        except Exception as e:  # noqa: BLE001
            log.warning("Neo4j at %s unavailable (%s); falling back to parquet", neo4j_uri, e)
    store = InMemoryGraphStore(kg_dir)
    if not store.entities:
        log.warning("no KG store found at %s; serving an empty graph honestly", kg_dir)
    return store
