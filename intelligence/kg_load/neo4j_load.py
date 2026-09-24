"""Load the KG store into Neo4j via Bolt (UNWIND $rows, MERGE).

Follows the ml/graph/neo4j_export.py contract: optional neo4j driver,
NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD env, clear non-crashy failure when the
driver or server is unavailable, idempotent MERGE.

Env:
  NEO4J_URI      bolt://localhost:7687 (default)
  NEO4J_USER     neo4j (default)
  NEO4J_PASSWORD password (default)
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict
from typing import Any

from .common import batches, read_store


def _driver():
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError:
        print("ERROR: neo4j python driver not installed. "
              "`pip install neo4j` (compose fragment: ml/graph/neo4j.compose.yml).",
              file=sys.stderr)
        sys.exit(2)
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    auth = (os.environ.get("NEO4J_USER", "neo4j"),
            os.environ.get("NEO4J_PASSWORD", "password"))
    try:
        d = GraphDatabase.driver(uri, auth=auth)
        d.verify_connectivity()
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: cannot connect to Neo4j at {uri}: {e}", file=sys.stderr)
        sys.exit(2)
    return d


def load(kg_dir: str) -> dict[str, Any]:
    import json

    from intelligence.kg_pipeline import schema

    d = _driver()
    entities, relations = read_store(kg_dir)

    by_label: dict[str, list[dict]] = defaultdict(list)
    for e in entities:
        if e["label"] in schema.ENTITY_TYPES:
            e = dict(e)
            e["props"] = json.loads(e["props"]) if e.get("props") else {}
            by_label[e["label"]].append(e)
    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in relations:
        if r["type"] in schema.REL_TYPES:
            r = dict(r)
            r["props"] = json.loads(r["props"]) if r.get("props") else {}
            r["count"] = int(r.get("count") or 1)
            by_type[r["type"]].append(r)

    stats: dict[str, Any] = {"backend": "neo4j", "entities": 0, "relations": 0}
    with d.session() as s:
        s.run("CREATE CONSTRAINT kg_entity_id IF NOT EXISTS "
              "FOR (n:KGEntity) REQUIRE n.id IS UNIQUE")
        for label, rows in by_label.items():
            for chunk in batches(rows):
                s.run(f"UNWIND $rows AS r MERGE (n:`{label}` {{id: r.id}}) "
                      "SET n += r.props, n.first_seen = r.first_seen, "
                      "n.last_seen = r.last_seen", rows=chunk)
                stats["entities"] += len(chunk)
        for rtype, rows in by_type.items():
            for chunk in batches(rows):
                s.run(f"UNWIND $rows AS r "
                      "MATCH (a {id: r.src_id}), (b {id: r.dst_id}) "
                      f"MERGE (a)-[e:`{rtype}`]->(b) "
                      "SET e += r.props, e.ts = r.ts, e.count = r.count",
                      rows=chunk)
                stats["relations"] += len(chunk)
    d.close()
    return stats
