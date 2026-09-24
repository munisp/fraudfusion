"""Train gnn_mule FROM Neo4j: load the account graph over Bolt, build the
same graph.npz contract as ml/data/synthetic_nigeria.build_graph (split-aware
windows), then delegate to ml/train/train_gnn.train.

Requires a reachable Neo4j (see ml/graph/neo4j.compose.yml) already populated
by ml/graph/neo4j_export.py. Fails with a clear error otherwise — never fakes
a run.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import build_graph  # noqa: E402


def load_from_neo4j() -> tuple[pd.DataFrame, pd.DataFrame]:
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError:
        print("ERROR: neo4j python driver not installed (`pip install neo4j`).",
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
    with d.session() as s:
        accts = pd.DataFrame([dict(r) for r in s.run(
            "MATCH (a:Account) RETURN a.customer_id AS customer_id, "
            "a.bank AS bank, a.age AS age, a.bureau_score AS bureau_score, "
            "a.monthly_income AS monthly_income, a.is_mule AS is_mule")])
        txns = pd.DataFrame([dict(r) for r in s.run(
            "MATCH (s:Account)-[:SENT]->(t:Transaction)-[:TO]->(d:Account) "
            "RETURN t.txn_id AS txn_id, s.customer_id AS sender_id, "
            "d.customer_id AS receiver_id, t.amount_ngn AS amount_ngn, "
            "t.ts AS ts")])
    d.close()
    if accts.empty or txns.empty:
        print("ERROR: Neo4j graph is empty; run ml/graph/neo4j_export.py first.",
              file=sys.stderr)
        sys.exit(2)
    txns["ts"] = pd.to_datetime(txns["ts"])
    return accts, txns


def main(version: str = "v2", epochs: int = 120, seed: int = 42) -> dict:
    from ml.train.train_gnn import train
    accts, txns = load_from_neo4j()
    t0, t1 = txns["ts"].min(), txns["ts"].max()
    cut_train = t0 + (t1 - t0) * 0.7
    cut_val = t0 + (t1 - t0) * 0.85
    X_tr, ei_tr, y = build_graph(txns, accts, cutoff=cut_train)
    X_va, ei_va, _ = build_graph(txns, accts, cutoff=cut_val)
    X_te, ei_te, _ = build_graph(txns, accts)
    out = Path(os.environ.get("FRAUDFUSION_DATA", "ml/data/generated"))
    out.mkdir(parents=True, exist_ok=True)
    np.savez(out / "graph.npz",
             X=X_te, edge_index=ei_te, y=y,
             X_train=X_tr, edge_index_train=ei_tr,
             X_val=X_va, edge_index_val=ei_va,
             X_test=X_te, edge_index_test=ei_te,
             cut_train_ts=str(cut_train), cut_val_ts=str(cut_val),
             train_mask=np.ones(len(accts), dtype=bool),
             val_mask=np.ones(len(accts), dtype=bool),
             test_mask=np.ones(len(accts), dtype=bool))
    print(f"graph.npz written from Neo4j -> {out}; training gnn_mule {version}")
    return train(epochs=epochs, version=version, seed=seed)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v2")
    ap.add_argument("--epochs", type=int, default=120)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    main(version=a.version, epochs=a.epochs, seed=a.seed)
