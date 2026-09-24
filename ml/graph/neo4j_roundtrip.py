"""Neo4j round-trip consistency check: export -> load -> graph contract.

Verifies that the graph stored in Neo4j round-trips to the SAME training
contract as the direct parquet path (ml/data/synthetic_nigeria.build_graph):

  1. export parquet -> Neo4j (neo4j_export.export, capped via --max-txns)
  2. load back over Bolt (neo4j_train.load_from_neo4j)
  3. build split-aware graph snapshots from the loaded frame
  4. assert node count / edge count / labels match the direct build

Runnable when a Neo4j server is present (ml/graph/neo4j.compose.yml);
``python -m ml.graph.neo4j_roundtrip --check-only`` (or the pytest helper
``roundtrip_or_skip``) exits/skips GRACEFULLY when no server is reachable —
a skipped check is reported, never a fake pass.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def neo4j_available() -> bool:
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError:
        return False
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    auth = (os.environ.get("NEO4J_USER", "neo4j"),
            os.environ.get("NEO4J_PASSWORD", "password"))
    try:
        d = GraphDatabase.driver(uri, auth=auth,
                                 connection_timeout=2, max_connection_lifetime=5)
        d.verify_connectivity()
        d.close()
        return True
    except Exception:  # noqa: BLE001
        return False


def roundtrip(data_dir: str, max_txns: int = 2000) -> dict:
    """Full export->load->build consistency check. Raises AssertionError on
    mismatch; SystemExit(2) if no server (loud, non-crashy)."""
    import numpy as np
    import pandas as pd

    if not neo4j_available():
        print("SKIP: no reachable Neo4j (set NEO4J_URI or start "
              "ml/graph/neo4j.compose.yml). Round-trip NOT executed.",
              file=sys.stderr)
        sys.exit(2)

    from ml.data.synthetic_nigeria import build_graph
    from ml.graph import neo4j_export, neo4j_train

    counts = neo4j_export.export(data_dir, max_txns=max_txns)
    accts_db, txns_db = neo4j_train.load_from_neo4j()

    # direct build on the SAME capped transaction set
    accts = pd.read_parquet(Path(data_dir) / "accounts.parquet")
    txns = pd.read_parquet(Path(data_dir) / "transactions.parquet").head(max_txns)

    assert len(accts_db) == len(accts), \
        f"account count mismatch: neo4j={len(accts_db)} parquet={len(accts)}"
    assert len(txns_db) == len(txns), \
        f"txn count mismatch: neo4j={len(txns_db)} parquet={len(txns)}"

    t0, t1 = txns["ts"].min(), txns["ts"].max()
    cut = t0 + (t1 - t0) * 0.7
    X_d, ei_d, y_d = build_graph(txns, accts, cutoff=cut)
    X_r, ei_r, y_r = build_graph(txns_db, accts_db, cutoff=cut)

    assert X_d.shape == X_r.shape, f"X shape {X_r.shape} != {X_d.shape}"
    assert ei_d.shape == ei_r.shape, f"edges {ei_r.shape} != {ei_d.shape}"
    assert np.array_equal(y_d, y_r), "labels differ after round-trip"
    assert np.allclose(X_d, X_r), "node features differ after round-trip"

    result = {"accounts": int(len(accts_db)), "transactions": int(len(txns_db)),
              "nodes": int(X_r.shape[0]), "edges_train_window": int(ei_r.shape[1]),
              "labels_match": True, "features_match": True,
              "neo4j_counts": counts}
    print(result)
    return result


def roundtrip_or_skip(data_dir: str, max_txns: int = 2000):
    """Pytest-friendly wrapper: pytest.skip if no server, else run."""
    import pytest
    if not neo4j_available():
        pytest.skip("no reachable Neo4j server (graceful skip, not a pass)")
    return roundtrip(data_dir, max_txns)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=os.environ.get(
        "FRAUDFUSION_DATA", "ml/data/generated"))
    ap.add_argument("--max-txns", type=int, default=2000)
    ap.add_argument("--check-only", action="store_true",
                    help="only report whether a server is reachable")
    a = ap.parse_args()
    if a.check_only:
        ok = neo4j_available()
        print({"neo4j_available": ok})
        sys.exit(0 if ok else 2)
    roundtrip(a.data_dir, a.max_txns)
