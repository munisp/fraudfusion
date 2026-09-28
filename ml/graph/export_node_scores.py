"""Regenerate gnn_mule node_scores.csv from the graph snapshot.

Runs gnn_mule inference over the full-window (test) graph snapshot
(``ml/data/generated/graph.npz`` keys ``X_test``/``edge_index_test``) and
writes per-node mule probabilities beside the model artifact:

    ml/artifacts/gnn_mule/<version>/node_scores.csv

Columns (order matters for the consumer):

    account_ref,mule_score,node_id,artifact_version

``account_ref`` is the account's customer_id (graph node i == row i of
accounts.parquet, per ml/data/synthetic_nigeria.build_graph's id2i mapping).

NOTE on column order: the insider collusion-graph endpoint
(services/go/insider-fraud-detector/insider_sod.go probeGNNArtifact) parses
this CSV positionally as (id, score, ...). Leading with
``account_ref,mule_score`` keeps that endpoint functional while carrying all
four contract fields; the header row is skipped by its float-parse guard.

Usage:
    python -m ml.graph.export_node_scores [--version v2] [--data-dir ...]
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.train.common import ARTIFACT_ROOT  # noqa: E402

DEFAULT_DATA_DIR = Path(os.environ.get(
    "FRAUDFUSION_DATA",
    Path(__file__).resolve().parents[1] / "data" / "generated"))


def export_node_scores(version: str = "v2",
                       data_dir: Path = DEFAULT_DATA_DIR,
                       out_path: Path | None = None) -> Path:
    import pandas as pd
    import torch
    from ml.models.gnn_mule import MuleGNN, load_state_dict_portable

    art = ARTIFACT_ROOT / "gnn_mule" / version
    out_path = out_path or art / "node_scores.csv"

    g = np.load(data_dir / "graph.npz")
    key = "X_test" if "X_test" in g else "X"
    ei_key = "edge_index_test" if "edge_index_test" in g else "edge_index"
    X_raw, ei = g[key], g[ei_key]

    prep = np.load(art / "preprocess.npz")
    mean, std = prep["scaler_mean"], prep["scaler_std"]
    model = MuleGNN(int(mean.shape[0]), use_pyg=False)
    load_state_dict_portable(model, art / "weights.pt")
    model.eval()
    with torch.no_grad():
        probs = model.prob(
            torch.from_numpy(((X_raw - mean) / std).astype(np.float32)),
            torch.from_numpy(ei)).numpy().astype(np.float64)

    accts = pd.read_parquet(data_dir / "accounts.parquet")
    customer_ids = accts["customer_id"].astype(str).tolist()
    if len(customer_ids) != len(probs):
        raise ValueError(
            f"node/account count mismatch: {len(probs)} graph nodes vs "
            f"{len(customer_ids)} accounts rows")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["account_ref", "mule_score", "node_id",
                    "artifact_version"])
        for i, (cid, p) in enumerate(zip(customer_ids, probs)):
            w.writerow([cid, f"{p:.6f}", i, f"gnn_mule/{version}"])
    tmp.replace(out_path)  # atomic publish beside the artifact
    print(f"wrote {out_path} ({len(probs)} nodes, "
          f"mean mule_score={probs.mean():.4f}, "
          f"max={probs.max():.4f})")
    return out_path


def main(argv=None) -> Path:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default="v2")
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    return export_node_scores(args.version, args.data_dir, args.out)


if __name__ == "__main__":
    main()
