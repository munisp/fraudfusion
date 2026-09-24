"""Train MuleGNN (GraphSAGE) on the synthetic transaction graph.

Leakage-free protocol (v2): the graph artifact carries split-aware snapshots
(ml/data/synthetic_nigeria.build_graph with cutoff). The model is trained on
the TRAIN-window graph only (edges + node features aggregated from train
transactions), early-stopped on the VAL-window graph, and evaluated on the
full-window TEST graph. The feature scaler is fit on train-window features of
train-mask nodes and shipped as preprocess.npz so inference is self-contained.

Default backend is the pure-PyTorch SAGELayer so weights.pt loads without
torch_geometric (see gnn_mule.load_state_dict_portable for PyG checkpoints).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.models.gnn_mule import MuleGNN, backend_name
from ml.train.common import (ARTIFACT_ROOT, DATA_DIR, EarlyStopper,
                             metrics_dict, model_card, save_artifacts,
                             set_seed)


def _graph(g, prefix: str):
    """Return (X, edge_index) for a split prefix, with v1 fallback."""
    key = f"X_{prefix}"
    if key in g:
        return g[key], g[f"edge_index_{prefix}"]
    return g["X"], g["edge_index"]  # v1 single-graph artifact


def train(epochs: int = 120, lr: float = 5e-3, patience: int = 20,
          seed: int = 42, version: str = "v2", use_pyg: bool = False) -> dict:
    set_seed(seed)
    g = np.load(DATA_DIR / "graph.npz")
    X_tr_raw, ei_tr = _graph(g, "train")
    X_va_raw, ei_va = _graph(g, "val")
    X_te_raw, ei_te = _graph(g, "test")
    y = torch.from_numpy(g["y"].astype(np.float32))
    # Node-level label split: every account is active in the train window
    # (dense synthetic graph), so temporal masks alone cannot hold out labels.
    # Hold out 15/15% of NODES from the loss entirely; message passing may use
    # their features, but their labels are never seen (transductive protocol).
    n_nodes = len(y)
    perm = np.random.default_rng(seed).permutation(n_nodes)
    n_tr = int(0.7 * n_nodes)
    n_va = int(0.15 * n_nodes)
    tr = torch.zeros(n_nodes, dtype=torch.bool); tr[perm[:n_tr]] = True
    va = torch.zeros(n_nodes, dtype=torch.bool); va[perm[n_tr:n_tr + n_va]] = True
    te = torch.zeros(n_nodes, dtype=torch.bool); te[perm[n_tr + n_va:]] = True

    # scaler fit on train-window features of train nodes only (no leakage)
    mu = X_tr_raw[tr.numpy()].mean(0)
    sd = X_tr_raw[tr.numpy()].std(0) + 1e-6
    X_tr = torch.from_numpy((X_tr_raw - mu) / sd)
    X_va = torch.from_numpy((X_va_raw - mu) / sd)
    X_te = torch.from_numpy((X_te_raw - mu) / sd)
    ei_tr, ei_va, ei_te = map(torch.from_numpy, (ei_tr, ei_va, ei_te))

    model = MuleGNN(X_tr.size(1), use_pyg=use_pyg)
    pos_w = torch.tensor([(y[tr] == 0).sum() / (y[tr] == 1).sum().clamp(min=1)])
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, factor=0.5, patience=5)
    stop = EarlyStopper(patience=patience)

    for epoch in range(epochs):
        model.train()
        opt.zero_grad()
        logits = model(X_tr, ei_tr)  # train-window graph only
        loss = F.binary_cross_entropy_with_logits(logits[tr], y[tr],
                                                  pos_weight=pos_w)
        loss.backward()
        opt.step()
        model.eval()
        with torch.no_grad():
            p = model.prob(X_va, ei_va)  # val-window graph
        ap = average_precision_score(y[va].numpy(), p[va].numpy())
        sched.step(1 - ap)
        if epoch % 10 == 0:
            print(f"epoch {epoch:03d} loss={loss.item():.4f} val_auc_pr={ap:.4f}")
        if stop.step(ap, model):
            print(f"early stop at epoch {epoch}")
            break
    model.load_state_dict(stop.best_state)
    model.eval()
    with torch.no_grad():
        p_te = model.prob(X_te, ei_te)[te].numpy()  # full-window graph
    m = metrics_dict(y[te].numpy(), p_te)
    m.update(backend=backend_name() if use_pyg else "pure-torch SAGELayer",
             epochs_trained=epoch + 1, seed=seed,
             n_nodes=int(X_tr.size(0)), n_edges_train=int(ei_tr.size(1)),
             n_edges_test=int(ei_te.size(1)),
             mule_prevalence=float(y[te].mean()),
             n_train_nodes=int(tr.sum()), n_test_nodes=int(te.sum()),
             leakage_fix=("split-aware graph snapshots (edges+features masked "
                          "by split cutoff) + node-level label holdout 70/15/15 "
                          "+ scaler fit on train-window train nodes only"))
    print(json.dumps(m, indent=2))

    dest = save_artifacts("gnn_mule", version, model, m, {
        "MODEL_CARD.md": model_card(
            "gnn_mule", version, m,
            "synthetic_nigeria account-transaction graph (split-aware snapshots)",
            notes=("Backend: pure-torch SAGELayer (weights.pt loads WITHOUT "
                   "torch_geometric). Trained on train-window graph only; "
                   "scaler in preprocess.npz applied at inference.")),
    })
    np.savez(dest / "preprocess.npz", scaler_mean=mu, scaler_std=sd,
             feature_names=np.array([
                 "log_in_amount", "log_out_amount", "log_in_count",
                 "log_out_count", "log_unique_senders", "log_unique_receivers",
                 "bureau_score_scaled", "age_scaled", "bank_code_scaled",
                 "log_monthly_income"]))
    # TorchScript export (ragged graph inputs do not map to plain ONNX CPU ops)
    try:
        scripted = torch.jit.script(model)
        scripted.save(str(dest / "model.jit.pt"))
        print("torchscript export -> model.jit.pt")
    except Exception as e:  # noqa: BLE001
        print(f"torchscript export failed ({e}); weights.pt still usable")
    print(f"saved -> {dest}")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=120)
    ap.add_argument("--version", default="v2")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--use-pyg", action="store_true")
    a = ap.parse_args()
    train(epochs=a.epochs, version=a.version, seed=a.seed, use_pyg=a.use_pyg)
