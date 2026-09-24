"""Train MuleGNN (GraphSAGE) on the synthetic transaction graph."""
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
from ml.train.common import (DATA_DIR, EarlyStopper, metrics_dict, model_card,
                             save_artifacts, set_seed)


def train(epochs: int = 120, lr: float = 5e-3, patience: int = 20,
          seed: int = 42, version: str = "v1") -> dict:
    set_seed(seed)
    g = np.load(DATA_DIR / "graph.npz")
    X = torch.from_numpy(g["X"])
    X = (X - X.mean(0)) / (X.std(0) + 1e-6)
    ei = torch.from_numpy(g["edge_index"])
    y = torch.from_numpy(g["y"].astype(np.float32))
    tr = torch.from_numpy(g["train_mask"])
    va = torch.from_numpy(g["val_mask"])
    te = torch.from_numpy(g["test_mask"])

    model = MuleGNN(X.size(1))
    pos_w = torch.tensor([(y[tr] == 0).sum() / (y[tr] == 1).sum().clamp(min=1)])
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, factor=0.5, patience=5)
    stop = EarlyStopper(patience=patience)

    for epoch in range(epochs):
        model.train()
        opt.zero_grad()
        logits = model(X, ei)
        loss = F.binary_cross_entropy_with_logits(logits[tr], y[tr],
                                                  pos_weight=pos_w)
        loss.backward()
        opt.step()
        model.eval()
        with torch.no_grad():
            p = model.prob(X, ei)
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
        p_te = model.prob(X, ei)[te].numpy()
    m = metrics_dict(y[te].numpy(), p_te)
    m.update(backend=backend_name(), epochs_trained=epoch + 1, seed=seed,
             n_nodes=int(X.size(0)), n_edges=int(ei.size(1)),
             mule_prevalence=float(y[te].mean()))
    print(json.dumps(m, indent=2))
    dest = save_artifacts("gnn_mule", version, model, m, {
        "MODEL_CARD.md": model_card(
            "gnn_mule", version, m,
            "synthetic_nigeria account-transaction graph",
            notes=f"Backend: {backend_name()}."),
    })
    print(f"saved -> {dest}")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=120)
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    train(epochs=a.epochs, version=a.version, seed=a.seed)
