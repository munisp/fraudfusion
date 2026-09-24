"""Train FraudNet tabular classifier on synthetic Nigerian transactions."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from ml.models.fraud_net import (FocalLoss, FraudNet, cardinalities,
                                 encode_categoricals, fit_temperature)
from ml.train.common import (DATA_DIR, EarlyStopper, metrics_dict, model_card,
                             save_artifacts, set_seed)

ART_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "fraud_net" / "v1"


def load_split(name: str):
    df = pd.read_parquet(DATA_DIR / "transactions.parquet")
    return df[df["split"] == name].reset_index(drop=True)


def prepare(df, vocab=None, scaler=None):
    x_num = df[NUMERIC_FEATURES].to_numpy(np.float32)
    if scaler is None:
        scaler = dict(mean=x_num.mean(0), std=x_num.std(0) + 1e-6)
    x_num = (x_num - scaler["mean"]) / scaler["std"]
    x_cat, vocab = encode_categoricals(df, CATEGORICAL_FEATURES, vocab)
    return (torch.from_numpy(x_num.astype(np.float32)),
            torch.from_numpy(x_cat), torch.from_numpy(
                df["is_fraud"].to_numpy(np.float32))), vocab, scaler


def train(epochs: int = 30, batch_size: int = 2048, lr: float = 2e-3,
          patience: int = 6, seed: int = 42, version: str = "v1",
          out_dir: Path | None = None) -> dict:
    set_seed(seed)
    tr, va, te = load_split("train"), load_split("val"), load_split("test")
    (xn_tr, xc_tr, y_tr), vocab, scaler = prepare(tr)
    (xn_va, xc_va, y_va), _, _ = prepare(va, vocab, scaler)
    (xn_te, xc_te, y_te), _, _ = prepare(te, vocab, scaler)

    model = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
    loss_fn = FocalLoss(alpha=0.35, gamma=2.0)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, factor=0.5, patience=2)
    stop = EarlyStopper(patience=patience)

    n = len(y_tr)
    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(n)
        tot = 0.0
        for i in range(0, n, batch_size):
            b = perm[i:i + batch_size]
            opt.zero_grad()
            loss = loss_fn(model(xn_tr[b], xc_tr[b]), y_tr[b])
            loss.backward()
            opt.step()
            tot += loss.item() * len(b)
        model.eval()
        with torch.no_grad():
            p_va = model.prob(xn_va, xc_va, calibrated=False).numpy()
        ap = average_precision_score(y_va.numpy(), p_va)
        sched.step(1 - ap)
        print(f"epoch {epoch:02d} loss={tot/n:.4f} val_auc_pr={ap:.4f}")
        if stop.step(ap, model):
            print(f"early stop at epoch {epoch}")
            break
    model.load_state_dict(stop.best_state)

    # temperature scaling on validation set
    t = fit_temperature(model, xn_va, xc_va, y_va)
    model.eval()
    with torch.no_grad():
        p_te = model.prob(xn_te, xc_te).numpy()
        p_va = model.prob(xn_va, xc_va).numpy()
    m = metrics_dict(y_te.numpy(), p_te)
    m.update(val_auc_pr=float(average_precision_score(y_va.numpy(), p_va)),
             temperature=t, epochs_trained=epoch + 1, seed=seed,
             backend="torch", n_train=len(tr), n_test=len(te))
    print(json.dumps(m, indent=2))

    out_dir = out_dir or ART_DIR.parent / version
    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez(out_dir / "preprocess.npz", scaler_mean=scaler["mean"],
             scaler_std=scaler["std"])
    (out_dir / "vocab.json").write_text(json.dumps(vocab))
    torch.save(model.state_dict(), out_dir / "weights.pt")
    (out_dir / "metrics.json").write_text(json.dumps(m, indent=2))
    dest = save_artifacts("fraud_net", version, model, m, {
        "MODEL_CARD.md": model_card("fraud_net", version, m,
                                    "synthetic_nigeria transactions"),
    })
    print(f"saved -> {dest}")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    train(epochs=a.epochs, version=a.version, seed=a.seed)
