"""Train deep autoencoder on legitimate transactions (unsupervised anomaly)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import NUMERIC_FEATURES
from ml.models.autoencoder import FraudAutoencoder
from ml.train.common import (DATA_DIR, EarlyStopper, metrics_dict, model_card,
                             save_artifacts, set_seed)


def load(split):
    df = pd.read_parquet(DATA_DIR / "transactions.parquet")
    return df[df["split"] == split].reset_index(drop=True)


def scale(df, scaler=None):
    x = df[NUMERIC_FEATURES].to_numpy(np.float32)
    if scaler is None:
        scaler = dict(mean=x.mean(0), std=x.std(0) + 1e-6)
    return torch.from_numpy(((x - scaler["mean"]) / scaler["std"]).astype(np.float32)), scaler


def train(epochs: int = 60, batch_size: int = 2048, lr: float = 1e-3,
          patience: int = 10, seed: int = 42, version: str = "v1") -> dict:
    set_seed(seed)
    tr, va, te = load("train"), load("val"), load("test")
    legit_tr = tr[tr["is_fraud"] == 0]
    legit_va = va[va["is_fraud"] == 0]
    x_tr, scaler = scale(legit_tr)
    x_va, _ = scale(legit_va, scaler)
    x_te, _ = scale(te, scaler)
    y_te = te["is_fraud"].to_numpy()

    model = FraudAutoencoder(x_tr.size(1))
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-5)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, factor=0.5, patience=3)
    stop = EarlyStopper(patience=patience, mode="min")

    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(len(x_tr))
        for i in range(0, len(x_tr), batch_size):
            b = perm[i:i + batch_size]
            opt.zero_grad()
            loss = F.mse_loss(model(x_tr[b]), x_tr[b])
            loss.backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            val_loss = F.mse_loss(model(x_va), x_va).item()
        sched.step(val_loss)
        if epoch % 5 == 0:
            print(f"epoch {epoch:02d} train_mse={loss.item():.5f} val_mse={val_loss:.5f}")
        if stop.step(-val_loss, model):
            print(f"early stop at epoch {epoch}")
            break
    model.load_state_dict(stop.best_state)
    model.eval()
    with torch.no_grad():
        scores = model.anomaly_score(x_te).numpy()
    m = metrics_dict(y_te, scores)
    m.update(epochs_trained=epoch + 1, seed=seed,
             note="trained on legitimate transactions only; score=MSE recon error")
    print(json.dumps(m, indent=2))

    out_dir = Path(__file__).resolve().parents[1] / "artifacts" / "autoencoder" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez(out_dir / "preprocess.npz", scaler_mean=scaler["mean"],
             scaler_std=scaler["std"])
    dest = save_artifacts("autoencoder", version, model, m, {
        "MODEL_CARD.md": model_card("autoencoder", version, m,
                                    "synthetic_nigeria legit-only transactions"),
    })
    print(f"saved -> {dest}")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    train(epochs=a.epochs, version=a.version, seed=a.seed)
