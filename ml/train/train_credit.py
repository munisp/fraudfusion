"""Train CreditNet PD scorer on synthetic credit data."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.models.credit_net import (CREDIT_CATEGORICAL, CREDIT_NUMERIC,
                                  CreditNet, pd_to_score)
from ml.models.fraud_net import cardinalities, encode_categoricals
from ml.train.common import (DATA_DIR, EarlyStopper, metrics_dict, model_card,
                             save_artifacts, set_seed)


def prepare(df, vocab=None, scaler=None):
    x_num = df[CREDIT_NUMERIC].to_numpy(np.float32).copy()
    x_num[:, 1] = np.log1p(x_num[:, 1])  # monthly_income
    x_num[:, 3] = np.log1p(x_num[:, 3])  # loan_amount
    if scaler is None:
        scaler = dict(mean=x_num.mean(0), std=x_num.std(0) + 1e-6)
    x_num = (x_num - scaler["mean"]) / scaler["std"]
    x_cat, vocab = encode_categoricals(df, CREDIT_CATEGORICAL, vocab)
    return (torch.from_numpy(x_num.astype(np.float32)),
            torch.from_numpy(x_cat),
            torch.from_numpy(df["default"].to_numpy(np.float32))), vocab, scaler


def train(epochs: int = 40, batch_size: int = 512, lr: float = 2e-3,
          patience: int = 8, seed: int = 42, version: str = "v1") -> dict:
    set_seed(seed)
    df = pd.read_parquet(DATA_DIR / "credit.parquet").sample(
        frac=1.0, random_state=seed).reset_index(drop=True)
    n = len(df)
    tr = df.iloc[: int(0.7 * n)]
    va = df.iloc[int(0.7 * n): int(0.85 * n)]
    te = df.iloc[int(0.85 * n):]
    (xn_tr, xc_tr, y_tr), vocab, scaler = prepare(tr)
    (xn_va, xc_va, y_va), _, _ = prepare(va, vocab, scaler)
    (xn_te, xc_te, y_te), _, _ = prepare(te, vocab, scaler)

    model = CreditNet(cardinalities(vocab))
    pos_w = torch.tensor([(y_tr == 0).sum() / (y_tr == 1).sum().clamp(min=1)])
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, factor=0.5, patience=3)
    stop = EarlyStopper(patience=patience)

    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(len(y_tr))
        for i in range(0, len(y_tr), batch_size):
            b = perm[i:i + batch_size]
            opt.zero_grad()
            loss = F.binary_cross_entropy_with_logits(
                model(xn_tr[b], xc_tr[b]), y_tr[b], pos_weight=pos_w)
            loss.backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            ap = average_precision_score(y_va.numpy(), model.pd(xn_va, xc_va).numpy())
        sched.step(1 - ap)
        print(f"epoch {epoch:02d} val_auc_pr={ap:.4f}")
        if stop.step(ap, model):
            print(f"early stop at epoch {epoch}")
            break
    model.load_state_dict(stop.best_state)
    model.eval()
    with torch.no_grad():
        pd_te = model.pd(xn_te, xc_te).numpy()
    m = metrics_dict(y_te.numpy(), pd_te)
    m.update(epochs_trained=epoch + 1, seed=seed, score_example=float(
        pd_to_score(pd_te[:1])[0]))
    # bust-out capture rate: honest secondary metric
    te_bust = te["bust_out"].to_numpy()
    m["bust_out_capture_at_20pct_review"] = float(
        te_bust[np.argsort(-pd_te)[: int(0.2 * len(te))]].mean())
    print(json.dumps(m, indent=2))

    out_dir = Path(__file__).resolve().parents[1] / "artifacts" / "credit_net" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez(out_dir / "preprocess.npz", scaler_mean=scaler["mean"],
             scaler_std=scaler["std"])
    (out_dir / "vocab.json").write_text(json.dumps(vocab))
    dest = save_artifacts("credit_net", version, model, m, {
        "MODEL_CARD.md": model_card("credit_net", version, m,
                                    "synthetic_nigeria credit bureau-style data"),
    })
    print(f"saved -> {dest}")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    train(epochs=a.epochs, version=a.version, seed=a.seed)
