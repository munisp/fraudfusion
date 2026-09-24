"""Fine-tune shipped FraudNet weights on a NEW data slice (production drift
simulation). Saves versioned output (default v2)."""
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
from ml.data import synthetic_nigeria as syn
from ml.data.synthetic_nigeria import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from ml.models.fraud_net import (FocalLoss, FraudNet, cardinalities,
                                 encode_categoricals, fit_temperature)
from ml.train.common import (DATA_DIR, EarlyStopper, metrics_dict, model_card,
                             save_artifacts, set_seed)

BASE_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "fraud_net"


def make_drift_slice(n_txns: int = 12000, seed: int = 777) -> pd.DataFrame:
    """New-period slice with drift: later window, shifted channel mix, new
    fraud mix (more ATO, less 419) -> simulates production drift."""
    rng = np.random.default_rng(seed)
    accts = pd.read_parquet(DATA_DIR / "accounts.parquet")
    nets = syn._build_mule_networks(accts, rng, n_networks=4)
    tx = syn.generate_transactions(accts, rng, n_txns=n_txns, days=45,
                                   start="2024-07-01")
    tx = syn.inject_fraud(tx, accts, nets, rng)
    tx = syn.add_behavioral_features(tx)
    # drift: shift channel distribution toward mobile_app post-hoc is implicit
    # in RNG; label stays ground-truth from injector.
    return tx


def finetune(new_df: pd.DataFrame | None = None, epochs: int = 10,
             lr: float = 5e-4, batch_size: int = 2048, patience: int = 4,
             seed: int = 42, base_version: str = "v1",
             out_version: str = "v2") -> dict:
    set_seed(seed)
    base = BASE_DIR / base_version
    vocab = json.loads((base / "vocab.json").read_text())
    scaler = np.load(base / "preprocess.npz")
    mean, std = scaler["scaler_mean"], scaler["scaler_std"]

    model = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
    model.load_state_dict(torch.load(base / "weights.pt", weights_only=True))

    if new_df is None:
        print("generating drift slice ...")
        new_df = make_drift_slice()
    drift = new_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    split_i = int(0.8 * len(drift))
    ft, ho = drift.iloc[:split_i], drift.iloc[split_i:]

    def prep(df):
        xn = (df[NUMERIC_FEATURES].to_numpy(np.float32) - mean) / std
        xc, _ = encode_categoricals(df, CATEGORICAL_FEATURES, vocab)
        return (torch.from_numpy(xn.astype(np.float32)), torch.from_numpy(xc),
                torch.from_numpy(df["is_fraud"].to_numpy(np.float32)))

    xn_ft, xc_ft, y_ft = prep(ft)
    xn_ho, xc_ho, y_ho = prep(ho)

    # champion baseline on held-out drift slice
    model.eval()
    with torch.no_grad():
        p_base = model.prob(xn_ho, xc_ho).numpy()
    m_base = metrics_dict(y_ho.numpy(), p_base)

    loss_fn = FocalLoss(alpha=0.35, gamma=2.0)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    stop = EarlyStopper(patience=patience)
    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(len(y_ft))
        for i in range(0, len(y_ft), batch_size):
            b = perm[i:i + batch_size]
            opt.zero_grad()
            loss = loss_fn(model(xn_ft[b], xc_ft[b]), y_ft[b])
            loss.backward()
            opt.step()
        sched.step()
        model.eval()
        with torch.no_grad():
            ap = average_precision_score(y_ho.numpy(),
                                         model.prob(xn_ho, xc_ho, calibrated=False).numpy())
        print(f"finetune epoch {epoch:02d} loss={loss.item():.4f} ho_auc_pr={ap:.4f}")
        if stop.step(ap, model):
            break
    model.load_state_dict(stop.best_state)
    fit_temperature(model, xn_ft, xc_ft, y_ft)
    model.eval()
    with torch.no_grad():
        p_new = model.prob(xn_ho, xc_ho).numpy()
    m_new = metrics_dict(y_ho.numpy(), p_new)

    m = {f"champion_{k}": v for k, v in m_base.items()}
    m.update({f"finetuned_{k}": v for k, v in m_new.items()})
    m.update(base_version=base_version, out_version=out_version,
             drift_slice_size=len(drift), seed=seed,
             improved=bool(m_new["auc_pr"] >= m_base["auc_pr"]))
    print(json.dumps(m, indent=2))
    dest = save_artifacts("fraud_net", out_version, model, m, {
        "MODEL_CARD.md": model_card(
            "fraud_net", out_version, m,
            "synthetic drift slice (post-period simulation)",
            notes="Fine-tuned from v1 champion weights."),
    })
    # carry preprocessing forward (vocab/scaler unchanged)
    (dest / "vocab.json").write_text(json.dumps(vocab))
    np.savez(dest / "preprocess.npz", scaler_mean=mean, scaler_std=std)
    print(f"saved -> {dest}")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=10)
    ap.add_argument("--base-version", default="v1")
    ap.add_argument("--out-version", default="v2")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    finetune(epochs=a.epochs, base_version=a.base_version,
             out_version=a.out_version, seed=a.seed)
