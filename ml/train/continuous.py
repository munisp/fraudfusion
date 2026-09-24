"""Continuous-training driver.

Reads new parquet partitions from the lakehouse dir (env LAKEHOUSE_DIR,
default ./lakehouse). When the new-data threshold is met, retrains a
challenger FraudNet, compares challenger vs champion on held-out metrics,
and writes a promotion decision JSON.

Lakehouse layout: <LAKEHOUSE_DIR>/transactions/dt=YYYY-MM-DD/part-*.parquet
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from ml.models.fraud_net import (FocalLoss, FraudNet, cardinalities,
                                 encode_categoricals, fit_temperature)
from ml.train.common import (EarlyStopper, metrics_dict, model_card,
                             save_artifacts, set_seed)
from ml.train.finetune import make_drift_slice

LAKEHOUSE_DIR = Path(os.environ.get("LAKEHOUSE_DIR", "./lakehouse"))
STATE_FILE = LAKEHOUSE_DIR / ".continuous_state.json"
DECISION_FILE = LAKEHOUSE_DIR / "promotion_decision.json"
ART_ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "fraud_net"


def scan_new_partitions(threshold: int) -> pd.DataFrame | None:
    """Collect unread parquet partitions; return combined df if >= threshold."""
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"seen": []}
    seen = set(state["seen"])
    parts = sorted(LAKEHOUSE_DIR.glob("transactions/dt=*/part-*.parquet"))
    new = [p for p in parts if str(p) not in seen]
    if not new:
        print("no new partitions")
        return None
    df = pd.concat([pd.read_parquet(p) for p in new], ignore_index=True)
    print(f"new partitions: {len(new)} files, {len(df)} rows")
    if len(df) < threshold:
        print(f"below threshold ({threshold}); deferring retrain")
        return None
    state["seen"] = sorted(seen | {str(p) for p in new})
    STATE_FILE.write_text(json.dumps(state, indent=2))
    return df


def retrain_challenger(champion_dir: Path, new_df: pd.DataFrame,
                       epochs: int, lr: float, seed: int,
                       out_version: str) -> tuple[dict, Path]:
    set_seed(seed)
    vocab = json.loads((champion_dir / "vocab.json").read_text())
    scaler = np.load(champion_dir / "preprocess.npz")
    mean, std = scaler["scaler_mean"], scaler["scaler_std"]

    def prep(df):
        xn = (df[NUMERIC_FEATURES].to_numpy(np.float32) - mean) / std
        xc, _ = encode_categoricals(df, CATEGORICAL_FEATURES, vocab)
        return (torch.from_numpy(xn.astype(np.float32)), torch.from_numpy(xc),
                torch.from_numpy(df["is_fraud"].to_numpy(np.float32)))

    df = new_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    cut = int(0.8 * len(df))
    xn_tr, xc_tr, y_tr = prep(df.iloc[:cut])
    xn_ho, xc_ho, y_ho = prep(df.iloc[cut:])

    champion = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
    champion.load_state_dict(torch.load(champion_dir / "weights.pt",
                                        weights_only=True))
    champion.eval()
    with torch.no_grad():
        m_champ = metrics_dict(y_ho.numpy(), champion.prob(xn_ho, xc_ho).numpy())

    challenger = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
    challenger.load_state_dict(torch.load(champion_dir / "weights.pt",
                                          weights_only=True))
    loss_fn = FocalLoss(alpha=0.35, gamma=2.0)
    opt = torch.optim.AdamW(challenger.parameters(), lr=lr, weight_decay=1e-4)
    stop = EarlyStopper(patience=4)
    for epoch in range(epochs):
        challenger.train()
        perm = torch.randperm(len(y_tr))
        for i in range(0, len(y_tr), 2048):
            b = perm[i:i + 2048]
            opt.zero_grad()
            loss = loss_fn(challenger(xn_tr[b], xc_tr[b]), y_tr[b])
            loss.backward()
            opt.step()
        challenger.eval()
        with torch.no_grad():
            ap = average_precision_score(
                y_ho.numpy(), challenger.prob(xn_ho, xc_ho, calibrated=False).numpy())
        print(f"challenger epoch {epoch:02d} ho_auc_pr={ap:.4f}")
        if stop.step(ap, challenger):
            break
    challenger.load_state_dict(stop.best_state)
    fit_temperature(challenger, xn_tr, xc_tr, y_tr)
    challenger.eval()
    with torch.no_grad():
        m_chal = metrics_dict(y_ho.numpy(), challenger.prob(xn_ho, xc_ho).numpy())

    promoted = m_chal["auc_pr"] >= m_champ["auc_pr"]
    decision = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "model": "fraud_net",
        "champion_version": champion_dir.name,
        "challenger_version": out_version,
        "champion_metrics": m_champ,
        "challenger_metrics": m_chal,
        "promoted": bool(promoted),
        "reason": ("challenger >= champion on held-out AUC-PR"
                   if promoted else "challenger below champion; keep champion"),
    }
    if promoted:
        dest = save_artifacts("fraud_net", out_version, challenger,
                              {"held_out": m_chal}, {
                                  "MODEL_CARD.md": model_card(
                                      "fraud_net", out_version, m_chal,
                                      "lakehouse incremental partitions (synthetic)"),
                              })
        (dest / "vocab.json").write_text(json.dumps(vocab))
        np.savez(dest / "preprocess.npz", scaler_mean=mean, scaler_std=std)
        decision["promoted_path"] = str(dest)
    _write_promotion_metrics(decision)
    return decision


def _write_promotion_metrics(decision: dict) -> None:
    """Prometheus textfile gauges for promotion decisions.

    Consumed by observability/prometheus/fraudfusion-model.rules.yml
    (FraudFusionChallengerPromotion alert). TEXTFILE_COLLECTOR_DIR is the
    node-exporter textfile directory; silently skips if unset.
    """
    out_dir = os.environ.get("TEXTFILE_COLLECTOR_DIR")
    if not out_dir:
        return
    try:
        p = Path(out_dir) / "fraudfusion_model.prom"
        lines = [
            "# HELP fraudfusion_model_promotion 1 if the latest challenger was promoted",
            "# TYPE fraudfusion_model_promotion gauge",
            f'fraudfusion_model_promotion{{model="{decision["model"]}",'
            f'challenger="{decision["challenger_version"]}"}} '
            f'{1 if decision["promoted"] else 0}',
            "# HELP fraudfusion_model_challenger_auc_pr latest challenger held-out AUC-PR",
            "# TYPE fraudfusion_model_challenger_auc_pr gauge",
            f'fraudfusion_model_challenger_auc_pr{{model="{decision["model"]}"}} '
            f'{decision["challenger_metrics"]["auc_pr"]:.6f}',
            "# HELP fraudfusion_model_champion_auc_pr champion held-out AUC-PR",
            "# TYPE fraudfusion_model_champion_auc_pr gauge",
            f'fraudfusion_model_champion_auc_pr{{model="{decision["model"]}"}} '
            f'{decision["champion_metrics"]["auc_pr"]:.6f}',
        ]
        tmp = p.with_suffix(".tmp")
        tmp.write_text("\n".join(lines) + "\n")
        tmp.rename(p)
    except OSError as e:
        print(f"promotion textfile export skipped: {e}")


def main(threshold: int = 2000, epochs: int = 8, lr: float = 5e-4,
         seed: int = 42, champion_version: str = "v1",
         out_version: str | None = None, demo: bool = False) -> dict | None:
    LAKEHOUSE_DIR.mkdir(parents=True, exist_ok=True)
    if demo:
        # simulate a lakehouse partition landing
        part_dir = LAKEHOUSE_DIR / "transactions" / "dt=2024-07-15"
        part_dir.mkdir(parents=True, exist_ok=True)
        df = make_drift_slice(n_txns=max(threshold + 500, 3000), seed=991)
        df.to_parquet(part_dir / "part-00000.parquet", index=False)
        print(f"demo partition written: {len(df)} rows")
    new_df = scan_new_partitions(threshold)
    if new_df is None:
        return None
    if out_version is None:
        existing = sorted(p.name for p in ART_ROOT.iterdir() if p.is_dir())
        out_version = f"v{max([int(v[1:]) for v in existing if v[1:].isdigit()] + [1]) + 1}"
    decision = retrain_challenger(ART_ROOT / champion_version, new_df,
                                  epochs, lr, seed, out_version)
    DECISION_FILE.write_text(json.dumps(decision, indent=2))
    print(f"decision -> {DECISION_FILE}")
    print(json.dumps({k: decision[k] for k in ("promoted", "reason")}, indent=2))
    return decision


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=2000)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--champion-version", default="v1")
    ap.add_argument("--demo", action="store_true",
                    help="write a simulated lakehouse partition first")
    a = ap.parse_args()
    main(threshold=a.threshold, epochs=a.epochs,
         champion_version=a.champion_version, demo=a.demo)
