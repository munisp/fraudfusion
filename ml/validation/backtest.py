"""Temporal backtesting harness: replay historical transactions through a
fraud_net artifact version, compute per-window precision/recall/alert-volume
curves, and tune the alert threshold on a cost model.

Honest methodology:
  * Windows are STRICTLY temporal (no shuffle) — replay, not random splits.
  * The threshold is tuned on the FIRST window set (calibration fraction) and
    then frozen for the remaining windows, so reported metrics are
    out-of-sample w.r.t. threshold choice.
  * Cost model: cost_fp (analyst review cost per false alert) and cost_fn
    (expected loss per missed fraud, default = median fraud amount).

Usage:
  python -m ml.validation.backtest --dataset synthetic \
      --file ml/data/generated/transactions.parquet --model-version v3
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import (CATEGORICAL_FEATURES, NUMERIC_FEATURES)
from ml.models.fraud_net import cardinalities, encode_categoricals
from ml.validation.adapters import ADAPTERS, to_model_frame

ART = Path(__file__).resolve().parents[1] / "artifacts"


def load_scorer(version: str = "v1"):
    """Batch scorer over the exported artifact (ONNX preferred)."""
    d = ART / "fraud_net" / version
    vocab = json.loads((d / "vocab.json").read_text())
    p = np.load(d / "preprocess.npz")
    mean, std = p["scaler_mean"], p["scaler_std"]
    onnx_path = d / "model.onnx"
    sess = None
    if onnx_path.exists():
        import onnxruntime as ort
        sess = ort.InferenceSession(str(onnx_path),
                                    providers=["CPUExecutionProvider"])
    if sess is None:
        import torch
        from ml.models.fraud_net import FraudNet
        m = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
        m.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
        m.eval()

    def score(df: pd.DataFrame) -> np.ndarray:
        df = to_model_frame(df)
        x_num = df[NUMERIC_FEATURES].to_numpy(np.float32)
        x_num = (x_num - mean) / std
        x_cat, _ = encode_categoricals(df, CATEGORICAL_FEATURES, vocab)
        if sess is not None:
            return sess.run(None, {"x_num": x_num.astype(np.float32),
                                   "x_cat": x_cat})[0].ravel()
        import torch
        with torch.no_grad():
            return m.prob(torch.from_numpy(x_num.astype(np.float32)),
                          torch.from_numpy(x_cat)).numpy()
    return score


def window_metrics(y_true: np.ndarray, scores: np.ndarray,
                   threshold: float) -> dict:
    alert = scores >= threshold
    tp = int(((y_true == 1) & alert).sum())
    fp = int(((y_true == 0) & alert).sum())
    fn = int(((y_true == 1) & ~alert).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return dict(n=len(y_true), fraud=int(y_true.sum()), alerts=int(alert.sum()),
                alert_rate=float(alert.mean()), tp=tp, fp=fp, fn=fn,
                precision=float(prec), recall=float(rec),
                f1=float(2 * prec * rec / (prec + rec)) if prec + rec else 0.0)


def tune_threshold(y_true: np.ndarray, scores: np.ndarray,
                   amounts: np.ndarray, cost_fp: float = 500.0,
                   cost_fn: float | None = None) -> dict:
    """Pick threshold minimising expected cost = cost_fp*FP + E[cost_fn]*FN.

    cost_fn defaults to the median fraud amount (missed fraud ~= lost funds).
    """
    if cost_fn is None:
        fraud_amt = amounts[y_true == 1]
        cost_fn = float(np.median(fraud_amt)) if len(fraud_amt) else 50_000.0
    grid = np.unique(np.quantile(scores, np.linspace(0.5, 0.999, 100)))
    best = None
    for t in grid:
        m = window_metrics(y_true, scores, float(t))
        cost = m["fp"] * cost_fp + m["fn"] * cost_fn
        if best is None or cost < best[0]:
            best = (cost, float(t), m)
    return dict(threshold=best[1], expected_cost=float(best[0]),
                cost_fp=cost_fp, cost_fn=cost_fn,
                metrics_at_threshold=best[2])


def backtest(df: pd.DataFrame, version: str = "v1", window: str = "7D",
             calib_frac: float = 0.3, cost_fp: float = 500.0) -> dict:
    df = df.sort_values("ts").reset_index(drop=True)
    df["window"] = df["ts"].dt.floor(window)  # e.g. "7D", "W", "1D"
    score = load_scorer(version)
    scores = np.zeros(len(df))
    # score per window to bound memory and mimic batch-scoring cadence
    for w, g in df.groupby("window"):
        scores[g.index.to_numpy()] = score(g)
    df["score"] = scores

    windows = sorted(df["window"].unique())
    n_cal = max(1, int(len(windows) * calib_frac))
    cal_w, eval_w = windows[:n_cal], windows[n_cal:] or windows[:n_cal]
    cal = df[df["window"].isin(cal_w)]
    tuned = tune_threshold(cal["is_fraud"].to_numpy(), cal["score"].to_numpy(),
                           cal["amount_ngn"].to_numpy(), cost_fp=cost_fp)
    thr = tuned["threshold"]

    per_window = []
    for w in eval_w:
        g = df[df["window"] == w]
        m = window_metrics(g["is_fraud"].to_numpy(), g["score"].to_numpy(), thr)
        m["window"] = str(w)
        per_window.append(m)
    ev = df[df["window"].isin(eval_w)]
    overall = window_metrics(ev["is_fraud"].to_numpy(), ev["score"].to_numpy(), thr)
    from sklearn.metrics import average_precision_score, roc_auc_score
    overall["auc_pr"] = float(average_precision_score(
        ev["is_fraud"], ev["score"]))
    overall["auc_roc"] = float(roc_auc_score(ev["is_fraud"], ev["score"]))
    return dict(model_version=version, window=window, threshold=thr,
                threshold_tuning=tuned, calibration_windows=[str(w) for w in cal_w],
                eval_windows=[str(w) for w in eval_w],
                overall_eval=overall, per_window=per_window,
                n_rows=len(df), fraud_rate=float(df["is_fraud"].mean()))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="synthetic", choices=sorted(ADAPTERS))
    ap.add_argument("--file", default="ml/data/generated")
    ap.add_argument("--model-version", default="v1")
    ap.add_argument("--window", default="7D")
    ap.add_argument("--cost-fp", type=float, default=500.0)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    try:
        df = ADAPTERS[a.dataset].load(a.file)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)
    res = backtest(df, version=a.model_version, window=a.window,
                   cost_fp=a.cost_fp)
    txt = json.dumps(res, indent=2)
    print(txt)
    if a.out:
        Path(a.out).write_text(txt)
