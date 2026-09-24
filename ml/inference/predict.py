"""Pure-CPU inference CLI: score a JSON transaction/credit application with
the exported ONNX models (torch fallback if onnxruntime is unavailable).

Example:
  python -m ml.inference.predict --model fraud_net --input '{"log_amount": 12.5, ...}'
  python -m ml.inference.predict --model fraud_net --input-file txn.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from ml.models.credit_net import (CREDIT_CATEGORICAL, CREDIT_NUMERIC,
                                  pd_to_score)

ART = Path(__file__).resolve().parents[1] / "artifacts"


def _load_preprocess(d: Path):
    p = np.load(d / "preprocess.npz")
    return p["scaler_mean"], p["scaler_std"]


def _encode(payload: dict, cat_features, vocab, num_features, mean, std):
    x_num = np.array([[float(payload.get(f, 0.0)) for f in num_features]],
                     dtype=np.float32)
    x_num = (x_num - mean) / std
    x_cat = np.zeros((1, len(cat_features)), dtype=np.int64)
    for j, c in enumerate(sorted(cat_features)):  # match model embedding order
        x_cat[0, j] = vocab.get(c, {}).get(str(payload.get(c, "")), 0)
    return x_num.astype(np.float32), x_cat


def score_fraud(payload: dict, version: str = "v1") -> dict:
    d = ART / "fraud_net" / version
    vocab = json.loads((d / "vocab.json").read_text())
    mean, std = _load_preprocess(d)
    x_num, x_cat = _encode(payload, CATEGORICAL_FEATURES, vocab,
                           NUMERIC_FEATURES, mean, std)
    onnx = d / "model.onnx"
    if onnx.exists():
        import onnxruntime as ort
        sess = ort.InferenceSession(str(onnx), providers=["CPUExecutionProvider"])
        prob = float(sess.run(None, {"x_num": x_num, "x_cat": x_cat})[0][0])
        engine = "onnxruntime-cpu"
    else:  # torch fallback
        import torch
        from ml.models.fraud_net import FraudNet, cardinalities
        m = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
        m.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
        m.eval()
        with torch.no_grad():
            prob = float(m.prob(torch.from_numpy(x_num),
                                torch.from_numpy(x_cat))[0])
        engine = "torch-fallback"
    return {"model": "fraud_net", "version": version, "engine": engine,
            "fraud_probability": prob,
            "decision": "block" if prob >= 0.8 else "review" if prob >= 0.3 else "allow"}


def score_credit(payload: dict, version: str = "v1") -> dict:
    d = ART / "credit_net" / version
    vocab = json.loads((d / "vocab.json").read_text())
    mean, std = _load_preprocess(d)
    p2 = dict(payload)
    for f, src in ((1, "monthly_income"), (3, "loan_amount_ngn")):
        if src in p2:
            p2[src] = float(np.log1p(float(p2[src])))
    x_num, x_cat = _encode(p2, CREDIT_CATEGORICAL, vocab, CREDIT_NUMERIC,
                           mean, std)
    onnx = d / "model.onnx"
    if onnx.exists():
        import onnxruntime as ort
        sess = ort.InferenceSession(str(onnx), providers=["CPUExecutionProvider"])
        pd_ = float(sess.run(None, {"x_num": x_num, "x_cat": x_cat})[0][0])
        engine = "onnxruntime-cpu"
    else:
        import torch
        from ml.models.credit_net import CreditNet
        from ml.models.fraud_net import cardinalities
        m = CreditNet(cardinalities(vocab))
        m.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
        m.eval()
        with torch.no_grad():
            pd_ = float(m.pd(torch.from_numpy(x_num), torch.from_numpy(x_cat))[0])
        engine = "torch-fallback"
    return {"model": "credit_net", "version": version, "engine": engine,
            "probability_of_default": pd_,
            "credit_score": float(pd_to_score(np.array([pd_]))[0])}


def score_anomaly(payload: dict, version: str = "v1") -> dict:
    d = ART / "autoencoder" / version
    mean, std = _load_preprocess(d)
    x = np.array([[float(payload.get(f, 0.0)) for f in NUMERIC_FEATURES]],
                 dtype=np.float32)
    x = ((x - mean) / std).astype(np.float32)
    onnx = d / "model.onnx"
    if onnx.exists():
        import onnxruntime as ort
        sess = ort.InferenceSession(str(onnx), providers=["CPUExecutionProvider"])
        s = float(sess.run(None, {"x": x})[0][0])
        engine = "onnxruntime-cpu"
    else:
        import torch
        from ml.models.autoencoder import FraudAutoencoder
        m = FraudAutoencoder(len(NUMERIC_FEATURES))
        m.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
        m.eval()
        with torch.no_grad():
            s = float(m.anomaly_score(torch.from_numpy(x))[0])
        engine = "torch-fallback"
    return {"model": "autoencoder", "version": version, "engine": engine,
            "anomaly_score": s}


SCORERS = {"fraud_net": score_fraud, "credit_net": score_credit,
           "autoencoder": score_anomaly}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, choices=sorted(SCORERS))
    ap.add_argument("--input", help="JSON payload inline")
    ap.add_argument("--input-file", help="path to JSON payload")
    ap.add_argument("--version", default="v1")
    a = ap.parse_args()
    if a.input_file:
        payload = json.loads(Path(a.input_file).read_text())
    elif a.input:
        payload = json.loads(a.input)
    else:
        payload = json.load(sys.stdin)
    print(json.dumps(SCORERS[a.model](payload, a.version), indent=2))


if __name__ == "__main__":
    main()
