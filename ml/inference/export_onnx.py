"""Export trained models to ONNX for CPU inference (fraud_net, credit_net,
autoencoder). GNN stays torch-only (graph input is awkward for ONNX CPU) but
is exported via torch.jit as fallback."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from ml.models.autoencoder import FraudAutoencoder
from ml.models.credit_net import CREDIT_NUMERIC, CreditNet
from ml.models.fraud_net import FraudNet, cardinalities

ART = Path(__file__).resolve().parents[1] / "artifacts"


class FraudOnnxWrapper(torch.nn.Module):
    """Sigmoid applied inside graph so ONNX emits probability directly."""

    def __init__(self, model: FraudNet):
        super().__init__()
        self.model = model

    def forward(self, x_num, x_cat):
        return torch.sigmoid(self.model.calibrated_logits(x_num, x_cat))


class AEOnnxWrapper(torch.nn.Module):
    def __init__(self, model: FraudAutoencoder):
        super().__init__()
        self.model = model

    def forward(self, x):
        rec = self.model(x)
        return ((rec - x) ** 2).mean(dim=1)


def export_fraud(version: str = "v1") -> Path:
    d = ART / "fraud_net" / version
    vocab = json.loads((d / "vocab.json").read_text())
    model = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
    model.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
    model.eval()
    w = FraudOnnxWrapper(model).eval()
    out = d / "model.onnx"
    torch.onnx.export(
        w, (torch.zeros(1, len(NUMERIC_FEATURES)),
            torch.zeros(1, len(CATEGORICAL_FEATURES), dtype=torch.long)),
        out, input_names=["x_num", "x_cat"], output_names=["fraud_prob"],
        dynamic_axes={"x_num": {0: "batch"}, "x_cat": {0: "batch"},
                      "fraud_prob": {0: "batch"}},
        opset_version=17)
    return out


def export_credit(version: str = "v1") -> Path:
    d = ART / "credit_net" / version
    vocab = json.loads((d / "vocab.json").read_text())
    model = CreditNet(cardinalities(vocab))
    model.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
    model.eval()

    class W(torch.nn.Module):
        def __init__(self, m):
            super().__init__()
            self.m = m

        def forward(self, x_num, x_cat):
            return torch.sigmoid(self.m(x_num, x_cat))

    out = d / "model.onnx"
    torch.onnx.export(
        W(model), (torch.zeros(1, len(CREDIT_NUMERIC)),
                   torch.zeros(1, 4, dtype=torch.long)),
        out, input_names=["x_num", "x_cat"], output_names=["pd"],
        dynamic_axes={"x_num": {0: "batch"}, "x_cat": {0: "batch"},
                      "pd": {0: "batch"}},
        opset_version=17)
    return out


def export_autoencoder(version: str = "v1") -> Path:
    d = ART / "autoencoder" / version
    model = FraudAutoencoder(len(NUMERIC_FEATURES))
    model.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
    model.eval()
    out = d / "model.onnx"
    torch.onnx.export(AEOnnxWrapper(model),
                      torch.zeros(1, len(NUMERIC_FEATURES)), out,
                      input_names=["x"], output_names=["anomaly_score"],
                      dynamic_axes={"x": {0: "batch"},
                                    "anomaly_score": {0: "batch"}},
                      opset_version=17)
    return out


def export_gnn_jit(version: str = "v1") -> Path:
    """GNN via torch.jit (graph structure not portable to plain ONNX here)."""
    from ml.models.gnn_mule import MuleGNN
    d = ART / "gnn_mule" / version
    model = MuleGNN(10)
    model.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
    model.eval()
    out = d / "model.jit.pt"
    torch.jit.save(torch.jit.script(model), out)
    return out


def main(versions: dict | None = None) -> dict:
    versions = versions or {}
    outs = {}
    outs["fraud_net"] = str(export_fraud(versions.get("fraud_net", "v1")))
    print(f"fraud_net -> {outs['fraud_net']}")
    outs["credit_net"] = str(export_credit(versions.get("credit_net", "v1")))
    print(f"credit_net -> {outs['credit_net']}")
    outs["autoencoder"] = str(export_autoencoder(versions.get("autoencoder", "v1")))
    print(f"autoencoder -> {outs['autoencoder']}")
    outs["gnn_mule"] = str(export_gnn_jit(versions.get("gnn_mule", "v1")))
    print(f"gnn_mule (jit) -> {outs['gnn_mule']}")
    return outs


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    a = ap.parse_args()
    main({k: a.version for k in ("fraud_net", "credit_net", "autoencoder", "gnn_mule")})
