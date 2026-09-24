"""Pytest smoke tests: data gen, model forward shapes, 1-epoch training,
ONNX roundtrip."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.data import synthetic_nigeria as syn
from ml.models.autoencoder import FraudAutoencoder
from ml.models.credit_net import CreditNet, pd_to_score
from ml.models.fraud_net import FraudNet
from ml.models.gnn_mule import MuleGNN


@pytest.fixture(scope="module")
def small_data(tmp_path_factory):
    out = tmp_path_factory.mktemp("gen")
    meta = syn.main(str(out), n_customers=400, n_txns=4000, seed=1)
    return out, meta


def test_data_gen_shapes_and_distributions(small_data):
    out, meta = small_data
    tx = pd.read_parquet(out / "transactions.parquet")
    accts = pd.read_parquet(out / "accounts.parquet")
    assert len(tx) >= 4000
    assert 0.005 < tx["is_fraud"].mean() < 0.3
    # NUBAN: 10 digits
    assert accts["nuban"].str.len().eq(10).all()
    # BVN/NIN: 11 digits
    assert accts["bvn"].str.len().eq(11).all()
    assert accts["nin"].str.len().eq(11).all()
    # kobo rounding: 2dp max
    cents = (tx["amount_ngn"] * 100).round()
    assert np.allclose(tx["amount_ngn"] * 100, cents)
    # Lagos-weighted geo
    assert (accts["state"] == "Lagos").mean() > 0.25
    # mules exist, salary-cycle features exist
    assert accts["is_mule"].sum() > 0
    assert set(syn.NUMERIC_FEATURES) <= set(tx.columns)
    assert tx["split"].isin(["train", "val", "test"]).all()


def test_temporal_split_ordering(small_data):
    out, _ = small_data
    tx = pd.read_parquet(out / "transactions.parquet")
    cuts = tx.groupby("split")["ts"].max()
    assert cuts["train"] <= cuts["val"] <= cuts["test"]


def test_fraud_net_forward_shape():
    vocab = {"channel": 6, "sender_bank": 10, "receiver_bank": 10,
             "sender_state": 17, "device_os": 5}
    m = FraudNet(vocab, len(syn.NUMERIC_FEATURES))
    xn = torch.randn(8, len(syn.NUMERIC_FEATURES))
    xc = torch.randint(0, 5, (8, len(syn.CATEGORICAL_FEATURES)))
    out = m(xn, xc)
    assert out.shape == (8,)
    p = m.prob(xn, xc)
    assert ((p >= 0) & (p <= 1)).all()


def test_credit_net_forward_and_score():
    vocab = {"employment": 6, "state": 17, "bank": 10, "purpose": 6}
    m = CreditNet(vocab)
    xn = torch.randn(4, 7)
    xc = torch.randint(0, 5, (4, 4))
    pd_ = m.pd(xn, xc)
    assert pd_.shape == (4,)
    scores = pd_to_score(pd_.detach().numpy())
    assert ((scores >= 300) & (scores <= 850)).all()
    # monotone: lower PD -> higher score
    s = pd_to_score(np.array([0.01, 0.5]))
    assert s[0] > s[1]


def test_gnn_forward_and_one_step():
    m = MuleGNN(10)
    x = torch.randn(50, 10)
    ei = torch.randint(0, 50, (2, 300))
    out = m(x, ei)
    assert out.shape == (50,)
    # 1-epoch-ish training step reduces loss on trivially separable data
    y = torch.zeros(50)
    y[:5] = 1
    opt = torch.optim.Adam(m.parameters(), lr=1e-2)
    l0 = torch.nn.functional.binary_cross_entropy_with_logits(m(x, ei), y)
    for _ in range(30):
        opt.zero_grad()
        loss = torch.nn.functional.binary_cross_entropy_with_logits(m(x, ei), y)
        loss.backward()
        opt.step()
    l1 = torch.nn.functional.binary_cross_entropy_with_logits(m(x, ei), y)
    assert l1.item() < l0.item()


def test_autoencoder_forward():
    m = FraudAutoencoder(len(syn.NUMERIC_FEATURES))
    x = torch.randn(16, len(syn.NUMERIC_FEATURES))
    assert m(x).shape == x.shape
    assert m.anomaly_score(x).shape == (16,)


def test_one_epoch_fraud_training(small_data, tmp_path, monkeypatch):
    """Full 1-epoch fraud training on the small fixture, artifacts written."""
    from ml.train import train_fraud
    monkeypatch.setenv("FRAUDFUSION_DATA", str(small_data[0]))
    import ml.train.common as common
    monkeypatch.setattr(train_fraud, "DATA_DIR", small_data[0])
    monkeypatch.setattr(common, "ARTIFACT_ROOT", tmp_path / "artifacts")
    m = train_fraud.train(epochs=1, batch_size=512, out_dir=tmp_path / "out")
    assert 0.0 <= m["auc_roc"] <= 1.0
    assert (tmp_path / "out" / "weights.pt").exists()


@pytest.mark.skipif(
    not pytest.importorskip("onnxruntime", reason="onnxruntime missing"),
    reason="needs onnxruntime")
def test_onnx_roundtrip(small_data, tmp_path):
    """Export FraudNet to ONNX and check outputs match torch."""
    import onnxruntime as ort
    from ml.inference.export_onnx import FraudOnnxWrapper
    from ml.models.fraud_net import cardinalities
    vocab = {"channel": 6, "sender_bank": 10, "receiver_bank": 10,
             "sender_state": 17, "device_os": 5}
    m = FraudNet(vocab, len(syn.NUMERIC_FEATURES)).eval()
    w = FraudOnnxWrapper(m).eval()
    xn = torch.randn(5, len(syn.NUMERIC_FEATURES))
    xc = torch.randint(0, 5, (5, len(syn.CATEGORICAL_FEATURES)))
    out = tmp_path / "m.onnx"
    torch.onnx.export(w, (xn, xc), out, input_names=["x_num", "x_cat"],
                      output_names=["p"], opset_version=17)
    sess = ort.InferenceSession(str(out), providers=["CPUExecutionProvider"])
    p_onnx = sess.run(None, {"x_num": xn.numpy(), "x_cat": xc.numpy()})[0]
    with torch.no_grad():
        p_torch = w(xn, xc).numpy()
    assert np.allclose(p_onnx, p_torch, atol=1e-5)
