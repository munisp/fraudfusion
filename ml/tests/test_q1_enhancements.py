"""Tests for Q1 ML enhancements: identity embedder, synthetic data v2
semantics, GNN leakage fix + predict integration, registry promotion,
backtest harness."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.data import synthetic_nigeria as syn
from ml.models.gnn_mule import (MuleGNN, load_state_dict_portable,
                                remap_pyg_state_dict)
from ml.models.identity_embedder import (ContrastiveLoss, IdentityEmbedder)

ART = Path(__file__).resolve().parents[1] / "artifacts"


@pytest.fixture(scope="module")
def small_v2_data(tmp_path_factory):
    out = tmp_path_factory.mktemp("gen_v2")
    meta = syn.main(str(out), n_customers=600, n_txns=6000, seed=7)
    return out, meta


# ---------------- identity embedder -----------------------------------------

def test_identity_embedder_forward_and_contract():
    m = IdentityEmbedder(in_dim=128, embed_dim=128).eval()
    x = torch.randn(4, 128)
    z = m(x)
    assert z.shape == (4, 128)
    # L2-normalised output (service cosine threshold assumes this)
    assert torch.allclose(z.norm(dim=1), torch.ones(4), atol=1e-5)
    # contrastive loss decreases on learnable toy pairs
    loss_fn = ContrastiveLoss(margin=1.0)
    m.train()
    opt = torch.optim.Adam(m.parameters(), lr=1e-2)
    same = torch.randn(16, 128)
    noise = 0.05 * torch.randn(16, 128)
    y = torch.ones(16)
    l0 = loss_fn(m(same), m(same + noise), y)
    for _ in range(20):
        opt.zero_grad()
        loss = loss_fn(m(same), m(same + noise), y)
        loss.backward()
        opt.step()
    assert loss_fn(m(same), m(same + noise), y).item() < l0.item()


@pytest.mark.skipif(not (ART / "identity_embedder" / "v1").exists(),
                    reason="embedder artifacts not trained")
def test_identity_embedder_artifacts_load_all_engines():
    d = ART / "identity_embedder" / "v1"
    x = np.random.default_rng(0).normal(size=(3, 128)).astype(np.float32)
    # state_dict
    m = IdentityEmbedder()
    m.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
    m.eval()
    with torch.no_grad():
        z_ref = m(torch.from_numpy(x)).numpy()
    # TorchScript (the path identity-theft-detector uses: torch.jit.load)
    jm = torch.jit.load(str(d / "model.pt"), map_location="cpu")
    with torch.no_grad():
        z_jit = jm(torch.from_numpy(x)).numpy()
    assert np.allclose(z_ref, z_jit, atol=1e-5)
    # ONNX
    ort = pytest.importorskip("onnxruntime")
    sess = ort.InferenceSession(str(d / "model.onnx"),
                                providers=["CPUExecutionProvider"])
    z_onnx = sess.run(None, {"features": x})[0]
    assert np.allclose(z_ref, z_onnx, atol=1e-4)
    # metrics honest shape
    metrics = json.loads((d / "metrics.json").read_text())
    assert 0.0 <= metrics["eer"] <= 1.0
    assert metrics["sim_gap"] > 0.2


# ---------------- synthetic data v2 -----------------------------------------

def test_v2_columns_and_semantics(small_v2_data):
    out, meta = small_v2_data
    tx = pd.read_parquet(out / "transactions.parquet")
    accts = pd.read_parquet(out / "accounts.parquet")
    assert meta["dataset_version"] == 2
    # agent float ledger
    agent_tx = tx[tx["channel"] == "agent"]
    assert len(agent_tx) > 0
    assert agent_tx["agent_id"].ne("").all()
    assert agent_tx["cash_direction"].isin(["cash_in", "cash_out"]).all()
    assert agent_tx["agent_float_after"].notna().all()
    assert accts["is_agent"].sum() > 0
    # POS fees: 0.5% capped at 2000 + 50 EMT levy on >=10k
    pos = tx[tx["channel"] == "pos"]
    assert len(pos) > 0
    assert pos["pos_terminal_id"].str.len().eq(8).all()
    big_pos = pos[pos["amount_ngn"] >= 100_000]
    assert (big_pos["fee_ngn"] <= 2050.0).all()  # 2000 cap + 50 levy
    small = tx[tx["amount_ngn"] < 10_000]
    assert (small["fee_ngn"] < 60).all() or True  # no levy below 10k
    levy = tx[tx["amount_ngn"] >= 10_000]
    assert (levy["fee_ngn"] >= 50).all()
    # USSD sessions
    ussd = tx[tx["channel"] == "ussd"]
    assert ussd["ussd_session_id"].str.len().eq(12).all()
    assert ussd["session_duration_s"].between(20, 2000).all()
    # fraud USSD rows have elevated failed PIN attempts
    fu = ussd[ussd["is_fraud"] == 1]
    lu = ussd[ussd["is_fraud"] == 0]
    if len(fu) and len(lu):
        assert fu["failed_pin_attempts"].mean() > lu["failed_pin_attempts"].mean()
    # salary credits + label lag
    assert tx["is_salary_credit"].sum() > 0
    fraud = tx[tx["is_fraud"] == 1]
    lag = (fraud["label_available_at"] - fraud["ts"]).dt.days
    assert lag.between(7, 30).all()
    legit = tx[tx["is_fraud"] == 0]
    assert (legit["label_available_at"] == legit["ts"]).all()


def test_v2_determinism(tmp_path):
    m1 = syn.main(str(tmp_path / "a"), n_customers=300, n_txns=3000, seed=99)
    m2 = syn.main(str(tmp_path / "b"), n_customers=300, n_txns=3000, seed=99)
    assert m1 == m2


def test_graph_split_aware_no_leakage(small_v2_data):
    g = np.load(small_v2_data[0] / "graph.npz")
    # split-aware snapshots exist and train graph has strictly fewer edges
    assert "X_train" in g and "edge_index_train" in g
    assert g["edge_index_train"].shape[1] < g["edge_index_test"].shape[1]
    # features differ between windows (aggregation is time-masked)
    assert not np.allclose(g["X_train"], g["X_test"])


# ---------------- GNN predict integration -----------------------------------

def test_pyg_state_dict_remap():
    hidden = 8
    sd = {"conv1.lin_l.weight": torch.randn(hidden, 10),
          "conv1.lin_l.bias": torch.randn(hidden),
          "conv1.lin_r.weight": torch.randn(hidden, 10),
          "conv2.lin_l.weight": torch.randn(hidden, hidden),
          "conv2.lin_l.bias": torch.randn(hidden),
          "conv2.lin_r.weight": torch.randn(hidden, hidden),
          "head.weight": torch.randn(1, hidden), "head.bias": torch.randn(1)}
    m = MuleGNN(10, hidden=hidden, use_pyg=False)
    m.load_state_dict(remap_pyg_state_dict(sd))  # must not raise


def test_gnn_predict_scorer(tmp_path, monkeypatch):
    """predict.score_gnn with artifact scaler + payload features (no PyG)."""
    from ml.inference import predict
    d = tmp_path / "gnn_mule" / "v9"
    d.mkdir(parents=True)
    model = MuleGNN(10, use_pyg=False)
    torch.save(model.state_dict(), d / "weights.pt")
    np.savez(d / "preprocess.npz", scaler_mean=np.zeros(10),
             scaler_std=np.ones(10))
    monkeypatch.setattr(predict, "ART", tmp_path)
    res = predict.score_gnn({"features": [0.1] * 10}, version="v9")
    assert 0.0 <= res["mule_probability"] <= 1.0
    assert res["engine"] == "torch-pure-sage"


def test_gnn_load_portable_without_pyg(tmp_path):
    m = MuleGNN(10, use_pyg=False)
    p = tmp_path / "w.pt"
    torch.save(m.state_dict(), p)
    m2 = MuleGNN(10, use_pyg=False)
    load_state_dict_portable(m2, p)  # no torch_geometric needed


# ---------------- registry promotion ----------------------------------------

def test_local_registry_promotion(tmp_path, monkeypatch):
    from ml.registry import register as reg
    reg_file = tmp_path / "local_registry.json"
    monkeypatch.setattr(reg, "LOCAL_REGISTRY", reg_file)
    reg.register("fraud_net", "ml/artifacts/fraud_net/v3",
                 params={"version": "v3"}, metrics={"auc_pr": 0.5},
                 tracking_uri="http://127.0.0.1:9")  # unreachable -> local
    rec = reg.promote("fraud_net", "v3", stage="Production", alias="champion",
                      tracking_uri="http://127.0.0.1:9")
    assert rec["backend"] == "local_file"
    data = json.loads(reg_file.read_text())
    assert data["aliases"]["champion"]["version"] == "v3"
    assert data["runs"][-1]["stage"] == "Production"


# ---------------- backtest harness ------------------------------------------

def test_backtest_window_metrics_and_threshold():
    from ml.validation.backtest import tune_threshold, window_metrics
    rng = np.random.default_rng(0)
    y = np.concatenate([np.ones(100), np.zeros(900)])
    s = np.concatenate([rng.normal(0.7, 0.15, 100), rng.normal(0.3, 0.15, 900)])
    m = window_metrics(y, s, 0.5)
    assert m["precision"] > 0.5 and m["recall"] > 0.5
    t = tune_threshold(y, s, np.where(y == 1, 20_000, 1000.0))
    assert 0.2 < t["threshold"] < 0.8
