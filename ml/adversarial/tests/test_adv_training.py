"""Tests for adversarial training (adv_train -> fraud_net v4) and the
gradient-masking-aware attacks (BPDA-lite / EOT) in defenses.py.

Fast unit tests use synthetic tensors; artifact tests load the shipped v4
artifact produced by `python -m ml.adversarial.adv_train`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from ml.adversarial import adv_train, defenses, evasion_eval  # noqa: E402
from ml.data.synthetic_nigeria import NUMERIC_FEATURES  # noqa: E402
from ml.models.fraud_net import FraudNet, cardinalities  # noqa: E402

V4_DIR = evasion_eval.ART_ROOT / "v4"


def _toy_wrapper(n: int, seed: int = 0):
    """Tiny linear 'model' behind the NumericOnlyWrapper interface."""
    g = torch.Generator().manual_seed(seed)

    class Toy(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.w = torch.nn.Parameter(torch.randn(n, generator=g))

        def calibrated_logits(self, x_num, x_cat):
            return x_num @ self.w

    wrapper = evasion_eval.NumericOnlyWrapper(
        Toy(), torch.zeros(4, 5, dtype=torch.long))
    return wrapper.eval()


def _bounds(n: int):
    lo = torch.full((n,), -3.0)
    hi = torch.full((n,), 3.0)
    mean = torch.zeros(n)
    std = torch.ones(n)
    return lo, hi, mean, std


def test_eot_pgd_respects_constraints():
    n = len(NUMERIC_FEATURES)
    wrapper = _toy_wrapper(n)
    x = torch.rand(4, n)
    # binary features must start in {0,1} (as real data does — the
    # projection's snap is then a no-op and the L_inf ball is respected)
    for i, f in enumerate(NUMERIC_FEATURES):
        if f in evasion_eval.BINARY_FEATURES:
            x[:, i] = torch.round(x[:, i])
    y = torch.ones(4)
    lo, hi, mean, std = _bounds(n)
    # eps=1.0: a binary flip (delta=1) is exactly on the L_inf boundary;
    # the projection's snap-to-{0,1} then stays inside the ball.
    x_adv = defenses.eot_pgd(wrapper, x, y, eps=1.0, steps=3, lo=lo, hi=hi,
                             mean=mean, std=std, sigma=0.1, n_samples=4)
    assert float((x_adv - x).abs().max()) <= 1.0 + 1e-6
    assert float(x_adv.min()) >= -3.0 and float(x_adv.max()) <= 3.0


def test_eot_pgd_moves_score_down_for_fraud():
    """EOT attack on a fraud example must lower the smoothed score."""
    n = len(NUMERIC_FEATURES)
    wrapper = _toy_wrapper(n, seed=1)
    x = torch.rand(4, n)
    for i, f in enumerate(NUMERIC_FEATURES):
        if f in evasion_eval.BINARY_FEATURES:
            x[:, i] = torch.round(x[:, i])
    y = torch.ones(4)
    lo, hi, mean, std = _bounds(n)
    x_adv = defenses.eot_pgd(wrapper, x, y, eps=1.0, steps=10, lo=lo, hi=hi,
                             mean=mean, std=std, sigma=0.1, n_samples=4)
    clean = defenses.smoothed_logits(wrapper, x, 0.1, 4).mean()
    adv = defenses.smoothed_logits(wrapper, x_adv, 0.1, 4).mean()
    assert adv < clean


def test_bpda_lite_matches_plain_pgd_perturbation():
    """BPDA-lite uses the identity-approximation gradient, so its
    perturbation equals plain PGD's given the same seed."""
    n = len(NUMERIC_FEATURES)
    wrapper = _toy_wrapper(n)
    x = torch.rand(4, n)
    for i, f in enumerate(NUMERIC_FEATURES):
        if f in evasion_eval.BINARY_FEATURES:
            x[:, i] = torch.round(x[:, i])
    y = torch.ones(4)
    lo, hi, mean, std = _bounds(n)
    torch.manual_seed(7)
    x_bpda = defenses.bpda_lite_pgd(wrapper, x, y, 0.5, 5, lo, hi, mean, std)
    torch.manual_seed(7)
    x_pgd = evasion_eval.pgd(wrapper, x, y, 0.5, 5, lo, hi, mean, std)
    assert torch.allclose(x_bpda, x_pgd)


@pytest.mark.skipif(not V4_DIR.exists(),
                    reason="v4 artifact not trained yet")
def test_v4_artifact_contract():
    """v4 must be a drop-in fraud_net artifact: same vocab/scaler contract,
    loadable weights, probabilities in [0,1], metrics present."""
    vocab = json.loads((V4_DIR / "vocab.json").read_text())
    v3_vocab = json.loads(
        (evasion_eval.ART_ROOT / "v3" / "vocab.json").read_text())
    assert vocab == v3_vocab, "v4 vocab must match v3 (serving contract)"
    pre = np.load(V4_DIR / "preprocess.npz")
    assert pre["scaler_mean"].shape[0] == len(NUMERIC_FEATURES)
    model = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
    model.load_state_dict(torch.load(V4_DIR / "weights.pt",
                                     weights_only=True))
    model.eval()
    with torch.no_grad():
        p = model.prob(torch.zeros(2, len(NUMERIC_FEATURES)),
                       torch.zeros(2, 5, dtype=torch.long))
    assert p.shape == (2,)
    assert torch.all((p >= 0) & (p <= 1))
    metrics = json.loads((V4_DIR / "metrics.json").read_text())
    for key in ("auc_pr", "auc_roc", "pgd_eps1", "init_version",
                "train_runtime_s"):
        assert key in metrics, key
    assert metrics["init_version"] == "v3"
    assert (V4_DIR / "MODEL_CARD.md").exists()


@pytest.mark.skipif(not (V4_DIR / "model.onnx").exists(),
                    reason="v4 ONNX not exported in this environment")
def test_v4_onnx_matches_torch():
    """ONNX export must agree with torch weights on the same inputs."""
    import onnxruntime as ort
    model, vocab, mean, std = evasion_eval.load_artifact("v4")
    rng = np.random.default_rng(0)
    x_num = rng.normal(size=(8, len(NUMERIC_FEATURES))).astype(np.float32)
    x_cat = np.zeros((8, 5), dtype=np.int64)
    sess = ort.InferenceSession(str(V4_DIR / "model.onnx"),
                                providers=["CPUExecutionProvider"])
    p_onnx = sess.run(None, {"x_num": x_num, "x_cat": x_cat})[0].reshape(-1)
    with torch.no_grad():
        p_torch = model.prob(torch.from_numpy(x_num),
                             torch.from_numpy(x_cat)).numpy()
    np.testing.assert_allclose(p_onnx, p_torch, atol=1e-5)


def test_adv_train_smoke_deterministic(tmp_path, monkeypatch):
    """One adversarial-training step on a tiny subsample must run and be
    deterministic given the seed (mechanics test, not a quality gate)."""
    orig = adv_train.load_split

    def tiny(name, vocab, mean, std):
        xn, xc, y = orig(name, vocab, mean, std)
        return xn[:512], xc[:512], y[:512]

    monkeypatch.setattr(adv_train, "load_split", tiny)
    m1, meta1, *_ = adv_train.adv_train(epochs=1, batch_size=256,
                                        pgd_steps=2, seed=0)
    sd1 = {k: v.clone() for k, v in m1.state_dict().items()}
    m2, meta2, *_ = adv_train.adv_train(epochs=1, batch_size=256,
                                        pgd_steps=2, seed=0)
    for k, v in m2.state_dict().items():
        assert torch.allclose(sd1[k], v), f"non-deterministic param {k}"
    assert meta1["init_version"] == "v3"
