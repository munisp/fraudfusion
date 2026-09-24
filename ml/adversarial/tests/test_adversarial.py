"""Smoke tests for the adversarial robustness stack (ml/adversarial).

Fast unit tests run on synthetic tensors; the artifact integration test loads
the real fraud_net v3 weights and evaluates a small test-split sample.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from ml.adversarial import defenses, evasion_eval  # noqa: E402
from ml.data.synthetic_nigeria import NUMERIC_FEATURES  # noqa: E402


# ---------------------------------------------------------------------------
# Constraint projection
# ---------------------------------------------------------------------------

def test_projection_keeps_amounts_positive_and_flags_binary():
    n = len(NUMERIC_FEATURES)
    mean = np.zeros(n, dtype=np.float32)
    std = np.ones(n, dtype=np.float32)
    lo, hi = evasion_eval.standardized_bounds(mean, std)
    x0 = torch.full((8, n), 0.5)
    # extreme adversarial push on every feature
    x_adv = x0 + torch.full_like(x0, 100.0)
    out = evasion_eval.project_constraints(
        x_adv, x0, eps=1.0, lo=lo, hi=hi,
        mean=torch.zeros(n), std=torch.ones(n))
    # L_inf ball respected
    assert float((out - x0).abs().max()) <= 1.0 + 1e-6
    # log_amount raw value must stay >= 0 (amount positive)
    i_amount = NUMERIC_FEATURES.index("log_amount")
    assert float(out[:, i_amount].min()) >= 0.0
    # binary features snapped into {0,1}
    for f in evasion_eval.BINARY_FEATURES:
        i = NUMERIC_FEATURES.index(f)
        vals = set(out[:, i].tolist())
        assert vals <= {0.0, 1.0}, (f, vals)


def test_zero_epsilon_is_identity():
    n = len(NUMERIC_FEATURES)
    x = torch.rand(4, n)
    lo = torch.zeros(n) - 10
    hi = torch.zeros(n) + 10
    out = evasion_eval.project_constraints(
        x.clone(), x, eps=0.0, lo=lo, hi=hi,
        mean=torch.zeros(n), std=torch.ones(n), snap_binary=False)
    assert torch.allclose(out, x)


# ---------------------------------------------------------------------------
# Defense transforms
# ---------------------------------------------------------------------------

def test_clip_quantize_bounds_and_snaps():
    n = len(NUMERIC_FEATURES)
    x = torch.randn(16, n) * 10  # deliberately extreme
    out = defenses.clip_quantize(x, torch.zeros(n), torch.ones(n))
    assert float(out.abs().max()) <= 5.0 + 1e-6
    i = NUMERIC_FEATURES.index("sim_swap_7d")
    assert set(out[:, i].tolist()) <= {0.0, 1.0}


def test_rule_score_range_and_signal():
    n = len(NUMERIC_FEATURES)
    x = torch.zeros(2, n)
    i = NUMERIC_FEATURES.index("sim_swap_7d")
    x[1, i] = 1.0
    scores = defenses.rule_score(x)
    assert scores[0] == 0.0
    assert scores[1] == pytest.approx(0.35)
    assert float(scores.max()) <= 1.0


def test_smoothing_deterministic_and_bounded():
    n = len(NUMERIC_FEATURES)

    class Dummy(torch.nn.Module):
        def forward(self, x):
            return torch.zeros(len(x))

        def prob(self, x):
            return torch.full((len(x),), 0.42)

    p1 = defenses.smoothed_probs(Dummy(), torch.zeros(3, n), n_samples=4, seed=7)
    p2 = defenses.smoothed_probs(Dummy(), torch.zeros(3, n), n_samples=4, seed=7)
    assert torch.allclose(p1, p2)
    assert torch.allclose(p1, torch.full((3,), 0.42))


# ---------------------------------------------------------------------------
# Real artifact integration (smoke)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[3]
         / "ml" / "artifacts" / "fraud_net" / "v3" / "weights.pt").exists(),
    reason="fraud_net v3 artifact not present")
def test_real_artifact_fgsm_moves_scores_down_on_fraud():
    (x_std, x_cat, y, _x_raw, model, mean, std) = \
        evasion_eval.load_test_split("v3", max_samples=500, seed=0)
    wrapper = evasion_eval.NumericOnlyWrapper(model, x_cat)
    lo, hi = evasion_eval.standardized_bounds(mean, std)
    x_adv = evasion_eval.fgsm(wrapper, x_std, y, eps=0.25, lo=lo, hi=hi,
                              mean=torch.from_numpy(mean),
                              std=torch.from_numpy(std))
    assert x_adv.shape == x_std.shape
    with torch.no_grad():
        p_clean = wrapper.prob(x_std).numpy()
        p_adv = wrapper.prob(x_adv).numpy()
    fraud = y.numpy() == 1
    if fraud.any():
        # FGSM against true labels must not raise the mean fraud score
        assert p_adv[fraud].mean() <= p_clean[fraud].mean() + 1e-6
    # constraints hold on real data too
    i_amount = NUMERIC_FEATURES.index("log_amount")
    raw_amount = x_adv[:, i_amount] * std[i_amount] + mean[i_amount]
    assert float(raw_amount.min()) >= 0.0
    # clean AUC-PR should be well above the fraud base rate
    clean = evasion_eval.evaluate_probs(p_clean, y.numpy())
    assert clean["auc_pr"] > float(y.numpy().mean())
