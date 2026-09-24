"""Tests for the Bayesian lane: MCMC convergence on known posteriors,
calibration end-to-end, shipped artifact loading, calibrated serving
endpoint, and graph-store graceful absence."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.bayesian import mcmc  # noqa: E402
from ml.bayesian import fraud_calibration as fc  # noqa: E402

ART = Path(__file__).resolve().parents[1] / "artifacts"


# ---------------------------------------------------------------------------
# MCMC core: recover a known Gaussian posterior
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def gaussian_posterior():
    rng = np.random.default_rng(0)
    y = rng.normal(3.0, 1.0, size=50)
    n = len(y)
    post_var = 1.0 / (n + 0.01)          # prior N(0, 10)
    post_mean = post_var * y.sum()
    return y, post_mean, post_var


def test_metropolis_hastings_recovers_gaussian(gaussian_posterior):
    y, mean_true, var_true = gaussian_posterior

    def logpost(mu):
        return -0.5 * (mu[0] / 10) ** 2 - 0.5 * np.sum((y - mu[0]) ** 2)

    res = mcmc.metropolis_hastings(logpost, np.array([0.0]), n_samples=2000,
                                   n_chains=4, burn=1500, seed=7)
    summ = mcmc.summarize(res["samples"])
    assert abs(summ["mean"][0] - mean_true) < 0.05
    assert abs(summ["sd"][0] - np.sqrt(var_true)) < 0.05
    assert summ["rhat"][0] < 1.05
    assert summ["ess"][0] > 200
    lo, hi = mcmc.credible_interval(res["samples"])
    assert lo[0] <= mean_true <= hi[0]


def test_nuts_lite_recovers_gaussian(gaussian_posterior):
    import torch
    y, mean_true, var_true = gaussian_posterior
    y_t = torch.as_tensor(y, dtype=torch.float64)

    def lp_torch(mu):
        return (-0.5 * (mu[0] / 10) ** 2
                - 0.5 * torch.sum((y_t - mu[0]) ** 2))

    res = mcmc.nuts_lite(mcmc._torch_logpost_and_grad(lp_torch),
                         np.array([0.0]), n_samples=1500, n_chains=4,
                         burn=1000, step_size=0.05, seed=11)
    summ = mcmc.summarize(res["samples"])
    assert abs(summ["mean"][0] - mean_true) < 0.05
    assert summ["rhat"][0] < 1.05
    assert summ["ess"][0] > 400  # HMC should crush random-walk ESS
    assert np.all(res["accept_rate"] > 0.5)


def test_posterior_save_load_roundtrip(tmp_path):
    samples = np.random.default_rng(1).normal(size=(4, 100, 2))
    p = mcmc.save_posterior(tmp_path / "posterior.npz", samples, ["a", "b"],
                            meta={"version": "test"})
    loaded = mcmc.load_posterior(p)
    assert np.array_equal(loaded["samples"], samples)
    assert loaded["param_names"] == ["a", "b"]
    assert loaded["meta"]["version"] == "test"


# ---------------------------------------------------------------------------
# Calibration: recover known miscalibration, end-to-end
# ---------------------------------------------------------------------------
def test_calibration_recovers_known_mapping():
    """Simulate scores from a TRUE calibration a=1.8, b=0.7; check the MCMC
    posterior recovers them and ECE improves vs the identity mapping."""
    rng = np.random.default_rng(3)
    n = 4000
    z = rng.normal(-2.5, 1.8, size=n)          # latent logit
    a_true, b_true = 1.8, 0.7
    y = (rng.uniform(size=n) < 1 / (1 + np.exp(-(a_true * z + b_true)))).astype(float)
    s_raw = 1 / (1 + np.exp(-z))               # raw score = UNcalibrated prob

    logpost = fc.make_logpost(np.log(s_raw / (1 - s_raw)), y)
    res = mcmc.metropolis_hastings(logpost, np.array([1.0, 0.0]),
                                   n_samples=1500, n_chains=4, burn=1000,
                                   proposal_scale=np.array([0.05, 0.05]), seed=5)
    summ = mcmc.summarize(res["samples"])
    assert abs(summ["mean"][0] - a_true) < 3 * summ["sd"][0] + 0.1
    assert abs(summ["mean"][1] - b_true) < 3 * summ["sd"][1] + 0.1
    assert summ["rhat"].max() < 1.1

    flat = res["samples"].reshape(-1, 2)
    p_cal = 1 / (1 + np.exp(-(flat[:, 0:1].mean() * np.log(s_raw / (1 - s_raw))
                              + flat[:, 1:2].mean())))
    ece_before = fc.expected_calibration_error(y, s_raw)
    ece_after = fc.expected_calibration_error(y, p_cal)
    assert ece_after < ece_before


@pytest.mark.skipif(not (ART / "fraud_net" / "v3").exists(),
                    reason="fraud_net v3 artifact missing")
def test_shipped_calibration_artifact_loads_and_helps():
    d = ART / "bayesian_calibration" / "v1"
    if not d.exists():
        pytest.skip("calibration artifact not fitted")
    cal = fc.BayesianCalibrator(d)
    out = cal.calibrate_one(0.5)
    assert 0.0 <= out["calibrated_probability"] <= 1.0
    assert out["ci95"][0] <= out["calibrated_probability"] <= out["ci95"][1]
    assert out["posterior_version"] == "bayesian_calibration/v1"
    m = json.loads((d / "metrics.json").read_text())
    assert m["ece_after"] <= m["ece_before"] + 1e-9
    assert max(m["rhat"]) < 1.1
    assert min(m["ess"]) > 100
    assert (d / "MODEL_CARD.md").exists()


@pytest.mark.skipif(not (ART / "mule_ring_posterior" / "v1").exists(),
                    reason="mule ring artifact not fitted")
def test_mule_ring_artifact_loads():
    d = ART / "mule_ring_posterior" / "v1"
    post = mcmc.load_posterior(d / "posterior.npz")
    assert post["samples"].shape[-1] == 5
    m = json.loads((d / "metrics.json").read_text())
    assert max(m["rhat"]) < 1.1
    assert 0.5 < m["auc_roc_posterior_mean"] <= 1.0
    acc = np.load(d / "account_posterior.npz")
    assert acc["p_mean"].shape == acc["ci95_lo"].shape == acc["ci95_hi"].shape
    assert (acc["ci95_lo"] <= acc["p_mean"] + 1e-9).all()
    assert (acc["p_mean"] <= acc["ci95_hi"] + 1e-9).all()


@pytest.mark.skipif(not (ART / "insider_risk" / "v1").exists(),
                    reason="insider risk artifact not fitted")
def test_insider_risk_artifact_shows_shrinkage():
    d = ART / "insider_risk" / "v1"
    m = json.loads((d / "metrics.json").read_text())
    assert m["rhat_max"] < 1.1
    assert m["ess_min"] > 100
    table = m["department_table"]
    pop = m["population_rate_posterior_mean"]
    # smallest department must shrink hardest toward the population rate
    small = min(table, key=lambda t: t["n_staff"])
    assert abs(small["posterior_mean_rate"] - pop) < abs(small["raw_rate"] - pop)


def test_insider_risk_fit_small_fast():
    """End-to-end hierarchical fit on a tiny synthetic ledger (fast MCMC)."""
    from ml.bayesian import insider_risk
    data = {"departments": ["a", "b", "c"],
            "n_staff": np.array([200, 10, 5]),
            "true_rates": np.array([0.02, 0.05, 0.10]),
            "y": np.array([4, 1, 1])}
    m = insider_risk.fit(version="test", n_samples=600, burn=600,
                         n_chains=2, out_dir=tmp_unused(data), data=data)
    assert m["n_departments"] == 3


def tmp_unused(data):  # helper: write test artifact under a tmp dir
    import tempfile
    return Path(tempfile.mkdtemp()) / "insider_risk" / "test"


# ---------------------------------------------------------------------------
# Graph stores: graceful absence (no server in CI)
# ---------------------------------------------------------------------------
def test_falkor_client_graceful_absence():
    from ml.graph import falkor_client
    if falkor_client.available():
        pytest.skip("FalkorDB server present — absence path not applicable")
    with pytest.raises(RuntimeError, match="cannot reach FalkorDB"):
        falkor_client.FalkorClient()


def test_neo4j_roundtrip_graceful_skip():
    from ml.graph import neo4j_roundtrip
    if neo4j_roundtrip.neo4j_available():
        res = neo4j_roundtrip.roundtrip_or_skip(
            str(Path(__file__).resolve().parents[1] / "data" / "generated"),
            max_txns=1000)
        assert res["labels_match"] and res["features_match"]
    else:
        with pytest.raises(SystemExit) as exc:
            neo4j_roundtrip.roundtrip("ml/data/generated", max_txns=10)
        assert exc.value.code == 2


# ---------------------------------------------------------------------------
# Serving: /v1/aml/score_calibrated
# ---------------------------------------------------------------------------
def test_score_calibrated_endpoint():
    serving = Path(__file__).resolve().parents[2] / "mlops" / "serving"
    sys.path.insert(0, str(serving))
    try:
        from fastapi.testclient import TestClient
        import aml_service
    except ImportError as e:
        pytest.skip(f"serving deps missing: {e}")
    with TestClient(aml_service.app) as client:
        r = client.post("/v1/aml/score_calibrated", json={
            "transaction_id": "t1", "user_id": "u1", "amount": 50000,
            "features": {"log_amount": 10.8, "sender_txns_24h": 12}})
        assert r.status_code == 200
        j = r.json()
        assert 0.0 <= j["raw_score"] <= 1.0
        assert 0.0 <= j["calibrated_probability"] <= 1.0
        assert len(j["ci95"]) == 2 and j["ci95"][0] <= j["ci95"][1]
        if (ART / "bayesian_calibration" / "v1" / "posterior.npz").exists():
            assert j["calibration_mode"] == "bayesian"
            assert j["posterior_version"] == "bayesian_calibration/v1"
        h = client.get("/health").json()
        assert "calibration_mode" in h


def test_score_calibrated_loud_fallback(monkeypatch):
    serving = Path(__file__).resolve().parents[2] / "mlops" / "serving"
    sys.path.insert(0, str(serving))
    try:
        from fastapi.testclient import TestClient
        import aml_service
    except ImportError as e:
        pytest.skip(f"serving deps missing: {e}")
    monkeypatch.setattr(aml_service, "CALIBRATION_DIR", Path("/nonexistent"))
    with TestClient(aml_service.app) as client:
        r = client.post("/v1/aml/score_calibrated", json={
            "transaction_id": "t2", "user_id": "u2", "amount": 100})
        j = r.json()
        assert j["calibration_mode"] == "uncalibrated_fallback"
        assert j["posterior_version"] is None
        assert j["ci95"][0] == j["ci95"][1]  # CI collapses onto raw score
        assert client.get("/health").json()["calibration_mode"] == "uncalibrated_fallback"
