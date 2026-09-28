"""Model-level tests for the National Fraud Intelligence layer:
generator determinism/structure, MCMC convergence diagnostics, shrinkage
direction on sparse LGAs, honest interval widening, artifact round-trip,
and shipped-artifact sanity."""
from __future__ import annotations

import json

import numpy as np
import pytest

from tests.conftest import ARTIFACT_DIR  # noqa: E402  (path setup)

from ml.bayesian import mcmc  # noqa: E402
from ml.bayesian import national_intelligence as ni  # noqa: E402

QUICK = dict(n_samples=250, burn=250, n_chains=2, seed=7)


@pytest.fixture(scope="module")
def small_data():
    return ni.synth_nigeria(seed=7, n_weeks=26)


# ---------------------------------------------------------------------------
# generator
# ---------------------------------------------------------------------------
def test_generator_deterministic(small_data):
    again = ni.synth_nigeria(seed=7, n_weeks=26)
    assert np.array_equal(small_data["y_state_week"], again["y_state_week"])
    assert np.array_equal(small_data["n_state_week"], again["n_state_week"])
    other = ni.synth_nigeria(seed=8, n_weeks=26)
    assert not np.array_equal(small_data["y_state_week"], other["y_state_week"])


def test_generator_structure(small_data):
    assert len(small_data["state_codes"]) == 37          # 36 states + FCT
    assert small_data["n_state_week"].shape == (37, 26)
    assert set(ni.PILOT_STATE_LGAS) == {"lagos", "kano", "abuja_fct"}
    assert len(ni.LAGOS_LGAS) == 20
    assert len(ni.KANO_LGAS) == 44
    assert len(ni.FCT_LGAS) == 6
    # typology counts per zone-week sum exactly to the zone's fraud count
    zones = small_data["zones"]
    for z in ni.ZONES:
        state_rows = [i for i, zz in enumerate(zones) if zz == z]
        fraud = small_data["y_state_week"][state_rows].sum(axis=0)
        assert np.array_equal(
            small_data["zone_week_typology"][z].sum(axis=1), fraud)


# ---------------------------------------------------------------------------
# fits (quick chains: diagnostics must exist and be finite; the <1.1 R-hat
# guarantee is asserted on the shipped artifact below)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def quick_fits(small_data):
    return {
        "state": ni.fit_state_model(small_data, **QUICK),
        "lga": ni.fit_lga_model(small_data, **QUICK),
        "typ": ni.fit_typology_model(small_data, n_samples=200, burn=200,
                                     n_chains=2, seed=7),
        "temp": ni.fit_temporal_model(small_data, **QUICK),
    }


def test_diagnostics_present_and_finite(quick_fits):
    for name, fit in quick_fits.items():
        rhat, ess = fit["summ"]["rhat"], fit["summ"]["ess"]
        assert np.all(np.isfinite(rhat)), name
        assert np.all(np.isfinite(ess)), name
        assert np.all(ess > 0), name
        assert np.all(fit["res"]["accept_rate"] > 0.3), name


def test_state_posterior_near_raw_aggregates(quick_fits, small_data):
    """Posterior means should track the raw rates (data are informative)."""
    fit = quick_fits["state"]
    raw = fit["y"] / fit["n"]
    post = fit["theta_post"].mean(axis=0)
    assert abs(post.mean() - raw.mean()) < 0.005
    corr = np.corrcoef(raw, post)[0, 1]
    assert corr > 0.9
    nat = fit["mu_rate_post"].mean()
    total_rate = fit["y"].sum() / fit["n"].sum()
    assert 0.3 * total_rate < nat < 3 * total_rate


def test_typology_mix_rows_sum_to_one(quick_fits):
    mix = quick_fits["typ"]["mix_post"]            # (draws, Z, K)
    assert np.allclose(mix.sum(axis=2), 1.0, atol=1e-9)
    assert (mix > 0).all()


def test_temporal_forecast_intervals(quick_fits):
    fr = quick_fits["temp"]["forecast_rate"]       # (draws, 4)
    assert fr.shape[1] == 4
    assert (fr > 0).all() and (fr < 1).all()
    lo, hi = np.quantile(fr, 0.025, axis=0), np.quantile(fr, 0.975, axis=0)
    mean = fr.mean(axis=0)
    assert np.all(lo < mean) and np.all(mean < hi)
    # honestly wide: predictive interval should span at least 0.05%
    assert (hi - lo).mean() > 5e-4


# ---------------------------------------------------------------------------
# shrinkage: sparse LGA pulled toward state mean, intervals widen honestly
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def handmade_lga_fit():
    """Hand-built deterministic LGA table. Lagos has two dense LGAs (~1%
    raw rate) and one sparse LGA with an extreme raw rate (2/30 = 6.7%/wk)
    that partial pooling must pull down toward the state mean; kano and
    abuja_fct carry moderate LGAs so the per-state dispersion is
    identifiable."""
    W = 26

    def block(n_wk, y_wk):
        return (np.full(W, n_wk, dtype=np.int64),
                np.full(W, y_wk, dtype=np.int64))

    states = {
        "lagos": [("DenseA", 20000, 200), ("DenseB", 10000, 95),
                  ("MidC", 2000, 22), ("SparseD", 30, 2)],
        "kano": [("K1", 8000, 70), ("K2", 3000, 30), ("K3", 500, 5)],
        "abuja_fct": [("F1", 9000, 95), ("F2", 2500, 28), ("F3", 400, 5)],
    }
    data = {"lga_weekly": {}}
    for code, rows in states.items():
        ns, ys, names = [], [], []
        for name, n_wk, y_wk in rows:
            n, y = block(n_wk, y_wk)
            names.append(name)
            ns.append(n)
            ys.append(y)
        data["lga_weekly"][code] = {"lga_names": names,
                                    "n": np.stack(ns), "y": np.stack(ys)}
    return ni.fit_lga_model(data, **QUICK)


def test_shrinkage_direction_on_sparse_lga(handmade_lga_fit):
    fit = handmade_lga_fit
    li = fit["lga_index"].index(("lagos", "SparseD"))
    raw = fit["y"][li] / fit["n"][li]                    # 0.0667
    shrunk = fit["theta_post"][:, li].mean()
    # lagos state mean (dense-dominated pooled rate ~0.01)
    lagos_rows = [i for i, (c, _) in enumerate(fit["lga_index"]) if c == "lagos"]
    state_pool = fit["y"][lagos_rows].sum() / fit["n"][lagos_rows].sum()
    assert abs(shrunk - state_pool) < abs(raw - state_pool)
    assert shrunk < raw                                   # pulled down


def test_intervals_widen_honestly_on_sparse_lga(handmade_lga_fit):
    fit = handmade_lga_fit
    dense = fit["lga_index"].index(("lagos", "DenseA"))
    sparse = fit["lga_index"].index(("lagos", "SparseD"))
    width = lambda i: (np.quantile(fit["theta_post"][:, i], 0.975)
                       - np.quantile(fit["theta_post"][:, i], 0.025))
    assert width(sparse) > 5 * width(dense)


# ---------------------------------------------------------------------------
# artifact round-trip + shipped artifact diagnostics
# ---------------------------------------------------------------------------
def test_posterior_artifact_round_trip(tmp_path):
    samples = np.random.default_rng(0).normal(size=(2, 50, 3))
    names = ["a", "b", "c"]
    p = mcmc.save_posterior(tmp_path / "posterior.npz", samples, names,
                            meta={"model": "t", "seed": 1})
    back = mcmc.load_posterior(p)
    assert np.array_equal(back["samples"], samples)
    assert back["param_names"] == names
    assert back["meta"] == {"model": "t", "seed": 1}


SHIPPED = pytest.mark.skipif(not (ARTIFACT_DIR / "metrics.json").exists(),
                             reason="shipped artifact not built")


@SHIPPED
def test_shipped_artifact_convergence():
    m = json.loads((ARTIFACT_DIR / "metrics.json").read_text())
    for sub in ("state_model", "lga_model", "typology_model", "temporal_model"):
        assert m[sub]["rhat_max"] < 1.1, f"{sub} R-hat {m[sub]['rhat_max']}"
        assert m[sub]["ess_min"] > 100, f"{sub} ESS {m[sub]['ess_min']}"


@SHIPPED
def test_shipped_artifact_files_load():
    post = mcmc.load_posterior(ARTIFACT_DIR / "posterior.npz")
    assert post["samples"].shape[-1] == 2 + 37
    assert post["param_names"][0] == "mu_national"
    assert post["meta"]["provenance"] == "synthetic"
    s = json.loads((ARTIFACT_DIR / "summaries.json").read_text())
    assert len(s["states"]) == 37
    assert set(s["lgas"]) == {"lagos", "kano", "abuja_fct"}
    assert len(s["lgas"]["lagos"]) == 20
    assert len(s["lgas"]["kano"]) == 44
    assert len(s["lgas"]["abuja_fct"]) == 6
    assert s["forecast"]["weeks_ahead"] == 4
    assert "synthetic" in s["provenance"]
