"""Validation tests for the full NUTS sampler (ml.bayesian.mcmc.nuts_sample).

Target: correlated 2-D Gaussian with a closed-form posterior (exact mean and
covariance known), so posterior mean/SD can be checked against ground truth.
Runtime: a few seconds (analytic gradient, small dimension).
"""
from __future__ import annotations

import numpy as np
import pytest

from ml.bayesian import mcmc

# Closed-form target: N(mu, Sigma), moderately correlated.
MU = np.array([1.5, -0.7])
SIGMA = np.array([[1.0, 0.9], [0.9, 2.0]])
PREC = np.linalg.inv(SIGMA)
TRUE_SD = np.sqrt(np.diag(SIGMA))


def gauss_logpost_and_grad(x: np.ndarray):
    d = x - MU
    return -0.5 * float(d @ PREC @ d), -PREC @ d


@pytest.fixture(scope="module")
def nuts_result():
    return mcmc.nuts_sample(
        gauss_logpost_and_grad, np.zeros(2),
        n_samples=2000, n_chains=4, burn=500, step_size=0.5, seed=3)


def test_nuts_posterior_mean(nuts_result):
    flat = nuts_result["samples"].reshape(-1, 2)
    est = flat.mean(axis=0)
    # MC error on the mean is sd / sqrt(ESS) ~ 0.02; allow generous margin.
    assert np.all(np.abs(est - MU) < 0.1), f"mean {est} vs true {MU}"


def test_nuts_posterior_sd(nuts_result):
    flat = nuts_result["samples"].reshape(-1, 2)
    est = flat.std(axis=0, ddof=1)
    assert np.all(np.abs(est - TRUE_SD) < 0.1), \
        f"sd {est} vs true {TRUE_SD}"


def test_nuts_convergence(nuts_result):
    chains = nuts_result["samples"]
    rh = mcmc.rhat(chains)
    es = mcmc.ess(chains)
    assert np.all(rh < 1.05), f"R-hat {rh}"
    assert np.all(es > 400), f"ESS {es}"


def test_nuts_divergence_tracking():
    """An absurd initial step size + tiny max_delta_h must produce tracked
    divergences (never silent)."""
    res = mcmc.nuts_sample(
        gauss_logpost_and_grad, np.zeros(2),
        n_samples=200, n_chains=2, burn=100, step_size=5.0,
        max_delta_h=1.0, seed=0)
    assert res["n_divergent"].sum() > 0


def test_nuts_determinism_and_shape():
    a = mcmc.nuts_sample(gauss_logpost_and_grad, np.zeros(2),
                         n_samples=50, n_chains=2, burn=50, seed=11)
    b = mcmc.nuts_sample(gauss_logpost_and_grad, np.zeros(2),
                         n_samples=50, n_chains=2, burn=50, seed=11)
    assert a["samples"].shape == (2, 50, 2)
    np.testing.assert_array_equal(a["samples"], b["samples"])
    assert a["sampler"] == "nuts"


def test_nuts_lite_signature_unchanged():
    """nuts_sample is an EXTENSION; existing public API must be untouched
    (another lane imports these)."""
    import inspect
    assert list(inspect.signature(mcmc.nuts_lite).parameters) == [
        "logpost_and_grad", "x0", "n_samples", "n_chains", "burn",
        "step_size", "max_leapfrog", "max_delta_h", "seed"]
    assert list(inspect.signature(mcmc.metropolis_hastings).parameters) == [
        "logpost", "x0", "n_samples", "n_chains", "burn",
        "proposal_scale", "adapt", "thin", "seed"]
