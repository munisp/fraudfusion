"""Dependency-light MCMC toolkit (numpy only, optional torch gradients).

Implements:
  * Random-walk Metropolis-Hastings with burn-in adaptive proposal scaling.
  * ``nuts_lite``: HMC with dual-averaging step-size adaptation and a fixed
    (randomised) number of leapfrog steps per iteration. This is deliberately
    NOT the full NUTS tree recursion — it is "NUTS-lite": NUTS-style
    adaptation without dynamic tree building. Honest trade-off: for the
    low-dimensional posteriors in this lane (2–30 params) it mixes well;
    for high-dimensional or strongly correlated posteriors, production
    should swap in NumPyro/PyMC (`pip install numpyro`) behind the same
    sample/diagnostics contract.
  * Convergence diagnostics: split R-hat (Gelman/Rubin, rank-normalisation
    omitted — classic split version) and effective sample size via
    autocorrelation with Geyer initial-positive-sequence truncation.
  * Credible intervals (equal-tailed) and posterior summary.
  * Save/load posterior samples as compressed npz with JSON metadata.

All functions are deterministic given an explicit seed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import numpy as np

Array = np.ndarray
LogPost = Callable[[Array], float]


# ---------------------------------------------------------------------------
# Samplers
# ---------------------------------------------------------------------------
def metropolis_hastings(
    logpost: LogPost,
    x0: Array,
    n_samples: int = 2000,
    n_chains: int = 4,
    burn: int = 1000,
    proposal_scale: float | Array = 0.1,
    adapt: bool = True,
    thin: int = 1,
    seed: int = 0,
) -> dict:
    """Random-walk Metropolis-Hastings.

    Parameters
    ----------
    logpost : callable(x) -> log posterior density (up to a constant)
    x0 : (dim,) starting point (jittered per chain)
    n_samples : kept samples per chain (after burn and thinning)
    proposal_scale : scalar or (dim,) std of the Gaussian random walk
    adapt : tune proposal scale during burn-in towards ~0.35 acceptance
            (target for low-dim random walk; 0.234 asymptotic optimum)

    Returns dict with ``samples`` (n_chains, n_samples, dim),
    ``accept_rate`` (per chain, post-burn), ``proposal_scale`` final.
    """
    rng = np.random.default_rng(seed)
    x0 = np.asarray(x0, dtype=np.float64)
    dim = x0.size
    scale0 = np.broadcast_to(np.asarray(proposal_scale, dtype=np.float64), (dim,))

    chains, accs = [], []
    for c in range(n_chains):
        r = np.random.default_rng(seed + 1000 + c)
        x = x0 + r.normal(0, 0.05, size=dim)
        lp = float(logpost(x))
        scale = scale0.copy()
        kept = np.empty((n_samples, dim))
        n_prop = n_acc = 0
        k = 0
        total_iters = burn + n_samples * thin
        # dual-avg-lite: multiplicative adaptation in windows of 50 iters
        window_acc: list[int] = []
        for it in range(total_iters):
            prop = x + r.normal(0, 1, size=dim) * scale
            lp_prop = float(logpost(prop))
            n_prop += 1
            if np.log(r.uniform()) < lp_prop - lp:
                x, lp = prop, lp_prop
                n_acc += 1
                window_acc.append(1)
            else:
                window_acc.append(0)
            if adapt and it < burn and len(window_acc) == 50:
                rate = sum(window_acc) / 50.0
                # log-space multiplicative step, Robbins-Monro-ish decay
                gamma = min(1.0, 50.0 / (it + 50.0))
                scale *= np.exp(gamma * (rate - 0.35))
                scale = np.clip(scale, 1e-4, 1e2)
                window_acc = []
            if it >= burn and (it - burn + 1) % thin == 0 and k < n_samples:
                kept[k] = x
                k += 1
        chains.append(kept)
        accs.append(n_acc / max(n_prop, 1))
    return {"samples": np.stack(chains), "accept_rate": np.array(accs),
            "proposal_scale": scale0, "sampler": "metropolis_hastings"}


def _torch_logpost_and_grad(logpost_torch: Callable):
    """Wrap a torch log-posterior into (value, grad) numpy callables."""
    import torch

    def fn(x: Array) -> tuple[float, Array]:
        t = torch.as_tensor(np.asarray(x, dtype=np.float64)).requires_grad_(True)
        lp = logpost_torch(t)
        lp.backward()
        return float(lp.detach()), t.grad.detach().numpy().astype(np.float64)

    return fn


def nuts_lite(
    logpost_and_grad: Callable[[Array], tuple[float, Array]],
    x0: Array,
    n_samples: int = 2000,
    n_chains: int = 4,
    burn: int = 1000,
    step_size: float = 0.1,
    max_leapfrog: int = 10,
    max_delta_h: float = 1000.0,
    seed: int = 0,
) -> dict:
    """HMC with NUTS-style dual-averaging step-size adaptation and a
    randomised (1..max_leapfrog) leapfrog count — "NUTS-lite".

    ``logpost_and_grad(x)`` must return (log posterior, gradient). Use
    ``_torch_logpost_and_grad`` to derive it from a torch autograd function.

    NOT full NUTS: no tree doubling / U-turn criterion. For the posteriors
    in this lane (dim <= ~30, mild correlation) this mixes fine; swap in
    NumPyro for anything harder (documented in module docstring).
    """
    x0 = np.asarray(x0, dtype=np.float64)
    dim = x0.size

    def one_chain(c: int) -> tuple[Array, float]:
        r = np.random.default_rng(seed + 5000 + c)
        x = x0 + r.normal(0, 0.05, size=dim)
        eps = step_size
        # dual averaging state (Hoffman & Gelman 2014, target accept 0.8)
        target, mu = 0.8, np.log(10 * eps)
        h_bar, log_eps_bar = 0.0, np.log(eps)
        gamma, t0, kappa = 0.05, 10.0, 0.75
        kept = np.empty((n_samples, dim))
        n_acc = 0
        k = 0
        for it in range(burn + n_samples):
            lp_cur, g_cur = logpost_and_grad(x)
            p = r.normal(0, 1, size=dim)
            x_new, g_new = x.copy(), g_cur.copy()
            p_new = p.copy()
            L = int(r.integers(1, max_leapfrog + 1))
            # Stan-style: sample with the *current* adapted eps during
            # warmup; switch to the shrunk (averaged) eps afterwards.
            e = eps if it < burn else float(np.exp(np.clip(
                log_eps_bar, np.log(1e-5), np.log(1.0))))
            divergent = False
            for _ in range(L):
                p_new += 0.5 * e * np.clip(g_new, -1e6, 1e6)
                x_new = x_new + e * p_new
                lp_new, g_new = logpost_and_grad(x_new)
                if not np.isfinite(lp_new) or not np.all(np.isfinite(g_new)):
                    divergent = True
                    break
                p_new += 0.5 * e * np.clip(g_new, -1e6, 1e6)
            if divergent:
                accept_prob = 0.0
            else:
                ham = (lp_cur - 0.5 * p @ p) - (lp_new - 0.5 * p_new @ p_new)
                # NUTS-style divergence guard: unstable leapfrog trajectories
                # can *drop* energy astronomically (not just gain it) and be
                # accepted, teleporting the chain into the tail where it gets
                # stuck. Reject any trajectory with |dH| above the threshold.
                if not np.isfinite(ham) or abs(ham) > max_delta_h:
                    accept_prob = 0.0
                else:
                    accept_prob = min(1.0, float(np.exp(np.clip(ham, -50, 0))))
            if it < burn:
                # dual averaging update
                eta = 1.0 / (it + 1 + t0)
                h_bar = (1 - eta) * h_bar + eta * (target - accept_prob)
                log_eps = mu - np.sqrt(it + 1) / gamma * h_bar
                log_eps_bar = (it + 1) ** -kappa * log_eps + \
                    (1 - (it + 1) ** -kappa) * log_eps_bar
                eps = float(np.exp(np.clip(log_eps, np.log(1e-5), np.log(1.0))))
            if r.uniform() < accept_prob:
                x = x_new
                n_acc += 1
            if it >= burn:
                kept[k] = x
                k += 1
        return kept, n_acc / (burn + n_samples)

    chains, accs = [], []
    for c in range(n_chains):
        s, a = one_chain(c)
        chains.append(s)
        accs.append(a)
    return {"samples": np.stack(chains), "accept_rate": np.array(accs),
            "sampler": "nuts_lite"}


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
def rhat(chains: Array) -> Array:
    """Classic split R-hat per parameter. chains: (n_chains, n_samples, dim).

    Values near 1.0 (< 1.01 ideal, < 1.1 acceptable) indicate convergence.
    """
    ch = np.asarray(chains, dtype=np.float64)
    m, n, _ = ch.shape
    # split each chain in half -> 2m chains of n/2
    half = n // 2
    split = np.concatenate([ch[:, :half], ch[:, half:2 * half]], axis=0)
    m2, n2 = split.shape[0], split.shape[1]
    chain_means = split.mean(axis=1)          # (2m, dim)
    chain_vars = split.var(axis=1, ddof=1)    # (2m, dim)
    W = chain_vars.mean(axis=0)
    B = n2 * chain_means.var(axis=0, ddof=1)
    var_plus = (n2 - 1) / n2 * W + B / n2
    with np.errstate(divide="ignore", invalid="ignore"):
        r = np.sqrt(var_plus / W)
    return np.where(np.isfinite(r), r, np.nan)


def ess(chains: Array) -> Array:
    """Effective sample size per parameter via autocorrelation with
    Geyer initial-positive-sequence truncation. chains: (m, n, dim).

    Uses the Stan-style formula: ESS = m*n / (1 + 2 * sum rho_t) where the
    sum is truncated at the first negative paired autocorrelation, and rho
    uses the between/within-chain variance estimator.
    """
    ch = np.asarray(chains, dtype=np.float64)
    m, n, d = ch.shape
    chain_vars = ch.var(axis=1, ddof=1)       # (m, d)
    W = chain_vars.mean(axis=0)
    chain_means = ch.mean(axis=1)
    B = n * chain_means.var(axis=0, ddof=1) if m > 1 else np.zeros(d)
    var_plus = (n - 1) / n * W + B / n
    var_plus = np.where(var_plus <= 0, 1e-12, var_plus)

    # autocorrelation per chain via FFT, averaged across chains
    nfft = 1 << (2 * n - 1).bit_length()
    centered = ch - chain_means[:, None, :]
    f = np.fft.rfft(centered, n=nfft, axis=1)
    acov = np.fft.irfft(f * np.conjugate(f), n=nfft, axis=1)[:, :n, :].real
    acov = acov.mean(axis=0)                  # (n, d)
    acov /= np.arange(n, 0, -1)[:, None]      # unbiased-ish normalisation
    rho = 1.0 - (W[None, :] - acov) / var_plus[None, :]

    out = np.empty(d)
    for j in range(d):
        s = 0.0
        t = 1
        while t + 1 < n:
            pair = rho[t, j] + rho[t + 1, j]
            if pair < 0:
                break
            s += pair
            t += 2
        tau = max(1.0 + 2.0 * s, 1.0)
        out[j] = m * n / tau
    return np.minimum(out, m * n * 10)  # cap absurd super-efficiency


def credible_interval(samples: Array, prob: float = 0.95) -> tuple[Array, Array]:
    """Equal-tailed credible interval over flattened samples (…, dim)."""
    s = np.asarray(samples, dtype=np.float64).reshape(-1, samples.shape[-1])
    lo = np.quantile(s, (1 - prob) / 2, axis=0)
    hi = np.quantile(s, 1 - (1 - prob) / 2, axis=0)
    return lo, hi


def summarize(samples: Array, prob: float = 0.95) -> dict:
    """Posterior summary per parameter: mean, sd, CI, plus rhat/ess if
    given (chains, n, dim)."""
    s = np.asarray(samples, dtype=np.float64)
    flat = s.reshape(-1, s.shape[-1])
    lo, hi = credible_interval(flat, prob)
    out = {"mean": flat.mean(axis=0), "sd": flat.std(axis=0, ddof=1),
           f"ci{int(prob * 100)}_lo": lo, f"ci{int(prob * 100)}_hi": hi,
           "n_samples": int(flat.shape[0])}
    if s.ndim == 3 and s.shape[0] > 1:
        out["rhat"] = rhat(s)
        out["ess"] = ess(s)
    return out


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def save_posterior(path: str | Path, samples: Array, param_names: list[str],
                   meta: dict | None = None) -> Path:
    """Save posterior samples + metadata to a compressed npz."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path, samples=np.asarray(samples, dtype=np.float64),
        param_names=np.array(param_names),
        meta_json=np.array(json.dumps(meta or {})))
    return path


def load_posterior(path: str | Path) -> dict:
    """Load a posterior npz written by :func:`save_posterior`."""
    z = np.load(Path(path), allow_pickle=False)
    return {"samples": z["samples"],
            "param_names": [str(p) for p in z["param_names"]],
            "meta": json.loads(str(z["meta_json"]))}
