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
# Full NUTS (multinomial, recursive tree building)
# ---------------------------------------------------------------------------
class _TreeState:
    """State of one (sub-)tree in the NUTS recursion (mirrors Stan's
    ``base_nuts::build_tree`` outputs).

    Carries the integration-direction endpoints (position, momentum,
    gradient) for continuation, the junction/outer endpoint momenta for the
    generalized U-turn criterion, the summed momentum ``rho`` over all
    visited non-divergent states, the log-sum-exp trajectory weight
    (``H0 - H`` per state), the multinomial candidate drawn from the
    subtree, stop/divergence flags, and the Metropolis-acceptance
    accumulators used by dual averaging.
    """

    __slots__ = ("x_end", "p_end", "g_end", "p_beg_out", "p_end_out",
                 "rho", "w", "cand", "s", "divergent", "alpha_sum", "n_lf")

    def __init__(self, x_end, p_end, g_end, p_beg_out, p_end_out, rho, w,
                 cand, s, divergent, alpha_sum, n_lf):
        self.x_end = x_end          # continuation state (integration end)
        self.p_end = p_end
        self.g_end = g_end
        self.p_beg_out = p_beg_out  # momentum at subtree beginning (junction)
        self.p_end_out = p_end_out  # momentum at subtree end (outer)
        self.rho = rho              # summed momentum of visited states
        self.w = w                  # log-sum-exp of (joint - joint0) weights
        self.cand = cand            # multinomial candidate from the subtree
        self.s = s                  # False -> stop doubling
        self.divergent = divergent
        self.alpha_sum = alpha_sum  # sum of min(1, exp(joint - joint0))
        self.n_lf = n_lf            # number of leapfrog steps taken


def _nuts_leapfrog(fn, x: Array, p: Array, g: Array, eps: float
                   ) -> tuple[Array, Array, Array, float]:
    """One leapfrog step; returns (x', p', g', logpost'). Non-finite results
    are returned as-is and handled by the caller (divergence)."""
    p_half = p + 0.5 * eps * np.clip(g, -1e6, 1e6)
    x_new = x + eps * p_half
    lp_new, g_new = fn(x_new)
    p_new = p_half + 0.5 * eps * np.clip(g_new, -1e6, 1e6)
    return x_new, p_new, g_new, lp_new


def _logaddexp(a: float, b: float) -> float:
    if a == -np.inf:
        return b
    if b == -np.inf:
        return a
    m = max(a, b)
    return m + float(np.log(np.exp(a - m) + np.exp(b - m)))


def _nuts_criterion(p_a: Array, p_b: Array, rho: Array) -> bool:
    """Generalized U-turn criterion (Stan's ``compute_criterion``):
    continue only while both endpoint momenta point along the summed
    trajectory momentum."""
    return float(p_a @ rho) > 0.0 and float(p_b @ rho) > 0.0


def _nuts_build_tree(fn, x: Array, p: Array, g: Array, depth: int,
                     sign: int, eps: float, joint0: float,
                     max_delta_h: float,
                     rng: np.random.Generator) -> _TreeState:
    """Recursive tree doubling (Hoffman & Gelman 2014 Fig. 3 recursion with
    Stan's multinomial weighting and generalized U-turn criterion).

    Every visited state contributes weight exp(joint - joint0) to the
    subtree weight (multinomial-over-trajectory formulation, equivalent to
    slice sampling). A state with energy error ``joint0 - joint >
    max_delta_h`` (or non-finite) is a divergence: it stops the tree.
    """
    if depth == 0:
        # Base case: single leapfrog in direction `sign`.
        x1, p1, g1, lp1 = _nuts_leapfrog(fn, x, p, g, sign * eps)
        joint1 = lp1 - 0.5 * float(p1 @ p1)
        if not (np.isfinite(joint1) and np.all(np.isfinite(x1))):
            joint1 = -np.inf
        d_e = joint1 - joint0  # = H0 - H1
        divergent = d_e < -max_delta_h  # includes -inf
        alpha = min(1.0, float(np.exp(d_e))) if np.isfinite(d_e) else 0.0
        return _TreeState(x1, p1, g1, p1.copy(), p1.copy(), p1.copy(),
                          d_e, x1, not divergent, divergent, alpha, 1)

    # Recursion: build the initial half, then the final half.
    left = _nuts_build_tree(fn, x, p, g, depth - 1, sign, eps, joint0,
                            max_delta_h, rng)
    if not left.s:
        return left
    right = _nuts_build_tree(fn, left.x_end, left.p_end, left.g_end,
                             depth - 1, sign, eps, joint0, max_delta_h, rng)
    if not right.s:
        # propagate the stop; keep acceptance accumulators from both halves
        right.alpha_sum += left.alpha_sum
        right.n_lf += left.n_lf
        right.divergent = right.divergent or left.divergent
        return right

    # Multinomial candidate: draw the final half's candidate with
    # probability proportional to its total weight.
    w = _logaddexp(left.w, right.w)
    if right.w > w or np.log(rng.uniform()) < right.w - w:
        cand = right.cand
    else:
        cand = left.cand
    rho = left.rho + right.rho
    # Generalized U-turn: around the merged subtree and between the halves.
    s = _nuts_criterion(left.p_beg_out, right.p_end_out, rho)
    s &= _nuts_criterion(left.p_beg_out, right.p_beg_out,
                         left.rho + right.p_beg_out)
    s &= _nuts_criterion(left.p_end_out, right.p_end_out,
                         right.rho + left.p_end_out)
    return _TreeState(right.x_end, right.p_end, right.g_end,
                      left.p_beg_out, right.p_end_out, rho, w, cand, s,
                      left.divergent or right.divergent,
                      left.alpha_sum + right.alpha_sum,
                      left.n_lf + right.n_lf)


def nuts_sample(
    logpost_and_grad: Callable[[Array], tuple[float, Array]],
    x0: Array,
    n_samples: int = 1000,
    n_chains: int = 4,
    burn: int = 500,
    step_size: float = 1.0,
    max_depth: int = 10,
    max_delta_h: float = 1000.0,
    target_accept: float = 0.8,
    seed: int = 0,
) -> dict:
    """Full NUTS: multinomial No-U-Turn Sampler with recursive tree building.

    Unlike :func:`nuts_lite` (fixed random leapfrog count), this implements
    the actual NUTS algorithm, mirroring Stan's ``base_nuts``:

    * recursive binary-tree doubling (:func:`_nuts_build_tree`) up to
      ``max_depth`` (default 10 -> trajectories of up to 2**10 leapfrogs),
    * generalized U-turn termination on momentum dot products:
      ``p_endpoint . rho > 0`` where ``rho`` is the summed momentum over the
      (sub-)trajectory (Betancourt 2017; required for the multinomial
      variant — the endpoint-momentum criterion of the original paper is
      only valid with uniform-over-slice candidate selection),
    * multinomial candidate selection over the trajectory with weights
      ``exp(joint - joint0)``,
    * divergence tracking: states with energy error above ``max_delta_h``
      stop the tree and are counted in ``n_divergent``,
    * dual-averaging step-size adaptation towards ``target_accept`` during
      warmup (Hoffman & Gelman 2014, sec. 3.2.1); after warmup the chain
      runs at the shrunk (averaged) step size.

    Returns dict with ``samples`` (n_chains, n_samples, dim),
    ``accept_stat`` (per-chain mean Metropolis accept statistic),
    ``n_divergent`` (per chain, post-warmup), ``step_size`` (final adapted
    per chain), ``n_leapfrog`` (mean per iteration), ``max_depth`` and
    ``sampler="nuts"``. Deterministic given ``seed``.
    """
    x0 = np.asarray(x0, dtype=np.float64)
    dim = x0.size

    def one_chain(c: int) -> tuple[Array, float, int, float, float]:
        r = np.random.default_rng(seed + 7000 + c)
        x = x0 + r.normal(0, 0.05, size=dim)
        eps = step_size
        # dual-averaging state (Hoffman & Gelman 2014)
        mu = np.log(10 * eps)
        h_bar, log_eps_bar = 0.0, np.log(eps)
        gamma, t0, kappa = 0.05, 10.0, 0.75
        kept = np.empty((n_samples, dim))
        alpha_stats: list[float] = []
        lf_counts: list[int] = []
        n_div = 0
        k = 0
        for it in range(burn + n_samples):
            lp_cur, g_cur = logpost_and_grad(x)
            p0 = r.normal(0, 1, size=dim)
            joint0 = lp_cur - 0.5 * float(p0 @ p0)
            e = eps if it < burn else float(np.exp(np.clip(
                log_eps_bar, np.log(1e-6), np.log(10.0))))

            # forward/backward endpoints of the accumulated trajectory
            x_fwd = x_bck = x.copy()
            g_fwd = g_bck = g_cur.copy()
            p_ff = p0.copy()   # momentum at outer end of forward part
            p_fb = p0.copy()   # momentum at junction of forward part
            p_bb = p0.copy()   # momentum at outer end of backward part
            p_bf = p0.copy()   # momentum at junction of backward part
            rho = p0.copy()    # summed momentum over the whole trajectory
            w_total = 0.0      # log(exp(joint0 - joint0)) = 0
            cand = x.copy()
            alpha_sum, n_lf = 0.0, 0
            divergent_iter = False
            for depth in range(max_depth):
                if r.uniform() > 0.5:
                    # extend forward
                    rho_bck = rho.copy()
                    p_bf = p_ff.copy()
                    sub = _nuts_build_tree(
                        logpost_and_grad, x_fwd, p_ff, g_fwd, depth, 1, e,
                        joint0, max_delta_h, r)
                    alpha_sum += sub.alpha_sum
                    n_lf += sub.n_lf
                    divergent_iter = divergent_iter or sub.divergent
                    if not sub.s:
                        break
                    x_fwd, p_fb, p_ff, g_fwd =                         sub.x_end, sub.p_beg_out, sub.p_end_out, sub.g_end
                    rho_fwd = sub.rho
                else:
                    # extend backward
                    rho_fwd = rho.copy()
                    p_fb = p_bb.copy()
                    sub = _nuts_build_tree(
                        logpost_and_grad, x_bck, p_bb, g_bck, depth, -1, e,
                        joint0, max_delta_h, r)
                    alpha_sum += sub.alpha_sum
                    n_lf += sub.n_lf
                    divergent_iter = divergent_iter or sub.divergent
                    if not sub.s:
                        break
                    x_bck, p_bf, p_bb, g_bck =                         sub.x_end, sub.p_beg_out, sub.p_end_out, sub.g_end
                    rho_bck = sub.rho

                # multinomial accept of the subtree's candidate
                if sub.w > w_total or np.log(r.uniform()) < sub.w - w_total:
                    cand = sub.cand
                w_total = _logaddexp(w_total, sub.w)
                rho = rho_bck + rho_fwd
                # generalized U-turn on the merged trajectory
                persist = _nuts_criterion(p_bb, p_ff, rho)
                persist &= _nuts_criterion(p_bb, p_fb, rho_bck + p_fb)
                persist &= _nuts_criterion(p_bf, p_ff, rho_fwd + p_bf)
                if not persist:
                    break

            x = cand
            accept_stat = alpha_sum / n_lf if n_lf else 0.0
            alpha_stats.append(accept_stat)
            lf_counts.append(n_lf)
            if divergent_iter and it >= burn:
                n_div += 1
            if it < burn:
                eta = 1.0 / (it + 1 + t0)
                h_bar = (1 - eta) * h_bar + eta * (target_accept - accept_stat)
                log_eps = mu - np.sqrt(it + 1) / gamma * h_bar
                log_eps_bar = (it + 1) ** -kappa * log_eps + \
                    (1 - (it + 1) ** -kappa) * log_eps_bar
                eps = float(np.exp(np.clip(log_eps, np.log(1e-6),
                                           np.log(10.0))))
            else:
                kept[k] = x
                k += 1
        final_eps = float(np.exp(np.clip(log_eps_bar, np.log(1e-6),
                                         np.log(10.0))))
        return (kept, float(np.mean(alpha_stats)), n_div, final_eps,
                float(np.mean(lf_counts)))

    chains, accs, divs, epss, lfs = [], [], [], [], []
    for c in range(n_chains):
        s, a, nd, e, lf = one_chain(c)
        chains.append(s)
        accs.append(a)
        divs.append(nd)
        epss.append(e)
        lfs.append(lf)
    return {"samples": np.stack(chains), "accept_stat": np.array(accs),
            "n_divergent": np.array(divs), "step_size": np.array(epss),
            "n_leapfrog": np.array(lfs), "max_depth": max_depth,
            "sampler": "nuts"}


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
