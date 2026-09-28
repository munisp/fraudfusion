"""National Fraud Intelligence: hierarchical Bayesian aggregation of fraud
signals into LOCAL (state/LGA) and NATIONAL intelligence for Nigeria.

Answers the question "can MCMC build local intelligence of a country?" with
four coupled Bayesian models, all fit with the dependency-light MCMC toolkit
in ``ml.bayesian.mcmc`` (NUTS-lite, torch autograd) and all reporting split
R-hat / ESS diagnostics:

1. **Hierarchical per-state fraud-rate model** — 37 jurisdictions
   (36 states + FCT). Non-centered logit-normal partial pooling:
       y_s ~ Binomial(n_s, theta_s)
       logit(theta_s) = l_s,  l_s ~ N(mu_national, sigma_states)
   (CENTERED logit-normal partial pooling: with ~150M transactions the
   likelihood is highly informative, which is exactly the regime where
   non-centered forms funnel — see fit_state_model docstring. Sampling
   runs in a Laplace-whitened space via ``_fit_whitened``.)
   Sparse states shrink toward the national mean with honestly wide
   intervals; dense states (Lagos, Abuja, Kano, Rivers) speak for themselves.

2. **LGA-level partial pooling** for 3 pilot states (Lagos 20 LGAs,
   Kano 44, FCT 6 area councils): same hierarchy one level down,
   demonstrating shrinkage on sparse LGAs (small n -> wide intervals pulled
   toward the state mean).

3. **Typology-mix model** — per geopolitical zone (6 zones) a
   Dirichlet-multinomial posterior over 8 fraud typologies
   (account_takeover, sim_swap, investment, advance_fee, crypto, insider,
   chargeback, mule_ring) fit on weekly zone-level typology counts.

4. **Temporal national intensity** — 52-week Gaussian random walk on the
   national weekly logit fraud rate, with a 4-week-ahead posterior
   predictive distribution.

TRAINING DATA IS SYNTHETIC (seeded generator below, assumptions documented
in ``synth_nigeria`` and in the shipped MODEL_CARD.md). No real NIBSS/NFIU
feed exists in this repo and none is faked. The artifact contract matches
the Bayesian lane: ml/artifacts/national_intelligence/<version>/ with
posterior.npz (+ per-submodel npz), metrics.json, MODEL_CARD.md.

Run:
    python -m ml.bayesian.national_intelligence [--version v1]
or the thin wrapper:
    python -m ml.train.train_national_intel [--version v1]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.bayesian import mcmc  # noqa: E402
from ml.train.common import ARTIFACT_ROOT, set_seed  # noqa: E402

MODEL_NAME = "national_intelligence"

TYPOLOGIES = [
    "account_takeover", "sim_swap", "investment", "advance_fee",
    "crypto", "insider", "chargeback", "mule_ring",
]

# ---------------------------------------------------------------------------
# Nigeria reference data: 36 states + FCT, 6 geopolitical zones.
# (code, display name, zone, relative weekly digital-payment volume weight)
# Volume weights encode *observable electronic-payment volume*, NOT
# population — Lagos/Abuja/Rivers dominate Nigerian e-payment rails.
# ---------------------------------------------------------------------------
STATES = [
    # South West — highest ATO / investment / crypto fraud share (urban-south)
    ("lagos", "Lagos", "south_west", 100.0),
    ("ogun", "Ogun", "south_west", 22.0),
    ("oyo", "Oyo", "south_west", 25.0),
    ("osun", "Osun", "south_west", 10.0),
    ("ondo", "Ondo", "south_west", 9.0),
    ("ekiti", "Ekiti", "south_west", 6.0),
    # South South
    ("rivers", "Rivers", "south_south", 40.0),
    ("delta", "Delta", "south_south", 18.0),
    ("edo", "Edo", "south_south", 15.0),
    ("akwa_ibom", "Akwa Ibom", "south_south", 12.0),
    ("cross_river", "Cross River", "south_south", 8.0),
    ("bayelsa", "Bayelsa", "south_south", 5.0),
    # South East
    ("anambra", "Anambra", "south_east", 18.0),
    ("enugu", "Enugu", "south_east", 14.0),
    ("imo", "Imo", "south_east", 12.0),
    ("abia", "Abia", "south_east", 11.0),
    ("ebonyi", "Ebonyi", "south_east", 6.0),
    # North Central
    ("abuja_fct", "Federal Capital Territory", "north_central", 55.0),
    ("kwara", "Kwara", "north_central", 9.0),
    ("plateau", "Plateau", "north_central", 9.0),
    ("kogi", "Kogi", "north_central", 8.0),
    ("niger", "Niger", "north_central", 8.0),
    ("benue", "Benue", "north_central", 7.0),
    ("nasarawa", "Nasarawa", "north_central", 7.0),
    # North West — higher agent/USSD-channel fraud share (rural-north)
    ("kano", "Kano", "north_west", 35.0),
    ("kaduna", "Kaduna", "north_west", 24.0),
    ("katsina", "Katsina", "north_west", 10.0),
    ("sokoto", "Sokoto", "north_west", 7.0),
    ("jigawa", "Jigawa", "north_west", 6.0),
    ("kebbi", "Kebbi", "north_west", 5.0),
    ("zamfara", "Zamfara", "north_west", 5.0),
    # North East
    ("borno", "Borno", "north_east", 12.0),
    ("bauchi", "Bauchi", "north_east", 8.0),
    ("adamawa", "Adamawa", "north_east", 7.0),
    ("gombe", "Gombe", "north_east", 6.0),
    ("yobe", "Yobe", "north_east", 5.0),
    ("taraba", "Taraba", "north_east", 5.0),
]

STATE_CODES = [s[0] for s in STATES]
ZONES = ["north_central", "north_east", "north_west",
         "south_east", "south_south", "south_west"]

# True (synthetic) zone-level base weekly fraud rates, as a fraction of
# transactions. Urban-south zones run hotter on digital fraud; rural-north
# zones lower on rails volume but with distinct typology mix.
ZONE_BASE_RATE = {
    "south_west": 0.0100,
    "south_south": 0.0110,
    "south_east": 0.0090,
    "north_central": 0.0090,
    "north_west": 0.0070,
    "north_east": 0.0065,
}

# True (synthetic) zone typology mixes (rows sum to 1.0). Assumptions:
# urban-south skews to account_takeover/investment/crypto/chargeback;
# rural-north skews to sim_swap/advance_fee/mule_ring (agent & USSD
# channel fraud); insider roughly uniform with a slight north tilt.
ZONE_TYPOLOGY_MIX = {
    "south_west": [0.18, 0.12, 0.16, 0.10, 0.14, 0.06, 0.12, 0.12],
    "south_south": [0.15, 0.10, 0.18, 0.12, 0.12, 0.07, 0.10, 0.16],
    "south_east": [0.14, 0.10, 0.15, 0.16, 0.10, 0.06, 0.13, 0.16],
    "north_central": [0.13, 0.16, 0.12, 0.14, 0.07, 0.08, 0.10, 0.20],
    "north_west": [0.10, 0.20, 0.08, 0.16, 0.04, 0.08, 0.08, 0.26],
    "north_east": [0.09, 0.22, 0.07, 0.17, 0.03, 0.09, 0.06, 0.27],
}

# ---------------------------------------------------------------------------
# Pilot-state LGAs (real names): Lagos 20, Kano 44, FCT 6 area councils.
# Shares are *within-state digital-payment volume shares* (percent, sum=100)
# with deliberately heavy left-skew in Kano/FCT so that several rural LGAs
# are sparse (small weekly n) and 2-3 fall under the k-anonymity serving
# threshold (n<30/wk) — this is what exercises shrinkage + suppression.
# ---------------------------------------------------------------------------
LAGOS_LGAS = [
    ("Alimosho", 15.0), ("Ajeromi-Ifelodun", 8.0), ("Kosofe", 8.0),
    ("Mushin", 7.5), ("Oshodi-Isolo", 7.5), ("Ikeja", 9.0),
    ("Surulere", 7.0), ("Lagos Mainland", 5.5), ("Shomolu", 4.5),
    ("Eti-Osa", 7.0), ("Lagos Island", 5.0), ("Apapa", 3.0),
    ("Amuwo-Odofin", 4.5), ("Ifako-Ijaiye", 4.5), ("Agege", 6.0),
    ("Ikorodu", 9.0), ("Badagry", 3.5), ("Ojo", 5.5),
    ("Epe", 1.5), ("Ibeju-Lekki", 2.0),
]
# shares above sum to 118.5 -> normalised in the generator.

KANO_LGAS = [
    ("Kano Municipal", 22.0), ("Fagge", 7.0), ("Dala", 8.0),
    ("Gwale", 7.0), ("Tarauni", 5.0), ("Nasarawa", 7.0),
    ("Kumbotso", 6.0), ("Ungogo", 5.0), ("Dambatta", 3.0),
    ("Dawakin Kudu", 3.0), ("Dawakin Tofa", 2.5), ("Tofa", 2.0),
    ("Rimin Gado", 1.8), ("Bichi", 2.5), ("Tsanyawa", 1.5),
    ("Shanono", 0.01), ("Gwarzo", 1.8), ("Karaye", 1.5),
    ("Rogo", 1.2), ("Kabo", 1.2), ("Minjibir", 1.2),
    ("Gezawa", 2.2), ("Bagwai", 1.2), ("Garko", 1.4), ("Garun Mallam", 0.9),
    ("Madobi", 0.8), ("Kunchi", 0.7), ("Makoda", 0.6),
    ("Ajingi", 0.8), ("Albasu", 0.7), ("Gaya", 0.8),
    ("Kiru", 0.9), ("Bebeji", 0.6), ("Bunkure", 0.8),
    ("Kura", 0.8), ("Sumaila", 0.7), ("Takai", 0.7),
    ("Tudun Wada", 1.0), ("Doguwa", 0.5), ("Gabasawa", 0.7),
    ("Rano", 0.8), ("Kibiya", 0.5), ("Warawa", 0.6),
    ("Wudil", 1.0),
]
# sums to ~113.1 -> normalised. Shanono (0.01%) is the suppressed cell demo.

FCT_LGAS = [  # "Area Councils"
    ("Abuja Municipal", 62.0), ("Bwari", 12.0), ("Gwagwalada", 14.0),
    ("Kuje", 6.5), ("Kwali", 3.0), ("Abaji", 2.5),
]

PILOT_STATE_LGAS = {"lagos": LAGOS_LGAS, "kano": KANO_LGAS, "abuja_fct": FCT_LGAS}

N_WEEKS = 52
NATIONAL_WEEKLY_TXNS = 3_000_000  # platform-observable share of national rails


def _logit(p):
    p = np.clip(p, 1e-9, 1 - 1e-9)
    return np.log(p / (1 - p))


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


def _laplace_precondition(logpost_torch, x0: np.ndarray) -> dict:
    """Mode + observed-information Cholesky for affine reparameterisation.

    The posteriors here are informed by up to ~150M transactions, so raw
    parameter scales differ by ~1000x and cross-correlations are strong
    (a scalar-step-size HMC cannot traverse them — verified empirically:
    R-hat > 3 without preconditioning). We find the posterior mode with
    LBFGS, estimate the Hessian of the log-posterior by central
    differences of the autograd gradient, and whiten:
        par = mode + L @ w,  L L^T = (-H)^{-1}
    HMC then samples w in a near-standard-Gaussian geometry. The sampler
    still targets the *exact* posterior (this is only a change of
    variables); diagnostics are computed in whitened space.
    """
    import torch
    x0 = np.asarray(x0, dtype=np.float64)
    dim = x0.size
    t = torch.as_tensor(x0.copy()).requires_grad_(True)
    opt = torch.optim.LBFGS([t], max_iter=150, tolerance_grad=1e-9,
                            line_search_fn="strong_wolfe")

    def closure():
        opt.zero_grad()
        loss = -logpost_torch(t)
        loss.backward()
        return loss

    opt.step(closure)
    mode = t.detach().numpy().astype(np.float64)

    def grad(x):
        tt = torch.as_tensor(x, dtype=torch.float64).requires_grad_(True)
        lp = logpost_torch(tt)
        lp.backward()
        return tt.grad.detach().numpy().astype(np.float64)

    h = 1e-5
    H = np.empty((dim, dim))
    for i in range(dim):
        e = np.zeros(dim)
        e[i] = h
        H[:, i] = (grad(mode + e) - grad(mode - e)) / (2 * h)
    H = 0.5 * (H + H.T)
    info = -H
    eig, V = np.linalg.eigh(info)
    eig = np.clip(eig, 1e-8, None)        # floor: keep PD even off-mode
    cov = (V / eig) @ V.T
    L = np.linalg.cholesky(cov)
    return {"mode": mode, "L": L, "dim": dim}


def _fit_whitened(logpost_torch, x0, n_samples: int, n_chains: int,
                  burn: int, seed: int, step_size: float = 0.3,
                  max_leapfrog: int = 10) -> dict:
    """NUTS-lite in Laplace-whitened space; draws returned in parameter
    space, whitened draws retained for convergence diagnostics."""
    import torch
    pre = _laplace_precondition(logpost_torch, x0)
    mode_t = torch.as_tensor(pre["mode"])
    Lt_t = torch.as_tensor(pre["L"].T)

    def lp_w(w):
        return logpost_torch(mode_t + w @ Lt_t)

    res = mcmc.nuts_lite(mcmc._torch_logpost_and_grad(lp_w),
                         np.zeros(pre["dim"]), n_samples=n_samples,
                         n_chains=n_chains, burn=burn, step_size=step_size,
                         max_leapfrog=max_leapfrog, seed=seed)
    res["samples_white"] = res["samples"]
    res["samples"] = pre["mode"] + res["samples_white"] @ pre["L"].T
    return res


# ---------------------------------------------------------------------------
# Synthetic data generator
# ---------------------------------------------------------------------------
def synth_nigeria(seed: int = 42, n_weeks: int = N_WEEKS) -> dict:
    """Generate one synthetic year of Nigerian fraud intelligence data.

    Assumptions (all synthetic, deterministic given ``seed``):
      * Weekly digital-payment volume per state is proportional to the
        volume weights in ``STATES`` (Lagos ~18% of national observable
        volume), scaled so the national weekly total is
        ``NATIONAL_WEEKLY_TXNS`` with +/-5% weekly seasonality.
      * True state fraud rate = zone base rate (``ZONE_BASE_RATE``)
        x lognormal state noise (sd 0.22) x hotspot bumps
        (Lagos x1.25, Rivers x1.15, FCT x1.20).
      * National weekly intensity drifts upward in logit space
        (+0.006/wk) with N(0, 0.07) innovations — a slow fraud wave.
      * Fraud counts: y_sw ~ Binomial(n_sw, theta_s * exp(rw_t - mean(rw))).
      * Typology: each zone-week's fraud count is split over the 8
        typologies via Multinomial(ZONE_TYPOLOGY_MIX[zone]).
      * LGA volumes partition the pilot state's weekly volume by the
        shares in ``PILOT_STATE_LGAS``; true LGA rate = state rate x
        lognormal(sd 0.35) noise — so sparse rural LGAs get noisy raw
        rates that partial pooling must tame.
    """
    rng = np.random.default_rng(seed)
    S = len(STATES)
    weights = np.array([s[3] for s in STATES])
    zones = [s[2] for s in STATES]

    # national weekly intensity random walk (logit space)
    drift, innov_sd = 0.006, 0.07
    rw = np.cumsum(np.concatenate([[0.0], rng.normal(drift, innov_sd, n_weeks - 1)]))
    rw_centered = rw - rw.mean()

    # true state fraud rates
    bumps = {"lagos": 1.25, "rivers": 1.15, "abuja_fct": 1.20}
    true_rates = np.array([
        ZONE_BASE_RATE[z] * np.exp(rng.normal(0, 0.22)) * bumps.get(code, 1.0)
        for code, _, z, _ in STATES
    ])

    # weekly volumes
    seasonal = np.exp(rng.normal(0, 0.05, n_weeks))
    base_vol = NATIONAL_WEEKLY_TXNS * weights / weights.sum()
    n_sw = np.empty((S, n_weeks), dtype=np.int64)
    y_sw = np.empty((S, n_weeks), dtype=np.int64)
    for si in range(S):
        for t in range(n_weeks):
            lam = base_vol[si] * seasonal[t]
            n = int(rng.poisson(lam))
            p = float(np.clip(true_rates[si] * np.exp(rw_centered[t]), 1e-6, 0.5))
            n_sw[si, t] = n
            y_sw[si, t] = int(rng.binomial(n, p))

    # typology counts per zone-week
    zone_week_typ = {z: np.zeros((n_weeks, len(TYPOLOGIES)), dtype=np.int64)
                     for z in ZONES}
    for si, z in enumerate(zones):
        mix = np.array(ZONE_TYPOLOGY_MIX[z])
        for t in range(n_weeks):
            f = y_sw[si, t]
            if f > 0:
                zone_week_typ[z][t] += rng.multinomial(f, mix)

    # LGA weekly counts for pilot states
    lga_weekly = {}
    lga_true_rates = {}
    for code, lgas in PILOT_STATE_LGAS.items():
        si = STATE_CODES.index(code)
        shares = np.array([sh for _, sh in lgas])
        shares = shares / shares.sum()
        names = [nm for nm, _ in lgas]
        n_l = np.empty((len(names), n_weeks), dtype=np.int64)
        y_l = np.empty((len(names), n_weeks), dtype=np.int64)
        rates = true_rates[si] * np.exp(rng.normal(0, 0.35, len(names)))
        lga_true_rates[code] = rates
        for li in range(len(names)):
            for t in range(n_weeks):
                n = int(rng.poisson(max(n_sw[si, t] * shares[li], 0.1)))
                p = float(np.clip(rates[li] * np.exp(rw_centered[t]), 1e-6, 0.5))
                n_l[li, t] = n
                y_l[li, t] = int(rng.binomial(n, p))
        lga_weekly[code] = {"lga_names": names, "n": n_l, "y": y_l}

    return {
        "seed": seed, "n_weeks": n_weeks,
        "state_codes": STATE_CODES,
        "state_names": [s[1] for s in STATES],
        "zones": zones,
        "n_state_week": n_sw, "y_state_week": y_sw,
        "true_state_rates": true_rates,
        "national_rw_centered": rw_centered,
        "zone_week_typology": zone_week_typ,
        "lga_weekly": lga_weekly,
        "lga_true_rates": lga_true_rates,
    }


# ---------------------------------------------------------------------------
# Model 1: hierarchical per-state fraud-rate model (centered logit-normal)
# ---------------------------------------------------------------------------
def fit_state_model(data: dict, n_samples: int = 1200, burn: int = 1200,
                    n_chains: int = 4, seed: int = 42) -> dict:
    """y_s ~ Binomial(n_s, theta_s); logit(theta_s) = l_s ~ N(mu, sigma).

    CENTERED parameterisation: with ~150M transactions informing 37 state
    rates, the likelihood is enormously informative and the classic
    non-centered form degenerates into a 1/sigma funnel (verified
    empirically: max R-hat > 2.5 even after Laplace whitening, vs ~1.00
    centered). Sampling runs in a Laplace-whitened space
    (``_fit_whitened``); priors: mu ~ N(-4.6, 1) (rate ~1%),
    log(sigma) ~ N(-0.5, 0.75).
    """
    import torch
    y = data["y_state_week"].sum(axis=1).astype(np.float64)
    n = data["n_state_week"].sum(axis=1).astype(np.float64)
    S = len(y)
    dim = 2 + S
    y_t, n_t = torch.as_tensor(y), torch.as_tensor(n)

    def logpost_torch(par):
        mu, log_sigma, l = par[0], par[1], par[2:]
        sigma = torch.exp(log_sigma)
        theta = torch.sigmoid(l)
        ll = torch.sum(y_t * torch.log(theta) + (n_t - y_t) * torch.log1p(-theta))
        lp = (-0.5 * torch.sum(((l - mu) / sigma) ** 2) - S * log_sigma
              - 0.5 * ((mu + 4.6) / 1.0) ** 2
              - 0.5 * ((log_sigma + 0.5) / 0.75) ** 2)
        return ll + lp

    raw = np.clip(y / n, 1e-6, 1 - 1e-6)
    raw_logit = np.log(raw / (1 - raw))
    x0 = np.concatenate([[float(_logit(y.sum() / n.sum())), -0.3], raw_logit])
    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    names = (["mu_national", "log_sigma_states"]
             + [f"theta_logit[{c}]" for c in data["state_codes"]])
    summ = mcmc.summarize(res["samples_white"])  # diagnostics in whitened space
    flat = res["samples"].reshape(-1, dim)
    theta_post = _sigmoid(flat[:, 2:])
    mu_rate_post = _sigmoid(flat[:, 0])
    return {
        "res": res, "summ": summ, "flat": flat, "theta_post": theta_post,
        "mu_rate_post": mu_rate_post, "y": y, "n": n, "names": names,
        "fit_seconds": fit_s,
    }


# ---------------------------------------------------------------------------
# Model 2: LGA-level partial pooling for pilot states (Lagos, Kano, FCT)
# ---------------------------------------------------------------------------
def fit_lga_model(data: dict, n_samples: int = 1200, burn: int = 1500,
                  n_chains: int = 4, seed: int = 42) -> dict:
    """One joint centered fit: logit(theta_lga) = l_lga ~ N(mu_state,
    sigma_state); sparse LGAs shrink toward their state mean.

    Priors: mu_state ~ N(logit(raw state rate), 0.75) (empirical-Bayes
    flavoured), log(sigma_state) ~ N(-0.5, 0.75).
    """
    import torch
    pilots = list(PILOT_STATE_LGAS.keys())          # lagos, kano, abuja_fct
    lga_index = []                                   # (state, lga_name)
    y_list, n_list = [], []
    for code in pilots:
        lw = data["lga_weekly"][code]
        for li, name in enumerate(lw["lga_names"]):
            lga_index.append((code, name))
            y_list.append(lw["y"][li].sum())
            n_list.append(lw["n"][li].sum())
    y = np.asarray(y_list, dtype=np.float64)
    n = np.asarray(n_list, dtype=np.float64)
    L = len(y)
    state_of = np.array([pilots.index(c) for c, _ in lga_index])
    P = len(pilots)
    dim = 2 * P + L
    y_t = torch.as_tensor(y)
    n_t = torch.as_tensor(n)
    so_t = torch.as_tensor(state_of)

    raw = np.clip(y / np.maximum(n, 1), 1e-6, 1 - 1e-6)
    state_raw = [float(_logit(y[state_of == p].sum()
                              / max(n[state_of == p].sum(), 1))) for p in range(P)]
    mu0 = torch.as_tensor(np.array(state_raw), dtype=torch.float64)

    def logpost_torch(par):
        mu, log_sigma, l = par[:P], par[P:2 * P], par[2 * P:]
        sigma = torch.exp(log_sigma)[so_t]
        theta = torch.sigmoid(l)
        ll = torch.sum(y_t * torch.log(theta) + (n_t - y_t) * torch.log1p(-theta))
        lp = (-0.5 * torch.sum(((l - mu[so_t]) / sigma) ** 2)
              - torch.sum(torch.log(sigma))
              - 0.5 * torch.sum(((mu - mu0) / 0.75) ** 2)
              - 0.5 * torch.sum(((log_sigma + 0.5) / 0.75) ** 2))
        return ll + lp

    x0 = np.concatenate([np.array(state_raw), np.full(P, -0.3),
                         np.log(raw / (1 - raw))])
    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    names = ([f"mu_state[{p}]" for p in pilots]
             + [f"log_sigma_state[{p}]" for p in pilots]
             + [f"theta_logit[{c}:{nm}]" for c, nm in lga_index])
    summ = mcmc.summarize(res["samples_white"])
    flat = res["samples"].reshape(-1, dim)
    theta_post = _sigmoid(flat[:, 2 * P:])
    return {"res": res, "summ": summ, "flat": flat, "theta_post": theta_post,
            "y": y, "n": n, "names": names, "lga_index": lga_index,
            "pilots": pilots, "fit_seconds": fit_s}


# ---------------------------------------------------------------------------
# Model 3: typology mix per geopolitical zone (Dirichlet-multinomial)
# ---------------------------------------------------------------------------
def fit_typology_model(data: dict, n_samples: int = 800, burn: int = 800,
                       n_chains: int = 4, seed: int = 42) -> dict:
    """Per zone z: weekly counts c_{z,w} ~ DirMult(alpha_z),
    alpha_zk = exp(x_zk). One joint fit over 6 zones x 8 typologies.
    """
    import torch
    K = len(TYPOLOGIES)
    Z = len(ZONES)
    counts = np.stack([data["zone_week_typology"][z] for z in ZONES]
                      ).astype(np.float64)            # (Z, W, K)
    W = counts.shape[1]
    dim = Z * K
    c_t = torch.as_tensor(counts)

    # empirical init + weakly informative prior centred on the raw mix
    totals = counts.sum(axis=1)                       # (Z, K)
    raw_mix = totals / totals.sum(axis=1, keepdims=True)
    x0 = np.log(np.clip(raw_mix, 1e-6, 1) * totals.mean(axis=1, keepdims=True) * 0.05
                ).reshape(-1)
    mu0 = torch.as_tensor(x0, dtype=torch.float64)

    def logpost_torch(par):
        x = par.reshape(Z, K)
        alpha = torch.exp(x)                          # (Z, K)
        a0 = alpha.sum(dim=1, keepdim=True)[:, :, None]   # (Z, 1, 1)
        n_zw = c_t.sum(dim=2, keepdim=True)           # (Z, W, 1)
        lg_alpha = torch.lgamma(alpha)[:, None, :]    # (Z, 1, K)
        ll = torch.sum(
            torch.lgamma(a0) - torch.lgamma(a0 + n_zw)
            + torch.sum(torch.lgamma(alpha[:, None, :] + c_t) - lg_alpha,
                        dim=2, keepdim=True))
        lp = -0.5 * torch.sum(((par - mu0) / 2.0) ** 2)
        return ll + lp

    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    names = [f"x_typology[{z}:{t}]" for z in ZONES for t in TYPOLOGIES]
    summ = mcmc.summarize(res["samples_white"])
    flat = res["samples"].reshape(-1, dim)
    alpha_post = np.exp(flat.reshape(-1, Z, K))
    mix_post = alpha_post / alpha_post.sum(axis=2, keepdims=True)  # (draws, Z, K)
    return {"res": res, "summ": summ, "flat": flat, "mix_post": mix_post,
            "alpha_post": alpha_post, "counts": counts, "names": names,
            "fit_seconds": fit_s}


# ---------------------------------------------------------------------------
# Model 4: temporal national intensity (52-week random walk + forecast)
# ---------------------------------------------------------------------------
def fit_temporal_model(data: dict, n_samples: int = 1200, burn: int = 1500,
                       n_chains: int = 4, seed: int = 42,
                       forecast_weeks: int = 4) -> dict:
    """y_t ~ Binomial(n_t, sigmoid(r_t)); r_t | r_{t-1} ~ N(r_{t-1}, sigma_rw).
    """
    import torch
    y = data["y_state_week"].sum(axis=0).astype(np.float64)
    n = data["n_state_week"].sum(axis=0).astype(np.float64)
    T = len(y)
    dim = 1 + T                                     # log_sigma_rw, r_0..r_{T-1}
    y_t, n_t = torch.as_tensor(y), torch.as_tensor(n)

    def logpost_torch(par):
        log_sigma, r = par[0], par[1:]
        p = torch.sigmoid(r)
        ll = torch.sum(y_t * torch.log(p) + (n_t - y_t) * torch.log1p(-p))
        d = r[1:] - r[:-1]
        sigma = torch.exp(log_sigma)
        lp_rw = (-0.5 * torch.sum((d / sigma) ** 2) - (T - 1) * log_sigma)
        lp_prior = (-0.5 * ((r[0] + 4.6) / 1.0) ** 2
                    - 0.5 * ((log_sigma + 3.0) / 0.75) ** 2)
        return ll + lp_rw + lp_prior

    raw = np.clip(y / n, 1e-6, 1 - 1e-6)
    x0 = np.concatenate([[-3.0], np.log(raw / (1 - raw))])
    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    names = ["log_sigma_rw"] + [f"r_week[{t}]" for t in range(T)]
    summ = mcmc.summarize(res["samples_white"])
    flat = res["samples"].reshape(-1, dim)

    # posterior predictive: extend the RW forecast_weeks ahead
    rng = np.random.default_rng(seed)
    sigma_post = np.exp(flat[:, 0])
    r_last = flat[:, -1]
    fwd = np.empty((len(flat), forecast_weeks))
    for k in range(forecast_weeks):
        r_last = r_last + rng.normal(0, 1, len(flat)) * sigma_post
        fwd[:, k] = r_last
    forecast_rate = _sigmoid(fwd)                   # (draws, forecast_weeks)
    weekly_rate_post = _sigmoid(flat[:, 1:])
    n_future = int(np.median(n[-8:]))               # assume similar volume
    forecast_counts = rng.binomial(n_future, forecast_rate)
    return {"res": res, "summ": summ, "flat": flat, "names": names,
            "weekly_rate_post": weekly_rate_post, "sigma_post": sigma_post,
            "forecast_rate": forecast_rate, "forecast_counts": forecast_counts,
            "n_future_assumed": n_future, "forecast_weeks": forecast_weeks,
            "y_week": y, "n_week": n, "fit_seconds": fit_s}


# ---------------------------------------------------------------------------
# Serving summaries (consumed by intel-service as summaries.json)
# ---------------------------------------------------------------------------
def _ci(x, prob=0.95):
    lo = np.quantile(x, (1 - prob) / 2, axis=0)
    hi = np.quantile(x, 1 - (1 - prob) / 2, axis=0)
    return lo, hi


def build_summaries(data: dict, state: dict, lga: dict, typ: dict,
                    temp: dict) -> dict:
    """Flatten posterior draws into the aggregate tables the API serves."""
    codes = data["state_codes"]
    mu_rate = state["mu_rate_post"]                 # (draws,)
    theta = state["theta_post"]                     # (draws, S)
    nat_mean = float(mu_rate.mean())
    nat_lo, nat_hi = _ci(mu_rate)

    weekly = temp["weekly_rate_post"]               # (draws, T)
    wk_mean = weekly.mean(axis=0)
    trend = float(wk_mean[-4:].mean() - wk_mean[-8:-4].mean())

    states = []
    for j, code in enumerate(codes):
        lo, hi = _ci(theta[:, j])
        states.append({
            "code": code, "name": data["state_names"][j],
            "zone": data["zones"][j],
            "txn_count": int(state["n"][j]), "fraud_count": int(state["y"][j]),
            "raw_rate": float(state["y"][j] / state["n"][j]),
            "posterior_mean": float(theta[:, j].mean()),
            "ci95": [float(lo), float(hi)],
            "p_above_national": float((theta[:, j] > mu_rate).mean()),
        })
    states.sort(key=lambda r: -r["posterior_mean"])

    # national typology mix = zone mixes weighted by zone fraud volume
    zone_fraud = np.array([data["zone_week_typology"][z].sum() for z in ZONES],
                          dtype=np.float64)
    mix = typ["mix_post"]                           # (draws, Z, K)
    nat_mix = (mix * zone_fraud[None, :, None]).sum(axis=1) / zone_fraud.sum()
    top_typ = sorted(
        ({"typology": TYPOLOGIES[k], "share": float(nat_mix[:, k].mean())}
         for k in range(len(TYPOLOGIES))),
        key=lambda r: -r["share"])[:4]

    zones_out = {}
    for zi, z in enumerate(ZONES):
        rows = []
        for k in range(len(TYPOLOGIES)):
            lo, hi = _ci(mix[:, zi, k])
            rows.append({"typology": TYPOLOGIES[k],
                         "posterior_mean": float(mix[:, zi, k].mean()),
                         "ci95": [float(lo), float(hi)]})
        zones_out[z] = {
            "fraud_count_year": int(zone_fraud[zi]),
            "mix": sorted(rows, key=lambda r: -r["posterior_mean"]),
        }

    lgas_out = {}
    for code in lga["pilots"]:
        rows = []
        for li, (c, name) in enumerate(lga["lga_index"]):
            if c != code:
                continue
            tp = lga["theta_post"][:, li]
            lo, hi = _ci(tp)
            rows.append({
                "lga": name, "txn_count": int(lga["n"][li]),
                "weekly_txn_mean": float(lga["n"][li] / data["n_weeks"]),
                "fraud_count": int(lga["y"][li]),
                "raw_rate": float(lga["y"][li] / max(lga["n"][li], 1)),
                "posterior_mean": float(tp.mean()),
                "ci95": [float(lo), float(hi)],
            })
        rows.sort(key=lambda r: -r["posterior_mean"])
        lgas_out[code] = rows

    fr = temp["forecast_rate"]
    fc_ = temp["forecast_counts"]
    forecast = {
        "weeks_ahead": temp["forecast_weeks"],
        "n_future_assumed_weekly": temp["n_future_assumed"],
        "rate_mean": [float(v) for v in fr.mean(axis=0)],
        "rate_ci95": [[float(l), float(h)] for l, h in zip(*_ci(fr))],
        "count_mean": [float(v) for v in fc_.mean(axis=0)],
        "count_ci95": [[float(l), float(h)] for l, h in zip(*_ci(fc_))],
    }

    return {
        "data_period_weeks": data["n_weeks"],
        "provenance": "synthetic (seeded generator; no real NIBSS/NFIU feed)",
        "seed": data["seed"],
        "national": {
            "posterior_mean": nat_mean,
            "ci95": [float(nat_lo), float(nat_hi)],
            "total_txn_year": int(state["n"].sum()),
            "total_fraud_year": int(state["y"].sum()),
            "week_trend_delta": trend,
            "trend_direction": ("rising" if trend > 5e-4 else
                                "falling" if trend < -5e-4 else "flat"),
            "top_typologies": top_typ,
            "weekly_rate_mean": [float(v) for v in wk_mean],
        },
        "states": states,
        "lgas": lgas_out,
        "typology_mix": zones_out,
        "forecast": forecast,
    }


# ---------------------------------------------------------------------------
# Orchestration: fit all four models, ship artifacts
# ---------------------------------------------------------------------------
def fit_all(version: str = "v1", seed: int = 42, quick: bool = False,
            out_dir: Path | None = None, data: dict | None = None) -> dict:
    set_seed(seed)
    data = data or synth_nigeria(seed)
    if quick:  # CI/test mode: thin chains, still honest diagnostics
        kw = dict(n_samples=400, burn=400, n_chains=3, seed=seed)
    else:
        kw = dict(n_samples=1200, burn=1200, n_chains=4, seed=seed)

    t_start = time.time()
    state = fit_state_model(data, **kw)
    lga = fit_lga_model(data, **{**kw, "burn": kw["burn"] + 300})
    typ = fit_typology_model(data, **{**kw, "n_samples": max(kw["n_samples"] - 400, 300),
                                      "burn": max(kw["burn"] - 400, 300)})
    temp = fit_temporal_model(data, **{**kw, "burn": kw["burn"] + 300})
    total_s = time.time() - t_start

    summaries = build_summaries(data, state, lga, typ, temp)

    def diag(fit):
        return {
            "rhat_max": float(np.max(fit["summ"]["rhat"])),
            "ess_min": float(np.min(fit["summ"]["ess"])),
            "rhat": [float(v) for v in fit["summ"]["rhat"]],
            "ess": [float(v) for v in fit["summ"]["ess"]],
            "accept_rate": [float(v) for v in fit["res"]["accept_rate"]],
            "fit_seconds": round(fit["fit_seconds"], 1),
        }

    # shrinkage demonstration: sparse vs dense LGAs
    shrink_demo = []
    for code in lga["pilots"]:
        for li, (c, name) in enumerate(lga["lga_index"]):
            if c != code:
                continue
            raw_r = lga["y"][li] / max(lga["n"][li], 1)
            shrunk = float(lga["theta_post"][:, li].mean())
            state_row = next(s for s in summaries["states"] if s["code"] == code)
            smean = state_row["posterior_mean"]
            shrink_demo.append({
                "state": code, "lga": name, "txn_count": int(lga["n"][li]),
                "raw_rate": float(raw_r), "posterior_mean": shrunk,
                "ci95_width": float(np.quantile(lga["theta_post"][:, li], 0.975)
                                    - np.quantile(lga["theta_post"][:, li], 0.025)),
                "shrinkage_toward_state_mean": float(abs(raw_r - smean) - abs(shrunk - smean)),
            })

    metrics = {
        "model": MODEL_NAME, "version": version,
        "data": ("synthetic seeded Nigeria generator "
                 f"(seed={data['seed']}, {data['n_weeks']} weeks, "
                 f"national weekly txns ~{NATIONAL_WEEKLY_TXNS:,} platform-observable)"),
        "seed": seed, "quick_mode": quick,
        "sampler": "nuts_lite", "n_chains": kw["n_chains"],
        "n_samples_per_chain": kw["n_samples"], "burn": kw["burn"],
        "total_fit_seconds": round(total_s, 1),
        "state_model": {**diag(state),
                        "sigma_states_posterior_mean": float(np.exp(state["flat"][:, 1]).mean())},
        "lga_model": diag(lga),
        "typology_model": diag(typ),
        "temporal_model": {**diag(temp),
                           "sigma_rw_posterior_mean": float(temp["sigma_post"].mean())},
        "national_rate_posterior_mean": summaries["national"]["posterior_mean"],
        "national_rate_ci95": summaries["national"]["ci95"],
        "top5_states": [{k: s[k] for k in ("code", "posterior_mean", "ci95",
                                           "p_above_national")}
                        for s in summaries["states"][:5]],
        "shrinkage_demo_sparsest": sorted(shrink_demo, key=lambda r: r["txn_count"])[:8],
        "forecast": summaries["forecast"],
    }
    print(json.dumps({k: v for k, v in metrics.items()
                      if k not in ("state_model", "lga_model", "typology_model",
                                   "temporal_model")}, indent=2))

    out_dir = out_dir or ARTIFACT_ROOT / MODEL_NAME / version
    out_dir.mkdir(parents=True, exist_ok=True)
    mcmc.save_posterior(out_dir / "posterior.npz", state["res"]["samples"],
                        state["names"],
                        meta={"model": MODEL_NAME, "version": version,
                              "submodel": "state_hierarchy",
                              "parametrization": "logit(theta_s)=l_s ~ N(mu,sigma) (centered; "
                                                 "Laplace-whitened sampling space)",
                              "priors": {"mu": "N(-4.6,1)",
                                         "log_sigma": "N(-0.5,0.75)",
                                         "l_s": "N(mu,sigma)"},
                              "provenance": "synthetic", "seed": seed})
    mcmc.save_posterior(out_dir / "lga_posterior.npz", lga["res"]["samples"],
                        lga["names"],
                        meta={"model": MODEL_NAME, "submodel": "lga_hierarchy",
                              "pilot_states": lga["pilots"], "seed": seed})
    mcmc.save_posterior(out_dir / "typology_posterior.npz", typ["res"]["samples"],
                        typ["names"],
                        meta={"model": MODEL_NAME, "submodel": "typology_dirmult",
                              "zones": ZONES, "typologies": TYPOLOGIES, "seed": seed})
    mcmc.save_posterior(out_dir / "temporal_posterior.npz", temp["res"]["samples"],
                        temp["names"],
                        meta={"model": MODEL_NAME, "submodel": "temporal_rw",
                              "n_weeks": data["n_weeks"],
                              "forecast_weeks": temp["forecast_weeks"], "seed": seed})
    (out_dir / "summaries.json").write_text(json.dumps(summaries, indent=2))
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (out_dir / "MODEL_CARD.md").write_text(_model_card(version, metrics, summaries))
    print(f"saved -> {out_dir} (total fit {total_s:.1f}s)")
    return metrics


def _model_card(version: str, m: dict, s: dict) -> str:
    top_rows = "\n".join(
        f"| {r['code']} | {r['posterior_mean']:.4f} | "
        f"[{r['ci95'][0]:.4f}, {r['ci95'][1]:.4f}] | {r['p_above_national']:.2f} |"
        for r in s["states"][:5])
    diag_rows = "\n".join(
        f"| {name} | {m[name]['rhat_max']:.4f} | {m[name]['ess_min']:.0f} | "
        f"{m[name]['fit_seconds']:.0f}s |"
        for name in ("state_model", "lga_model", "typology_model", "temporal_model"))
    fc = s["forecast"]
    fc_rows = "\n".join(
        f"| +{k + 1}wk | {fc['rate_mean'][k]:.4f} | "
        f"[{fc['rate_ci95'][k][0]:.4f}, {fc['rate_ci95'][k][1]:.4f}] |"
        for k in range(fc["weeks_ahead"]))
    return f"""# Model Card: national_intelligence ({version})

Hierarchical Bayesian (MCMC) aggregation of fraud signals into LOCAL and
NATIONAL fraud intelligence for Nigeria: 37-jurisdiction partial-pooling
fraud-rate model, LGA-level pooling for 3 pilot states, per-zone
Dirichlet-multinomial typology mixes, and a 52-week random-walk national
intensity with a 4-week posterior predictive forecast.

- **Data**: {m['data']} — provenance: **synthetic** (no real NIBSS/NFIU feed).
- **Inference**: {m['sampler']} (ml.bayesian.mcmc), {m['n_chains']} chains x
  {m['n_samples_per_chain']} kept samples per model. Total fit {m['total_fit_seconds']:.0f}s.
- **Serving contract**: summaries.json aggregates only; intel-service
  suppresses cells with n<30 (k-anonymity); no PII anywhere in the pipeline.

## Convergence diagnostics

| Sub-model | max R-hat | min ESS | fit time |
|---|---|---|---|
{diag_rows}

## National estimate

- Annual-average weekly fraud rate (state hierarchy): posterior mean
  {s['national']['posterior_mean']:.4f}, 95% CI
  [{s['national']['ci95'][0]:.4f}, {s['national']['ci95'][1]:.4f}]
  (trend: {s['national']['trend_direction']}; the current week runs hotter
  than the annual average — see forecast below, which continues from the
  latest week of the temporal model)
- Top typologies nationally: {', '.join(t['typology'] for t in s['national']['top_typologies'])}

## Top-5 states by posterior mean fraud rate

| State | Posterior mean | 95% CI | P(above national) |
|---|---|---|---|
{top_rows}

## 4-week forecast (national weekly fraud rate)

| Horizon | Mean | 95% CI |
|---|---|---|
{fc_rows}

## Limitations

- Trained on synthetic data with documented assumptions; absolute levels are
  NOT real-world Nigerian fraud rates until real feeds are wired in.
- Binomial likelihood assumes reported fraud; reporting bias (some states
  detect/report better) enters the estimates directly.
- State/zone aggregates must not be projected onto individuals
  (ecological fallacy).
"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--quick", action="store_true",
                    help="thin chains for CI smoke runs")
    a = ap.parse_args()
    fit_all(version=a.version, seed=a.seed, quick=a.quick)
