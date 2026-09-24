"""Bayesian hierarchical model of insider-event rates (partial pooling by
department/role).

Motivation: raw per-department insider-event rates are wildly over-dispersed
for small teams (2 events out of 5 staff = 40%!). Partial pooling shrinks
low-count departments toward the population mean, with the shrinkage STrength
learned from the data rather than fixed.

Model (logit-normal-binomial hierarchy, NON-CENTERED for good HMC geometry —
a centered Beta-binomial has a funnel in the concentration parameter that
hand-rolled samplers cannot traverse):
    y_d ~ Binomial(n_d, theta_d)                     per department d
    logit(theta_d) = alpha + sigma * z_d,  z_d ~ N(0, 1)   partial pooling
    alpha ~ N(-3, 1.5)         population log-rate prior
    log(sigma) ~ N(-0.5, 0.75) dispersion prior
Population rate = sigmoid(alpha); sigma controls shrinkage strength
(learned). Sampled with NUTS-lite + torch autograd. Production may swap in
NumPyro (same npz artifact contract).

Data: synthetic insider-event ledger generated here (seeded, self-contained)
— no real HR data exists in this repo, and none is faked.

Run:
    python -m ml.bayesian.insider_risk [--version v1]

Ships ml/artifacts/insider_risk/<version>/ with posterior.npz, metrics.json
(raw vs shrunk rates table), MODEL_CARD.md.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.bayesian import mcmc  # noqa: E402
from ml.train.common import ARTIFACT_ROOT, set_seed  # noqa: E402

DEPARTMENTS = [
    # (name, staff, true monthly insider-event rate) — synthetic ground truth
    ("fraud_ops", 120, 0.020),
    ("treasury", 40, 0.030),
    ("agent_network", 800, 0.012),
    ("customer_care", 300, 0.015),
    ("engineering", 90, 0.008),
    ("compliance", 25, 0.040),
    ("field_sales", 12, 0.060),      # tiny team -> raw rate wildly noisy
    ("executive", 6, 0.050),         # tiny team -> extreme shrinkage demo
]


def synth_events(seed: int = 42) -> dict:
    """Generate one synthetic month of insider events (deterministic)."""
    rng = np.random.default_rng(seed)
    names, n_staff, true_rates, y = [], [], [], []
    for name, n, rate in DEPARTMENTS:
        names.append(name)
        n_staff.append(n)
        true_rates.append(rate)
        y.append(int(rng.binomial(n, rate)))
    return {"departments": names, "n_staff": np.array(n_staff),
            "true_rates": np.array(true_rates), "y": np.array(y)}


def fit(version: str = "v1", seed: int = 42, n_samples: int = 3000,
        burn: int = 2500, n_chains: int = 4,
        out_dir: Path | None = None, data: dict | None = None) -> dict:
    set_seed(seed)
    import torch
    data = data or synth_events(seed)
    y = np.asarray(data["y"], dtype=np.float64)
    n = np.asarray(data["n_staff"], dtype=np.float64)
    D = len(y)
    dim = 2 + D

    y_t = torch.as_tensor(y)
    n_t = torch.as_tensor(n)

    def logpost_torch(par):
        alpha, log_sigma = par[0], par[1]
        z = par[2:]
        sigma = torch.exp(log_sigma)
        theta_d = torch.sigmoid(alpha + sigma * z)
        ll = torch.sum(y_t * torch.log(theta_d)
                       + (n_t - y_t) * torch.log1p(-theta_d))
        lp_z = -0.5 * torch.sum(z ** 2)
        lp_hyper = (-0.5 * ((alpha + 3.0) / 1.5) ** 2
                    - 0.5 * ((log_sigma + 0.5) / 0.75) ** 2)
        return ll + lp_z + lp_hyper

    raw_logit = np.log(np.clip(y / n, 1e-4, 1 - 1e-4)
                       / (1 - np.clip(y / n, 1e-4, 1 - 1e-4)))
    x0 = np.concatenate([[-3.0, -0.5], (raw_logit - raw_logit.mean())
                         / (raw_logit.std() + 1e-6) * 0.1])
    res = mcmc.nuts_lite(mcmc._torch_logpost_and_grad(logpost_torch),
                         x0, n_samples=n_samples, n_chains=n_chains,
                         burn=burn, step_size=0.02, max_leapfrog=8, seed=seed)

    names = ["alpha", "log_sigma"] + [f"z[{d}]" for d in data["departments"]]
    summ = mcmc.summarize(res["samples"])
    flat = res["samples"].reshape(-1, dim)

    theta_post = 1.0 / (1.0 + np.exp(-(flat[:, 0:1] + np.exp(flat[:, 1:2]) * flat[:, 2:])))
    mu_post = 1.0 / (1.0 + np.exp(-flat[:, 0]))
    sigma_post = np.exp(flat[:, 1])

    raw_rates = y / n
    shrunk = theta_post.mean(axis=0)
    shrunk_lo = np.quantile(theta_post, 0.025, axis=0)
    shrunk_hi = np.quantile(theta_post, 0.975, axis=0)

    table = []
    for j, d in enumerate(data["departments"]):
        table.append({
            "department": d,
            "n_staff": int(n[j]), "events": int(y[j]),
            "raw_rate": round(float(raw_rates[j]), 4),
            "posterior_mean_rate": round(float(shrunk[j]), 4),
            "ci95": [round(float(shrunk_lo[j]), 4), round(float(shrunk_hi[j]), 4)],
            "shrinkage_toward_population": round(float(abs(raw_rates[j] - mu_post.mean())
                                                       - abs(shrunk[j] - mu_post.mean())), 4),
        })

    metrics = {
        "model": "insider_risk", "version": version,
        "data": "synthetic insider-event ledger (seeded), one month",
        "n_departments": D,
        "population_rate_posterior_mean": float(mu_post.mean()),
        "population_rate_ci95": [float(np.quantile(mu_post, 0.025)),
                                 float(np.quantile(mu_post, 0.975))],
        "sigma_posterior_mean": float(sigma_post.mean()),
        "sigma_ci95": [float(np.quantile(sigma_post, 0.025)),
                       float(np.quantile(sigma_post, 0.975))],
        "department_table": table,
        "rhat_max": float(np.max(summ["rhat"])),
        "ess_min": float(np.min(summ["ess"])),
        "rhat": [float(v) for v in summ["rhat"]],
        "ess": [float(v) for v in summ["ess"]],
        "accept_rate": [float(v) for v in res["accept_rate"]],
        "sampler": "nuts_lite", "n_chains": n_chains,
        "n_samples_per_chain": n_samples, "burn": burn, "seed": seed,
    }
    print(json.dumps(metrics, indent=2))

    out_dir = out_dir or ARTIFACT_ROOT / "insider_risk" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    mcmc.save_posterior(out_dir / "posterior.npz", res["samples"], names,
                        meta={"model": "insider_risk", "version": version,
                              "parametrization": "logit(theta_d)=alpha+sigma*z_d, z_d~N(0,1) "
                                                 "(non-centered logit-normal hierarchy)",
                              "priors": {"alpha": "N(-3,1.5)",
                                         "log_sigma": "N(-0.5,0.75)"},
                              "seed": seed})
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (out_dir / "MODEL_CARD.md").write_text(_model_card(version, metrics))
    print(f"saved -> {out_dir}")
    return metrics


def _model_card(version: str, m: dict) -> str:
    rows = "\n".join(
        f"| {t['department']} | {t['n_staff']} | {t['events']} | "
        f"{t['raw_rate']:.4f} | {t['posterior_mean_rate']:.4f} | "
        f"[{t['ci95'][0]:.4f}, {t['ci95'][1]:.4f}] |"
        for t in m["department_table"])
    return f"""# Model Card: insider_risk ({version})

Hierarchical Bayesian estimate of monthly insider-event rates by department,
with partial pooling (small departments shrink toward the population rate).

- **Data**: synthetic seeded insider-event ledger ({m['n_departments']}
  departments, one month) — provenance: **synthetic**, no real HR data.
- **Model**: y_d ~ Binomial(n_d, theta_d); logit(theta_d) = alpha + sigma·z_d,
  z_d ~ N(0, 1) (non-centered logit-normal hierarchy); alpha ~ N(-3, 1.5);
  log(sigma) ~ N(-0.5, 0.75).
- **Inference**: {m['sampler']} (ml.bayesian.mcmc), {m['n_chains']} chains ×
  {m['n_samples_per_chain']} samples, burn {m['burn']}.
  max R-hat {m['rhat_max']:.4f}, min ESS {m['ess_min']:.0f}.
  Production may swap in NumPyro; artifact contract = posterior.npz.

## Population

- Population rate sigmoid(alpha): posterior mean {m['population_rate_posterior_mean']:.4f},
  95% CI [{m['population_rate_ci95'][0]:.4f}, {m['population_rate_ci95'][1]:.4f}]
- Dispersion sigma: posterior mean {m['sigma_posterior_mean']:.2f}
  (smaller sigma = stronger pooling toward the population rate)

## Raw vs shrunk rates

| Department | Staff | Events | Raw rate | Posterior mean | 95% CI |
|---|---|---|---|---|---|
{rows}

## Limitations

- One synthetic month; production use needs real labelled insider events and
  per-department exposure windows.
- Beta-binomial assumes exchangeability within department; role-level
  pooling can be added as another hierarchy level (same toolkit).
"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-samples", type=int, default=3000)
    ap.add_argument("--burn", type=int, default=2500)
    a = ap.parse_args()
    fit(version=a.version, seed=a.seed, n_samples=a.n_samples, burn=a.burn)
