"""Bayesian posterior over "account belongs to an active mule ring".

Combines the trained GNN node score with transaction-graph statistics in a
Bayesian logistic model, sampled with MCMC so every account gets a
probability AND a credible interval (a point estimate cannot express "the
GNN is confident but the graph stats disagree").

Model (per account i):
    eta_i = b0 + w_gnn * logit(s_gnn_i) + w_topo' * topo_i
    p_i   = sigmoid(eta_i)
    y_i   ~ Bernoulli(p_i)        # is_mule label (synthetic ground truth)
Priors (weakly informative, taming quasi-separation from saturated GNN
scores): b0 ~ N(logit(base_rate), 1), w_gnn ~ N(1, 0.5), w_topo ~ N(0, 0.5).
logit(s_gnn) is capped at ±6 for the same reason.

topo features (from the graph snapshot): log_unique_senders (fan-in),
log_in_count, log_in/out amount ratio — the classic mule "high fan-in,
pass-through" signature, z-scored.

Inference: NUTS-lite (ml.bayesian.mcmc) with torch autograd gradients.
Production may swap in NumPyro; artifact contract = posterior.npz.

Run:
    python -m ml.bayesian.mule_ring_posterior [--version v1] [--gnn-version v2]

Ships ml/artifacts/mule_ring_posterior/<version>/ with posterior.npz,
metrics.json (incl. per-account uncertainty examples), MODEL_CARD.md.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.bayesian import mcmc  # noqa: E402
from ml.train.common import ARTIFACT_ROOT, set_seed  # noqa: E402

EPS = 1e-6
PARAM_NAMES = ["b0", "w_gnn", "w_fanin", "w_incident_count", "w_passthrough"]


def _logit(s, cap: float = 6.0):
    # cap the logit: GNN scores of exactly ~0/1 would otherwise inject
    # ±13.8 features and induce quasi-separation (unidentifiable b0).
    s = np.clip(s, EPS, 1 - EPS)
    return np.clip(np.log(s / (1 - s)), -cap, cap)


def gnn_node_scores(gnn_version: str = "v2",
                    data_dir: Path | None = None) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Score every node of the full-window graph snapshot with the shipped
    gnn_mule artifact (pure-torch SAGE path, no PyG). Returns
    (scores, topo_features[N,3], labels)."""
    import os
    import torch
    from ml.models.gnn_mule import MuleGNN, load_state_dict_portable

    data_dir = Path(os.environ.get(
        "FRAUDFUSION_DATA",
        Path(__file__).resolve().parents[1] / "data" / "generated")) if data_dir is None else data_dir
    g = np.load(data_dir / "graph.npz")
    key = "X_test" if "X_test" in g else "X"
    ei_key = "edge_index_test" if "edge_index_test" in g else "edge_index"
    X_raw, ei, y = g[key], g[ei_key], g["y"]

    art = ARTIFACT_ROOT / "gnn_mule" / gnn_version
    prep = np.load(art / "preprocess.npz")
    mean, std = prep["scaler_mean"], prep["scaler_std"]
    model = MuleGNN(int(mean.shape[0]), use_pyg=False)
    load_state_dict_portable(model, art / "weights.pt")
    model.eval()
    with torch.no_grad():
        scores = model.prob(torch.from_numpy(((X_raw - mean) / std).astype(np.float32)),
                            torch.from_numpy(ei)).numpy().astype(np.float64)

    # topo features from RAW (unscaled) node features:
    # idx 4 log_unique_senders (fan-in), idx 2 log_in_count,
    # passthrough = log_in_amount - log_out_amount (≈0 => money passes through)
    fanin = X_raw[:, 4]
    incount = X_raw[:, 2]
    passthrough = -np.abs(X_raw[:, 0] - X_raw[:, 1])  # 0 = perfect pass-through
    topo = np.stack([fanin, incount, passthrough], axis=1)
    topo = (topo - topo.mean(0)) / (topo.std(0) + 1e-9)
    return scores, topo, y.astype(np.float64)


def fit(gnn_version: str = "v2", version: str = "v1", seed: int = 42,
        n_samples: int = 2000, burn: int = 1500, n_chains: int = 4,
        out_dir: Path | None = None, data_dir: Path | None = None) -> dict:
    set_seed(seed)
    import torch
    s_gnn, topo, y = gnn_node_scores(gnn_version, data_dir)
    n = len(y)
    z_gnn = _logit(s_gnn)
    X = np.column_stack([np.ones(n), z_gnn, topo])  # (n, 5)

    X_t = torch.as_tensor(X, dtype=torch.float64)
    y_t = torch.as_tensor(y, dtype=torch.float64)
    # Weakly informative priors to tame quasi-separation (GNN scores saturate
    # at 0/1): intercept centred on the empirical logit base rate (standard
    # empirical-Bayes-flavoured default), slope priors shrunk towards 0/1.
    base_rate = float(np.clip(y.mean(), 1e-4, 1 - 1e-4))
    mu_prior = torch.as_tensor([math.log(base_rate / (1 - base_rate)),
                                1.0, 0.0, 0.0, 0.0], dtype=torch.float64)
    sd_prior = torch.as_tensor([1.0, 0.5, 0.5, 0.5, 0.5], dtype=torch.float64)

    def logpost_torch(theta):
        eta = X_t @ theta
        ll = torch.sum(y_t * eta - torch.logaddexp(torch.zeros_like(eta), eta))
        return ll - 0.5 * torch.sum(((theta - mu_prior) / sd_prior) ** 2)

    res = mcmc.nuts_lite(mcmc._torch_logpost_and_grad(logpost_torch),
                         np.zeros(5), n_samples=n_samples, n_chains=n_chains,
                         burn=burn, step_size=0.01, max_leapfrog=8, seed=seed)
    summ = mcmc.summarize(res["samples"])
    flat = res["samples"].reshape(-1, 5)

    # posterior predictive per account (subsample draws for memory)
    rng = np.random.default_rng(seed)
    sub = flat[rng.choice(len(flat), size=min(1000, len(flat)), replace=False)]
    p_samples = 1.0 / (1.0 + np.exp(-(sub @ X.T)))      # (draws, n)
    p_mean = p_samples.mean(axis=0)
    p_lo = np.quantile(p_samples, 0.025, axis=0)
    p_hi = np.quantile(p_samples, 0.975, axis=0)

    from sklearn.metrics import average_precision_score, roc_auc_score
    # widest-CI high-risk accounts = "uncertain but suspicious" queue
    ci_width = p_hi - p_lo
    order = np.argsort(-ci_width)
    suspicious = [i for i in order[:20] if p_mean[i] > 0.2][:5]
    examples = [{
        "node_index": int(i),
        "is_mule_label": int(y[i]),
        "gnn_score": round(float(s_gnn[i]), 4),
        "posterior_mean": round(float(p_mean[i]), 4),
        "ci95": [round(float(p_lo[i]), 4), round(float(p_hi[i]), 4)],
    } for i in suspicious]

    metrics = {
        "model": "mule_ring_posterior", "version": version,
        "base_gnn": f"gnn_mule/{gnn_version}",
        "n_accounts": int(n), "n_mules": int(y.sum()),
        "auc_roc_gnn_only": float(roc_auc_score(y, s_gnn)),
        "auc_roc_posterior_mean": float(roc_auc_score(y, p_mean)),
        "auc_pr_gnn_only": float(average_precision_score(y, s_gnn)),
        "auc_pr_posterior_mean": float(average_precision_score(y, p_mean)),
        "mean_ci95_width": float(ci_width.mean()),
        "mule_mean_ci95_width": float(ci_width[y == 1].mean()),
        "posterior_mean": {PARAM_NAMES[j]: float(summ["mean"][j]) for j in range(5)},
        "posterior_sd": {PARAM_NAMES[j]: float(summ["sd"][j]) for j in range(5)},
        "rhat": [float(v) for v in summ["rhat"]],
        "ess": [float(v) for v in summ["ess"]],
        "accept_rate": [float(v) for v in res["accept_rate"]],
        "sampler": "nuts_lite", "n_chains": n_chains,
        "n_samples_per_chain": n_samples, "burn": burn, "seed": seed,
        "uncertain_suspicious_examples": examples,
        "evaluation": "fit on full synthetic graph snapshot (labels are the "
                      "synthetic ground truth; AUCs are in-sample)",
    }
    print(json.dumps(metrics, indent=2))

    out_dir = out_dir or ARTIFACT_ROOT / "mule_ring_posterior" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    mcmc.save_posterior(out_dir / "posterior.npz", res["samples"], PARAM_NAMES,
                        meta={"model": "mule_ring_posterior", "version": version,
                              "base_gnn": f"gnn_mule/{gnn_version}",
                              "parametrization": "eta=b0+w_gnn*clip(logit(s_gnn),±6)+w_topo'.topo",
                              "priors": {"b0": "N(logit(base_rate),1)",
                                         "w_gnn": "N(1,0.5)",
                                         "w_topo": "N(0,0.5)"},
                              "seed": seed})
    np.savez_compressed(out_dir / "account_posterior.npz",
                        p_mean=p_mean, ci95_lo=p_lo, ci95_hi=p_hi, y=y)
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (out_dir / "MODEL_CARD.md").write_text(_model_card(version, metrics))
    print(f"saved -> {out_dir}")
    return metrics


def _model_card(version: str, m: dict) -> str:
    rows = "\n".join(
        f"| {k} | {m['posterior_mean'][k]:.4f} | {m['posterior_sd'][k]:.4f} | "
        f"{m['rhat'][j]:.4f} | {m['ess'][j]:.0f} |"
        for j, k in enumerate(PARAM_NAMES))
    return f"""# Model Card: mule_ring_posterior ({version})

Bayesian logistic posterior over "account belongs to an active mule ring",
combining `{m['base_gnn']}` node scores with graph topology statistics
(fan-in, incident count, pass-through balance). Every account gets a
probability plus a 95% credible interval.

- **Fit data**: full synthetic graph snapshot ({m['n_accounts']} accounts,
  {m['n_mules']} mules) — provenance: **synthetic**.
- **Inference**: {m['sampler']} (ml.bayesian.mcmc), {m['n_chains']} chains ×
  {m['n_samples_per_chain']} samples. Production may swap in NumPyro.
- **Priors**: b0 ~ N(logit(base_rate), 1), w_gnn ~ N(1, 0.5),
  w_topo ~ N(0, 0.5); logit(s_gnn) capped at ±6 (quasi-separation guard).

## Posterior over weights

| Param | Mean | SD | R-hat | ESS |
|---|---|---|---|---|
{rows}

## Discrimination (in-sample, synthetic labels)

| Metric | GNN score only | Posterior mean |
|---|---|---|
| AUC-ROC | {m['auc_roc_gnn_only']:.4f} | {m['auc_roc_posterior_mean']:.4f} |
| AUC-PR | {m['auc_pr_gnn_only']:.4f} | {m['auc_pr_posterior_mean']:.4f} |

Mean 95% CI width: {m['mean_ci95_width']:.4f} overall,
{m['mule_mean_ci95_width']:.4f} on true mules.

## Limitations

- Fit on synthetic ground truth; on production data labels are delayed and
  noisy — recalibrate before acting on the credible intervals.
- In-sample discrimination metrics; the GNN base score already encodes most
  of the signal, so gains are expected to be modest — the value is the
  uncertainty quantification, not AUC.
"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--gnn-version", default="v2")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-samples", type=int, default=2000)
    ap.add_argument("--burn", type=int, default=1500)
    a = ap.parse_args()
    fit(gnn_version=a.gnn_version, version=a.version, seed=a.seed,
        n_samples=a.n_samples, burn=a.burn)
