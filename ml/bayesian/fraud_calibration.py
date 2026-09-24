"""Bayesian logistic calibration of fraud_net raw scores.

Model (fit on the validation split via MCMC — no closed-form shortcut):

    logit(p_cal) = a * logit(s_raw) + b
    a ~ Normal(1, 1)      # centred on identity calibration
    b ~ Normal(0, 1)
    y_i ~ Bernoulli(sigmoid(a * logit(s_raw_i) + b))

The posterior over (a, b) is sampled with the hand-rolled Metropolis-
Hastings sampler from ml.bayesian.mcmc (numpy only; production may swap in
NumPyro — the artifact contract is just posterior samples in an npz).

Outputs per transaction: calibrated probability = posterior mean of
sigmoid(a*logit(s)+b), plus a 95% credible interval over that probability.

Run:
    python -m ml.bayesian.fraud_calibration [--version v1] [--fraud-version v3]

Ships ml/artifacts/bayesian_calibration/<version>/ with:
    posterior.npz   MCMC samples (chains, n, 2) + param names + meta
    metrics.json    ECE/Brier/NLL before vs after, R-hat, ESS, acceptance
    MODEL_CARD.md
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
from ml.train.common import ARTIFACT_ROOT, DATA_DIR, set_seed  # noqa: E402

EPS = 1e-6
PARAM_NAMES = ["a", "b"]


# ---------------------------------------------------------------------------
# Scoring the validation split with the shipped fraud_net artifact
# ---------------------------------------------------------------------------
def validation_scores(fraud_version: str = "v3",
                      data_dir: Path | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Return (raw_scores, labels) for the validation split, scored with the
    shipped fraud_net artifact (ONNX if present, torch fallback)."""
    import pandas as pd
    from ml.data.synthetic_nigeria import CATEGORICAL_FEATURES, NUMERIC_FEATURES

    data_dir = data_dir or DATA_DIR
    art = ARTIFACT_ROOT / "fraud_net" / fraud_version
    if not art.exists():
        raise FileNotFoundError(
            f"fraud_net artifact missing at {art}; train fraud_net first.")
    df = pd.read_parquet(data_dir / "transactions.parquet")
    df = df[df["split"] == "val"].reset_index(drop=True)

    vocab = json.loads((art / "vocab.json").read_text())
    prep = np.load(art / "preprocess.npz")
    x_num = df[NUMERIC_FEATURES].to_numpy(np.float32)
    x_num = ((x_num - prep["scaler_mean"]) / prep["scaler_std"]).astype(np.float32)
    x_cat = np.zeros((len(df), len(CATEGORICAL_FEATURES)), dtype=np.int64)
    for j, c in enumerate(sorted(CATEGORICAL_FEATURES)):
        x_cat[:, j] = df[c].astype(str).map(vocab.get(c, {})).fillna(0).to_numpy(np.int64)

    onnx = art / "model.onnx"
    if onnx.exists():
        import onnxruntime as ort
        sess = ort.InferenceSession(str(onnx), providers=["CPUExecutionProvider"])
        probs = np.empty(len(df), dtype=np.float64)
        bs = 8192
        for i in range(0, len(df), bs):
            probs[i:i + bs] = sess.run(
                None, {"x_num": x_num[i:i + bs],
                       "x_cat": x_cat[i:i + bs]})[0].reshape(-1)
    else:
        import torch
        from ml.models.fraud_net import FraudNet, cardinalities
        m = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
        m.load_state_dict(torch.load(art / "weights.pt", weights_only=True))
        m.eval()
        with torch.no_grad():
            probs = m.prob(torch.from_numpy(x_num),
                           torch.from_numpy(x_cat)).numpy().astype(np.float64)
    return probs, df["is_fraud"].to_numpy(np.float64)


# ---------------------------------------------------------------------------
# Posterior
# ---------------------------------------------------------------------------
def _logit(s: np.ndarray) -> np.ndarray:
    s = np.clip(s, EPS, 1 - EPS)
    return np.log(s / (1 - s))


def make_logpost(z: np.ndarray, y: np.ndarray) -> callable:
    """z = logit(raw scores), y = labels. Priors a~N(1,1), b~N(0,1)."""
    def logpost(theta: np.ndarray) -> float:
        a, b = float(theta[0]), float(theta[1])
        if abs(a) > 50 or abs(b) > 50:  # flat tail guard
            return -np.inf
        eta = a * z + b
        # Bernoulli log-likelihood, numerically stable
        ll = float(np.sum(y * eta - np.logaddexp(0.0, eta)))
        lp = -0.5 * ((a - 1.0) ** 2 + b ** 2)
        return ll + lp
    return logpost


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 15) -> float:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(float(y[m].mean()) - float(p[m].mean()))
    return float(ece)


def brier(y: np.ndarray, p: np.ndarray) -> float:
    return float(np.mean((p - y) ** 2))


def nll(y: np.ndarray, p: np.ndarray) -> float:
    p = np.clip(p, EPS, 1 - EPS)
    return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))


# ---------------------------------------------------------------------------
# Fit + artifact
# ---------------------------------------------------------------------------
def fit(fraud_version: str = "v3", version: str = "v1", seed: int = 42,
        n_samples: int = 4000, burn: int = 2000, n_chains: int = 4,
        out_dir: Path | None = None, data_dir: Path | None = None) -> dict:
    set_seed(seed)
    s_raw, y = validation_scores(fraud_version, data_dir)
    z = _logit(s_raw)
    logpost = make_logpost(z, y)

    # NUTS-lite (HMC + dual averaging) with torch autograd gradients —
    # far better mixing than random-walk MH on this correlated 2-D posterior.
    import torch
    z_t = torch.as_tensor(z, dtype=torch.float64)
    y_t = torch.as_tensor(y, dtype=torch.float64)

    def logpost_torch(theta):
        a, b = theta[0], theta[1]
        eta = a * z_t + b
        ll = torch.sum(y_t * eta - torch.logaddexp(torch.zeros_like(eta), eta))
        return ll - 0.5 * ((a - 1.0) ** 2 + b ** 2)

    res = mcmc.nuts_lite(mcmc._torch_logpost_and_grad(logpost_torch),
                         np.array([1.0, 0.0]), n_samples=n_samples,
                         n_chains=n_chains, burn=burn, step_size=0.05,
                         seed=seed)
    summ = mcmc.summarize(res["samples"])
    flat = res["samples"].reshape(-1, 2)

    # posterior-mean calibration on the validation set (honest: same data the
    # posterior was fit on; the POINT is uncertainty quantification + ECE of
    # the mapping, evaluated here in-sample and flagged as such)
    # subsample posterior draws to bound the (n_draws x n_val) matrix
    rng = np.random.default_rng(seed)
    draw_idx = rng.choice(len(flat), size=min(2000, len(flat)), replace=False)
    sub = flat[draw_idx]
    p_cal_samples = 1.0 / (1.0 + np.exp(-(sub[:, 0:1] * z[None, :] + sub[:, 1:2])))
    p_cal = p_cal_samples.mean(axis=0)

    metrics = {
        "model": "bayesian_calibration",
        "version": version,
        "base_model": f"fraud_net/{fraud_version}",
        "n_val": int(len(y)),
        "val_base_rate": float(y.mean()),
        "ece_before": expected_calibration_error(y, s_raw),
        "ece_after": expected_calibration_error(y, p_cal),
        "brier_before": brier(y, s_raw),
        "brier_after": brier(y, p_cal),
        "nll_before": nll(y, s_raw),
        "nll_after": nll(y, p_cal),
        "posterior_mean_a": float(summ["mean"][0]),
        "posterior_mean_b": float(summ["mean"][1]),
        "posterior_sd_a": float(summ["sd"][0]),
        "posterior_sd_b": float(summ["sd"][1]),
        "ci95_a": [float(summ["ci95_lo"][0]), float(summ["ci95_hi"][0])],
        "ci95_b": [float(summ["ci95_lo"][1]), float(summ["ci95_hi"][1])],
        "rhat": [float(v) for v in summ["rhat"]],
        "ess": [float(v) for v in summ["ess"]],
        "accept_rate": [float(v) for v in res["accept_rate"]],
        "sampler": "nuts_lite",
        "n_chains": n_chains, "n_samples_per_chain": n_samples, "burn": burn,
        "seed": seed,
        "evaluation": "in-sample on the validation split used for fitting",
    }
    print(json.dumps(metrics, indent=2))

    out_dir = out_dir or ARTIFACT_ROOT / "bayesian_calibration" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    mcmc.save_posterior(out_dir / "posterior.npz", res["samples"], PARAM_NAMES,
                        meta={"model": "bayesian_calibration",
                              "version": version,
                              "base_model": f"fraud_net/{fraud_version}",
                              "parametrization": "logit(p_cal)=a*logit(s_raw)+b",
                              "priors": {"a": "N(1,1)", "b": "N(0,1)"},
                              "n_val": int(len(y)), "seed": seed})
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (out_dir / "MODEL_CARD.md").write_text(_model_card(version, metrics))
    print(f"saved -> {out_dir}")
    return metrics


def _model_card(version: str, m: dict) -> str:
    return f"""# Model Card: bayesian_calibration ({version})

Bayesian logistic recalibration of `{m['base_model']}` raw fraud scores.

- **Fit data**: validation split of synthetic_nigeria transactions
  (n={m['n_val']}, base rate {m['val_base_rate']:.4f}) — provenance: **synthetic**.
- **Model**: logit(p_cal) = a·logit(s_raw) + b; priors a~N(1,1), b~N(0,1).
- **Inference**: {m['sampler']} (ml.bayesian.mcmc, {m['n_chains']} chains ×
  {m['n_samples_per_chain']} samples, burn {m['burn']}).
  Production may swap in NumPyro; artifact contract = posterior.npz samples.

## Posterior

| Param | Mean | SD | 95% CI | R-hat | ESS |
|---|---|---|---|---|---|
| a | {m['posterior_mean_a']:.4f} | {m['posterior_sd_a']:.4f} | [{m['ci95_a'][0]:.4f}, {m['ci95_a'][1]:.4f}] | {m['rhat'][0]:.4f} | {m['ess'][0]:.0f} |
| b | {m['posterior_mean_b']:.4f} | {m['posterior_sd_b']:.4f} | [{m['ci95_b'][0]:.4f}, {m['ci95_b'][1]:.4f}] | {m['rhat'][1]:.4f} | {m['ess'][1]:.0f} |

## Calibration metrics (in-sample on validation split)

| Metric | Before | After |
|---|---|---|
| ECE (15 bins) | {m['ece_before']:.4f} | {m['ece_after']:.4f} |
| Brier | {m['brier_before']:.4f} | {m['brier_after']:.4f} |
| NLL | {m['nll_before']:.4f} | {m['nll_after']:.4f} |

## Limitations

- Fit on synthetic data only; recalibrate on real labelled traffic before
  production use.
- Metrics above are in-sample (same validation split used for fitting);
  expect mild optimism.
- Credible intervals reflect parameter uncertainty only, not model
  misspecification.
"""


# ---------------------------------------------------------------------------
# Calibrator (used by serving + predict)
# ---------------------------------------------------------------------------
class BayesianCalibrator:
    """Loads a fitted posterior and maps raw scores -> calibrated probability
    with a credible interval from the posterior samples."""

    def __init__(self, artifact_dir: str | Path):
        d = Path(artifact_dir)
        post = mcmc.load_posterior(d / "posterior.npz")
        self.samples = post["samples"].reshape(-1, len(post["param_names"]))
        self.param_names = post["param_names"]
        self.version = post["meta"].get("version", d.name)
        self.meta = post["meta"]
        self.posterior_version = f"bayesian_calibration/{self.version}"

    def calibrate(self, raw_scores) -> dict:
        """raw_scores: scalar or array in (0,1). Returns dict of arrays with
        calibrated mean probability and 95% equal-tailed credible interval."""
        s = np.atleast_1d(np.asarray(raw_scores, dtype=np.float64))
        z = _logit(s)
        a = self.samples[:, 0:1]
        b = self.samples[:, 1:2]
        p = 1.0 / (1.0 + np.exp(-(a * z[None, :] + b)))
        return {"calibrated_probability": p.mean(axis=0),
                "ci95_lo": np.quantile(p, 0.025, axis=0),
                "ci95_hi": np.quantile(p, 0.975, axis=0)}

    def calibrate_one(self, raw_score: float) -> dict:
        out = self.calibrate([raw_score])
        return {"raw_score": float(raw_score),
                "calibrated_probability": float(out["calibrated_probability"][0]),
                "ci95": [float(out["ci95_lo"][0]), float(out["ci95_hi"][0])],
                "posterior_version": self.posterior_version}


def default_artifact_dir() -> Path:
    return ARTIFACT_ROOT / "bayesian_calibration" / "v1"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--fraud-version", default="v3")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-samples", type=int, default=4000)
    ap.add_argument("--burn", type=int, default=2000)
    a = ap.parse_args()
    fit(fraud_version=a.fraud_version, version=a.version, seed=a.seed,
        n_samples=a.n_samples, burn=a.burn)
