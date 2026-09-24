"""Evasion robustness evaluation of fraud_net against FGSM / PGD attacks.

Threat model
------------
A fraudster who knows (or probes) the scoring pipeline perturbs the *numeric*
transaction features of a fraudulent transaction to push the fraud probability
below the review/block threshold. Categorical features are held fixed (they
are discrete, and changing e.g. the sender bank is an operational act, not a
gradient perturbation). Attacks run in the model's standardized numeric space
with an L_inf budget epsilon (in standard-deviation units), projected onto
per-feature plausibility bounds so adversarial examples remain physically
possible transactions (amounts stay positive, hour in [0,23], binary flags in
{0,1}, velocities non-negative).

Engines
-------
* ``torch`` (default reference): hand-rolled FGSM/PGD with exact per-feature
  box projection. Supports the full plausibility constraint set.
* ``art``: Adversarial Robustness Toolbox (FastGradientMethod /
  ProjectedGradientDescent) driving the same torch model via a numeric-only
  wrapper, with global clip values derived from the feature bounds. Used as an
  independent cross-check of the hand-rolled attacks when ART is installed.

Usage
-----
    python -m ml.adversarial.evasion_eval \
        --version v3 --epsilon-grid 0,0.1,0.25,0.5,1.0 \
        --out ml/adversarial/reports/evasion_report.md
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import CATEGORICAL_FEATURES, NUMERIC_FEATURES  # noqa: E402
from ml.models.fraud_net import FraudNet, cardinalities, encode_categoricals  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
ART_ROOT = REPO / "ml" / "artifacts" / "fraud_net"
DATA_PATH = REPO / "ml" / "data" / "generated" / "transactions.parquet"
REPORT_DIR = Path(__file__).resolve().parent / "reports"

# Production decision thresholds (mirrors ml/inference/predict.py score_fraud).
BLOCK_THRESHOLD = 0.8
REVIEW_THRESHOLD = 0.3

# Per-feature plausibility bounds in RAW feature units. A perturbation that
# leaves these bounds produces a transaction that could never exist (negative
# amount, hour=30, ...), which would overstate the attack surface.
FEATURE_BOUNDS_RAW: dict[str, tuple[float, float]] = {
    "log_amount": (0.0, 20.0),               # amount = expm1(log_amount) > 0
    "hour": (0.0, 23.0),
    "dow": (0.0, 6.0),
    "is_month_end": (0.0, 1.0),
    "is_market_day": (0.0, 1.0),
    "amount_vs_sender_avg": (0.0, 50.0),     # generator clips to 50
    "sender_txns_24h": (0.0, 500.0),
    "sender_unique_receivers_72h": (0.0, 500.0),
    "receiver_fanin_72h": (0.0, 1000.0),
    "mins_since_last_txn": (0.0, 10080.0),   # one week in minutes
    "device_emulator": (0.0, 1.0),
    "sim_swap_7d": (0.0, 1.0),
    "new_device": (0.0, 1.0),
    "cross_state": (0.0, 1.0),
    "cross_bank": (0.0, 1.0),
    "is_night": (0.0, 1.0),
}
# Binary flags are additionally snapped to {0,1} after projection.
BINARY_FEATURES = {
    "is_month_end", "is_market_day", "device_emulator", "sim_swap_7d",
    "new_device", "cross_state", "cross_bank", "is_night",
}

DEFAULT_EPSILON_GRID = (0.0, 0.1, 0.25, 0.5, 1.0)


# ---------------------------------------------------------------------------
# Artifact / data loading
# ---------------------------------------------------------------------------

def load_artifact(version: str = "v3", artifact_root: Path = ART_ROOT):
    """Load fraud_net weights + preprocessing exactly as inference does."""
    d = artifact_root / version
    vocab = json.loads((d / "vocab.json").read_text())
    pre = np.load(d / "preprocess.npz")
    mean = pre["scaler_mean"].astype(np.float32)
    std = pre["scaler_std"].astype(np.float32)
    model = FraudNet(cardinalities(vocab), len(NUMERIC_FEATURES))
    model.load_state_dict(torch.load(d / "weights.pt", weights_only=True))
    model.eval()
    return model, vocab, mean, std


def load_test_split(version: str = "v3", max_samples: int | None = None,
                    data_path: Path = DATA_PATH, seed: int = 0):
    """Return (x_num_std, x_cat, y, x_num_raw) for the held-out test split."""
    import pandas as pd
    model, vocab, mean, std = load_artifact(version)
    df = pd.read_parquet(data_path)
    df = df[df["split"] == "test"].reset_index(drop=True)
    if max_samples and len(df) > max_samples:
        df = df.sample(n=max_samples, random_state=seed).reset_index(drop=True)
    x_raw = df[NUMERIC_FEATURES].to_numpy(np.float32)
    x_std = ((x_raw - mean) / std).astype(np.float32)
    x_cat, _ = encode_categoricals(df, CATEGORICAL_FEATURES, vocab)
    y = df["is_fraud"].to_numpy(np.float32)
    return (torch.from_numpy(x_std), torch.from_numpy(x_cat),
            torch.from_numpy(y), torch.from_numpy(x_raw), model, mean, std)


def standardized_bounds(mean: np.ndarray, std: np.ndarray):
    """Per-feature box bounds expressed in standardized space."""
    lo = np.zeros(len(NUMERIC_FEATURES), dtype=np.float32)
    hi = np.zeros(len(NUMERIC_FEATURES), dtype=np.float32)
    for i, f in enumerate(NUMERIC_FEATURES):
        blo, bhi = FEATURE_BOUNDS_RAW[f]
        lo[i] = (blo - mean[i]) / std[i]
        hi[i] = (bhi - mean[i]) / std[i]
    return torch.from_numpy(lo), torch.from_numpy(hi)


# ---------------------------------------------------------------------------
# Model wrapper (numeric-only view; categoricals frozen)
# ---------------------------------------------------------------------------

class NumericOnlyWrapper(torch.nn.Module):
    """Freeze categorical inputs so attacks differentiate numerics only."""

    def __init__(self, model: FraudNet, x_cat: torch.Tensor):
        super().__init__()
        self.model = model
        self.register_buffer("x_cat", x_cat)

    def forward(self, x_num_std: torch.Tensor) -> torch.Tensor:
        # calibrated logits: this is the score production decisions consume
        return self.model.calibrated_logits(x_num_std, self.x_cat)

    def prob(self, x_num_std: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.forward(x_num_std))


class TwoLogitAdapter(torch.nn.Module):
    """ART-compatible classifier view: outputs [benign, fraud] logits."""

    def __init__(self, wrapper: NumericOnlyWrapper):
        super().__init__()
        self.wrapper = wrapper

    def forward(self, x_num_std: torch.Tensor) -> torch.Tensor:
        z = self.wrapper(x_num_std)
        return torch.stack([-z, z], dim=1)


# ---------------------------------------------------------------------------
# Hand-rolled torch attacks (reference engine; exact box constraints)
# ---------------------------------------------------------------------------

def project_constraints(x_adv: torch.Tensor, x0: torch.Tensor, eps: float,
                        lo: torch.Tensor, hi: torch.Tensor,
                        mean: torch.Tensor, std: torch.Tensor,
                        snap_binary: bool = True) -> torch.Tensor:
    """Project onto L_inf ball around x0 AND per-feature plausibility box."""
    if eps > 0:
        x_adv = torch.max(torch.min(x_adv, x0 + eps), x0 - eps)
    x_adv = torch.max(torch.min(x_adv, hi), lo)
    if snap_binary:
        for i, f in enumerate(NUMERIC_FEATURES):
            if f in BINARY_FEATURES:
                raw = x_adv[:, i] * std[i] + mean[i]
                x_adv[:, i] = (torch.round(raw.clamp(0.0, 1.0)) - mean[i]) / std[i]
    return x_adv


def fgsm(wrapper: NumericOnlyWrapper, x: torch.Tensor, y: torch.Tensor,
         eps: float, lo, hi, mean, std) -> torch.Tensor:
    if eps <= 0:
        return x.clone()
    x_adv = x.clone().requires_grad_(True)
    loss = torch.nn.functional.binary_cross_entropy_with_logits(
        wrapper(x_adv), y)
    grad = torch.autograd.grad(loss, x_adv)[0]
    return project_constraints(x.detach() + eps * grad.sign(), x, eps,
                               lo, hi, mean, std).detach()


def pgd(wrapper: NumericOnlyWrapper, x: torch.Tensor, y: torch.Tensor,
        eps: float, steps: int, lo, hi, mean, std,
        random_start: bool = True) -> torch.Tensor:
    if eps <= 0:
        return x.clone()
    alpha = max(eps / max(steps // 2, 1), eps / 10)
    x_adv = x.clone()
    if random_start:
        x_adv = x_adv + torch.empty_like(x_adv).uniform_(-eps, eps)
        x_adv = project_constraints(x_adv, x, eps, lo, hi, mean, std)
    for _ in range(steps):
        x_adv = x_adv.detach().requires_grad_(True)
        loss = torch.nn.functional.binary_cross_entropy_with_logits(
            wrapper(x_adv), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = project_constraints(x_adv.detach() + alpha * grad.sign(),
                                    x, eps, lo, hi, mean, std)
    return x_adv.detach()


# ---------------------------------------------------------------------------
# ART adapter engine (cross-check; used when ART is installed)
# ---------------------------------------------------------------------------

def art_available() -> bool:
    try:
        import art  # noqa: F401
        return True
    except ImportError:
        return False


def _art_classifier(wrapper: NumericOnlyWrapper, lo: torch.Tensor,
                    hi: torch.Tensor):
    from art.estimators.classification import PyTorchClassifier
    adapter = TwoLogitAdapter(wrapper).eval()
    return PyTorchClassifier(
        model=adapter,
        loss=torch.nn.CrossEntropyLoss(),
        input_shape=(len(NUMERIC_FEATURES),),
        nb_classes=2,
        optimizer=torch.optim.Adam(adapter.parameters(), lr=0.0),
        clip_values=(float(lo.min()), float(hi.max())),
    )


def art_fgsm(wrapper, x, y, eps, lo, hi):
    from art.attacks.evasion import FastGradientMethod
    clf = _art_classifier(wrapper, lo, hi)
    attack = FastGradientMethod(estimator=clf, eps=eps, batch_size=4096)
    # NB: passing y to ART generate() makes the attack *targeted toward* y;
    # omit y for the untargeted (maximize loss on true label) attack.
    _ = y
    return torch.from_numpy(attack.generate(x.numpy()))


def art_pgd(wrapper, x, y, eps, steps, lo, hi):
    from art.attacks.evasion import ProjectedGradientDescent
    clf = _art_classifier(wrapper, lo, hi)
    attack = ProjectedGradientDescent(
        estimator=clf, eps=eps, eps_step=max(eps / max(steps // 2, 1), 1e-6),
        max_iter=steps, batch_size=4096, verbose=False)
    _ = y  # untargeted: see art_fgsm
    return torch.from_numpy(attack.generate(x.numpy()))


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def evaluate_probs(probs: np.ndarray, y: np.ndarray) -> dict:
    return {
        "auc_pr": float(average_precision_score(y, probs)),
        "auc_roc": float(roc_auc_score(y, probs)),
    }


def evasion_success_rate(probs_clean: np.ndarray, probs_adv: np.ndarray,
                         y: np.ndarray, threshold: float) -> dict:
    """Fraction of fraud txns that scored >= threshold clean and < threshold
    after the attack (successful evasions / detected fraud)."""
    fraud = y == 1
    detected = fraud & (probs_clean >= threshold)
    evaded = detected & (probs_adv < threshold)
    n = int(detected.sum())
    return {
        "threshold": threshold,
        "fraud_detected_clean": n,
        "evaded": int(evaded.sum()),
        "success_rate": float(evaded.sum() / n) if n else 0.0,
    }


def run_attack(wrapper, attack: str, engine: str, x, y, eps, steps,
               lo, hi, mean, std) -> torch.Tensor:
    if engine == "art":
        if attack == "fgsm":
            return art_fgsm(wrapper, x, y, eps, lo, hi)
        return art_pgd(wrapper, x, y, eps, steps, lo, hi)
    if attack == "fgsm":
        return fgsm(wrapper, x, y, eps, lo, hi, mean, std)
    return pgd(wrapper, x, y, eps, steps, lo, hi, mean, std)


def run_evaluation(version: str = "v3", max_samples: int | None = 4000,
                   epsilon_grid=DEFAULT_EPSILON_GRID, pgd_steps: int = 20,
                   engines: tuple[str, ...] = ("torch", "art"),
                   seed: int = 0, data_path: Path = DATA_PATH) -> dict:
    torch.manual_seed(seed)
    x_std, x_cat, y, x_raw, model, mean_np, std_np = load_test_split(
        version, max_samples, data_path, seed)
    wrapper = NumericOnlyWrapper(model, x_cat)
    mean_t = torch.from_numpy(mean_np)
    std_t = torch.from_numpy(std_np)
    lo, hi = standardized_bounds(mean_np, std_np)

    with torch.no_grad():
        probs_clean = wrapper.prob(x_std).numpy()
    y_np = y.numpy()
    results = {
        "model": "fraud_net", "version": version, "n_samples": len(y_np),
        "base_rate": float(y_np.mean()),
        "epsilon_units": "L_inf in standardized (z-score) feature space",
        "clean": evaluate_probs(probs_clean, y_np),
        "thresholds": {"review": REVIEW_THRESHOLD, "block": BLOCK_THRESHOLD},
        "attacks": [],
    }
    active_engines = [e for e in engines
                      if e != "art" or art_available()]
    for engine in active_engines:
        for attack in ("fgsm", "pgd"):
            for eps in epsilon_grid:
                t0 = time.time()
                x_adv = run_attack(wrapper, attack, engine, x_std, y, eps,
                                   pgd_steps, lo, hi, mean_t, std_t)
                with torch.no_grad():
                    probs_adv = wrapper.prob(x_adv).numpy()
                row = {
                    "engine": engine, "attack": attack, "epsilon": eps,
                    "pgd_steps": pgd_steps if attack == "pgd" else 1,
                    **evaluate_probs(probs_adv, y_np),
                    "evasion@review": evasion_success_rate(
                        probs_clean, probs_adv, y_np, REVIEW_THRESHOLD),
                    "evasion@block": evasion_success_rate(
                        probs_clean, probs_adv, y_np, BLOCK_THRESHOLD),
                    "mean_linf_z": float(
                        (x_adv - x_std).abs().max(dim=1).values.mean()),
                    "runtime_s": round(time.time() - t0, 2),
                }
                results["attacks"].append(row)
                print(f"[{engine}/{attack}] eps={eps:<5} "
                      f"auc_pr={row['auc_pr']:.4f} "
                      f"evade@0.3={row['evasion@review']['success_rate']:.3f}")
    results["clean"]["evasion@review"] = evasion_success_rate(
        probs_clean, probs_clean, y_np, REVIEW_THRESHOLD)
    results["clean"]["evasion@block"] = evasion_success_rate(
        probs_clean, probs_clean, y_np, BLOCK_THRESHOLD)
    return results


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def render_report(results: dict) -> str:
    c = results["clean"]
    lines = [
        "# fraud_net evasion robustness report",
        "",
        f"- Model: `{results['model']}` `{results['version']}` "
        f"(artifact `ml/artifacts/fraud_net/{results['version']}`)",
        f"- Eval set: held-out test split, n={results['n_samples']}, "
        f"fraud base rate={results['base_rate']:.4f}",
        f"- Perturbation budget: {results['epsilon_units']}; categorical "
        "features held fixed",
        "- Feature-space constraints enforced: per-feature plausibility box "
        "(amounts stay positive, hour in [0,23], velocities non-negative), "
        "binary flags snapped to {0,1} (see `FEATURE_BOUNDS_RAW` in "
        "`ml/adversarial/evasion_eval.py`)",
        f"- ART engine: "
        + ("available — torch hand-roll cross-checked against ART "
           "FastGradientMethod / ProjectedGradientDescent"
           if any(a["engine"] == "art" for a in results["attacks"])
           else "not installed — torch hand-rolled reference implementation "
                "used (ART adapter ships in this module as an optional "
                "engine)"),
        "",
        "## Clean baseline",
        "",
        f"- AUC-PR: **{c['auc_pr']:.4f}** | AUC-ROC: {c['auc_roc']:.4f}",
        f"- Fraud txns scoring >= review threshold "
        f"({REVIEW_THRESHOLD}): {c['evasion@review']['fraud_detected_clean']}",
        f"- Fraud txns scoring >= block threshold "
        f"({BLOCK_THRESHOLD}): {c['evasion@block']['fraud_detected_clean']}",
        "",
        "## Adversarial results",
        "",
        "| engine | attack | eps | AUC-PR | AUC-ROC | evasion@0.3 | evasion@0.8 | mean Linf (z) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for a in results["attacks"]:
        lines.append(
            f"| {a['engine']} | {a['attack']} | {a['epsilon']} | "
            f"{a['auc_pr']:.4f} | {a['auc_roc']:.4f} | "
            f"{a['evasion@review']['success_rate']:.3f} "
            f"({a['evasion@review']['evaded']}/{a['evasion@review']['fraud_detected_clean']}) | "
            f"{a['evasion@block']['success_rate']:.3f} "
            f"({a['evasion@block']['evaded']}/{a['evasion@block']['fraud_detected_clean']}) | "
            f"{a['mean_linf_z']:.3f} |")
    worst = max(results["attacks"],
                key=lambda a: a["evasion@review"]["success_rate"], default=None)
    lines += [
        "",
        "## Reading",
        "",
        "- `evasion@0.3` = fraction of fraud transactions that were flagged "
        "for review/block on clean features but dropped below the review "
        "threshold after perturbation (successful evasions).",
        "- AUC-PR under attack is computed over the full test set with every "
        "example adversarially perturbed (worst-case evaluation).",
    ]
    if worst:
        lines += [
            f"- **Worst case observed**: {worst['engine']}/{worst['attack']} "
            f"at eps={worst['epsilon']} evaded "
            f"{worst['evasion@review']['success_rate']:.1%} of flagged fraud "
            f"and cut AUC-PR from {c['auc_pr']:.4f} to {worst['auc_pr']:.4f}.",
        ]
    lines += [
        "",
        "Post-defense re-evaluation and residual risk: "
        "see `ml/adversarial/reports/defenses_report.md`.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default="v3")
    ap.add_argument("--max-samples", type=int, default=4000)
    ap.add_argument("--epsilon-grid", default=",".join(map(str, DEFAULT_EPSILON_GRID)))
    ap.add_argument("--pgd-steps", type=int, default=20)
    ap.add_argument("--engine", default="auto",
                    choices=["auto", "torch", "art", "both"])
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=str(REPORT_DIR / "evasion_report.md"))
    ap.add_argument("--json-out", default=str(REPORT_DIR / "evasion_report.json"))
    args = ap.parse_args(argv)

    engines = {
        "auto": ("torch", "art"),
        "torch": ("torch",),
        "art": ("art",),
        "both": ("torch", "art"),
    }[args.engine]
    grid = tuple(float(e) for e in args.epsilon_grid.split(",") if e != "")
    results = run_evaluation(version=args.version,
                             max_samples=args.max_samples,
                             epsilon_grid=grid, pgd_steps=args.pgd_steps,
                             engines=engines, seed=args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(results))
    Path(args.json_out).write_text(json.dumps(results, indent=2))
    print(f"wrote {out}")
    return results


if __name__ == "__main__":
    main()
