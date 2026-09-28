"""Post-defense evasion re-evaluation for fraud_net.

Implements and evaluates four defense layers against the PGD evasion attack
from ``ml.adversarial.evasion_eval`` (same artifact, same test split, same
epsilon grid):

1. **Input clipping / quantization** — standardized numerics clamped to
   +/-5 sigma and rounded to a 0.05-sigma grid; binary flags snapped. This
   destroys sub-quantization perturbations, which is where small-epsilon
   FGSM noise lives.
2. **Ensemble with deterministic rules** — the model score is blended with a
   non-differentiable rule score derived from high-signal fraud indicators
   (sim swap, emulator, receiver fan-in, amount vs sender average, new
   device). The attacker's gradient flows only through the neural net, so
   evasion must overcome a gradient-free component.
3. **Randomized smoothing-lite** — the score is averaged over N Gaussian
   noise draws (sigma in standardized space), approximating a smoothed
   classifier (Cohen et al. 2019, without certification). Deterministic seed.
4. **Adversarial training** — now implemented in
   ``ml/adversarial/adv_train.py`` (constrained PGD training from v3 init ->
   fraud_net v4 artifact); measured v3-vs-v4 results and residual risk in
   ``docs/ADVERSARIAL_TRAINING.md``.

Usage
-----
    python -m ml.adversarial.defenses \
        --out ml/adversarial/reports/defenses_report.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.data.synthetic_nigeria import NUMERIC_FEATURES  # noqa: E402
from ml.adversarial.evasion_eval import (  # noqa: E402
    BINARY_FEATURES, BLOCK_THRESHOLD, DEFAULT_EPSILON_GRID, REPORT_DIR,
    REVIEW_THRESHOLD, NumericOnlyWrapper, evasion_success_rate,
    evaluate_probs, load_test_split, pgd, project_constraints,
    standardized_bounds)

DEFAULT_DEFENSE_EPSILONS = (0.0, 0.25, 0.5, 1.0)


# ---------------------------------------------------------------------------
# Defense transforms
# ---------------------------------------------------------------------------

def clip_quantize(x_std: torch.Tensor, mean: torch.Tensor, std: torch.Tensor,
                  clip_z: float = 5.0, quantum: float = 0.05) -> torch.Tensor:
    """Clip to +/-clip_z sigma and quantize standardized values to a grid."""
    z = x_std.clamp(-clip_z, clip_z)
    z = torch.round(z / quantum) * quantum
    for i, f in enumerate(NUMERIC_FEATURES):
        if f in BINARY_FEATURES:
            raw = z[:, i] * std[i] + mean[i]
            z[:, i] = (torch.round(raw.clamp(0.0, 1.0)) - mean[i]) / std[i]
    return z


def rule_score(x_raw: torch.Tensor) -> torch.Tensor:
    """Deterministic, non-differentiable fraud-rule score in [0,1].

    Encodes analyst knowledge of Nigerian fraud typologies; mirrors signals
    the rules engine already surfaces (sim-swap, emulator, mule fan-in).
    """
    idx = {f: i for i, f in enumerate(NUMERIC_FEATURES)}
    score = torch.zeros(len(x_raw))
    score += 0.35 * (x_raw[:, idx["sim_swap_7d"]] >= 1).float()
    score += 0.25 * (x_raw[:, idx["device_emulator"]] >= 1).float()
    score += 0.20 * (x_raw[:, idx["receiver_fanin_72h"]] >= 5).float()
    score += 0.10 * (x_raw[:, idx["amount_vs_sender_avg"]] >= 10).float()
    score += 0.10 * (x_raw[:, idx["new_device"]] >= 1).float()
    return score.clamp(0.0, 1.0)


def smoothed_probs(wrapper: NumericOnlyWrapper, x_std: torch.Tensor,
                   sigma: float = 0.1, n_samples: int = 25,
                   seed: int = 0) -> torch.Tensor:
    """Noise-averaged fraud probability (randomized smoothing-lite)."""
    g = torch.Generator().manual_seed(seed)
    total = torch.zeros(len(x_std))
    with torch.no_grad():
        for _ in range(n_samples):
            noise = torch.randn(x_std.shape, generator=g) * sigma
            total += wrapper.prob(x_std + noise)
    return total / n_samples


# ---------------------------------------------------------------------------
# Gradient-masking-aware attacks: BPDA-lite and EOT
# ---------------------------------------------------------------------------

def smoothed_logits(wrapper: NumericOnlyWrapper, x_std: torch.Tensor,
                    sigma: float, n_samples: int,
                    seed: int = 0) -> torch.Tensor:
    """Differentiable Monte-Carlo smoothed logits: mean over N noise draws
    of the model's calibrated logit. EOT attacks differentiate through this.
    Noise is fixed by ``seed`` so the attack is deterministic."""
    g = torch.Generator().manual_seed(seed)
    total = torch.zeros(len(x_std))
    for _ in range(n_samples):
        noise = torch.randn(x_std.shape, generator=g) * sigma
        total = total + wrapper(x_std + noise)
    return total / n_samples


def bpda_lite_pgd(wrapper: NumericOnlyWrapper, x: torch.Tensor,
                  y: torch.Tensor, eps: float, steps: int, lo, hi, mean,
                  std, random_start: bool = True) -> torch.Tensor:
    """BPDA-lite (Athalye et al. 2018, sec. 4.2): attack the *smoothed*
    score while approximating the smoothing transform's gradient with the
    identity — i.e. the gradient is taken through the raw model only,
    exactly the plain PGD gradient, while success is measured against the
    defended (smoothed) output. The perturbation returned here is therefore
    identical to plain PGD; the difference vs the oblivious eval is purely
    which score the evasion metric is computed on."""
    return pgd(wrapper, x, y, eps, steps, lo, hi, mean, std,
               random_start=random_start)


def eot_pgd(wrapper: NumericOnlyWrapper, x: torch.Tensor, y: torch.Tensor,
            eps: float, steps: int, lo, hi, mean, std,
            sigma: float = 0.1, n_samples: int = 10, seed: int = 0,
            random_start: bool = True) -> torch.Tensor:
    """EOT-PGD (Athalye et al. 2018, sec. 5): gradient of the *expectation
    over the random transformation* — differentiate through the mean of
    ``n_samples`` noisy forward passes (a small-sample estimate of the true
    smoothed gradient). This is the correct adaptive attack against the
    smoothing defense; BPDA-lite is the cheaper approximation."""
    if eps <= 0:
        return x.clone()
    alpha = max(eps / max(steps // 2, 1), eps / 10)
    x_adv = x.clone()
    if random_start:
        x_adv = x_adv + torch.empty_like(x_adv).uniform_(-eps, eps)
        x_adv = project_constraints(x_adv, x, eps, lo, hi, mean, std)
    for t in range(steps):
        x_adv = x_adv.detach().requires_grad_(True)
        logits = smoothed_logits(wrapper, x_adv, sigma, n_samples,
                                 seed=seed + t)
        loss = torch.nn.functional.binary_cross_entropy_with_logits(
            logits, y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = project_constraints(x_adv.detach() + alpha * grad.sign(),
                                    x, eps, lo, hi, mean, std)
    return x_adv.detach()


def evaluate_gradient_masking(version: str = "v3",
                              max_samples: int | None = 2000,
                              epsilon_grid=(0.5, 1.0), pgd_steps: int = 20,
                              sigma: float = 0.1, smoothing_eval_n: int = 25,
                              eot_n: int = 10, seed: int = 0) -> dict:
    """Adaptive-attack evaluation of the smoothing defense for ``version``.

    Compares, per epsilon:
      * oblivious:  plain PGD scored against the smoothed output == BPDA-lite
        (identity-approximation gradient) — same perturbation;
      * EOT:        gradient through the Monte-Carlo smoothed logits.

    If EOT evasion >> BPDA-lite evasion, the defense's robustness is
    gradient masking, not true robustness.
    """
    torch.manual_seed(seed)
    x_std, x_cat, y, x_raw, model, mean_np, std_np = load_test_split(
        version, max_samples=max_samples, seed=seed)
    wrapper = NumericOnlyWrapper(model, x_cat)
    mean_t, std_t = torch.from_numpy(mean_np), torch.from_numpy(std_np)
    lo, hi = standardized_bounds(mean_np, std_np)
    y_np = y.numpy()

    clean_smooth = smoothed_probs(wrapper, x_std, sigma=sigma,
                                  n_samples=smoothing_eval_n, seed=seed)
    results = {
        "model": "fraud_net", "version": version,
        "n_samples": len(y_np),
        "defense": f"smoothing sigma={sigma}, eval_n={smoothing_eval_n}",
        "clean_smoothed": evaluate_probs(clean_smooth.numpy(), y_np),
        "attacks": [],
    }
    for eps in epsilon_grid:
        for attack_name, attack_fn in (
                ("bpda_lite", lambda: bpda_lite_pgd(
                    wrapper, x_std, y, eps, pgd_steps, lo, hi,
                    mean_t, std_t)),
                ("eot", lambda: eot_pgd(
                    wrapper, x_std, y, eps, pgd_steps, lo, hi, mean_t, std_t,
                    sigma=sigma, n_samples=eot_n, seed=seed))):
            x_adv = attack_fn() if eps > 0 else x_std.clone()
            probs = smoothed_probs(wrapper, x_adv, sigma=sigma,
                                   n_samples=smoothing_eval_n, seed=seed)
            row = {
                "attack": attack_name, "epsilon": eps,
                **evaluate_probs(probs.numpy(), y_np),
                "evasion@review": evasion_success_rate(
                    clean_smooth.numpy(), probs.numpy(), y_np,
                    REVIEW_THRESHOLD),
                "evasion@block": evasion_success_rate(
                    clean_smooth.numpy(), probs.numpy(), y_np,
                    BLOCK_THRESHOLD),
            }
            results["attacks"].append(row)
            print(f"[{version}/{attack_name}] eps={eps:<5} "
                  f"auc_pr={row['auc_pr']:.4f} "
                  f"evade@0.3={row['evasion@review']['success_rate']:.3f}",
                  flush=True)
    return results


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _perturb_raw(x_adv_std: torch.Tensor, mean: torch.Tensor,
                 std: torch.Tensor) -> torch.Tensor:
    """Raw feature values from standardized (approximate inverse)."""
    return x_adv_std * std + mean


def evaluate_defenses(version: str = "v3", max_samples: int | None = 4000,
                      epsilon_grid=DEFAULT_DEFENSE_EPSILONS,
                      pgd_steps: int = 20, seed: int = 0,
                      smoothing_samples: int = 25,
                      smoothing_sigma: float = 0.1,
                      ensemble_weight: float = 0.5) -> dict:
    torch.manual_seed(seed)
    x_std, x_cat, y, x_raw, model, mean_np, std_np = load_test_split(
        version, max_samples=max_samples, seed=seed)
    wrapper = NumericOnlyWrapper(model, x_cat)
    mean_t = torch.from_numpy(mean_np)
    std_t = torch.from_numpy(std_np)
    lo, hi = standardized_bounds(mean_np, std_np)
    y_np = y.numpy()

    def model_probs(x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            return wrapper.prob(x)

    defenses: dict[str, dict] = {
        "none": {"description": "undefended baseline (PGD, constrained)"},
        "clip_quantize": {"description":
                          "clamp +/-5 sigma, quantize to 0.05-sigma grid, "
                          "snap binary flags"},
        "ensemble_rules": {"description":
                           f"blend: {ensemble_weight:.1f}*model + "
                           f"{1-ensemble_weight:.1f}*rule_score "
                           "(non-differentiable rules)"},
        "smoothing": {"description":
                      f"mean prob over {smoothing_samples} N(0, "
                      f"{smoothing_sigma}) noise draws (smoothing-lite)"},
    }

    rows = []
    for name, meta in defenses.items():
        for eps in epsilon_grid:
            x_adv = pgd(wrapper, x_std, y, eps, pgd_steps, lo, hi,
                        mean_t, std_t) if eps > 0 else x_std.clone()
            # raw features under attack = true raw + exact standardized
            # delta (avoids float roundtrip artifacts at eps=0)
            x_adv_raw = x_raw + (x_adv - x_std) * std_t
            if name == "none":
                probs = model_probs(x_adv)
            elif name == "clip_quantize":
                probs = model_probs(clip_quantize(x_adv, mean_t, std_t))
            elif name == "ensemble_rules":
                p_model = model_probs(x_adv)
                p_rule = rule_score(x_adv_raw)
                probs = ensemble_weight * p_model + (1 - ensemble_weight) * p_rule
            else:  # smoothing
                probs = smoothed_probs(wrapper, x_adv, sigma=smoothing_sigma,
                                       n_samples=smoothing_samples, seed=seed)
            probs_np = probs.numpy()
            # clean reference for this defense at eps=0 is recomputed from
            # the same transform, so deltas are apples-to-apples
            row = {
                "defense": name, "epsilon": eps,
                **evaluate_probs(probs_np, y_np),
                "evasion@review": evasion_success_rate(
                    _clean_probs(name, wrapper, x_std, x_raw, mean_t, std_t,
                                 ensemble_weight, smoothing_samples,
                                 smoothing_sigma, seed).numpy(),
                    probs_np, y_np, REVIEW_THRESHOLD),
                "evasion@block": evasion_success_rate(
                    _clean_probs(name, wrapper, x_std, x_raw, mean_t, std_t,
                                 ensemble_weight, smoothing_samples,
                                 smoothing_sigma, seed).numpy(),
                    probs_np, y_np, BLOCK_THRESHOLD),
            }
            rows.append(row)
            print(f"[{name}] eps={eps:<5} auc_pr={row['auc_pr']:.4f} "
                  f"evade@0.3={row['evasion@review']['success_rate']:.3f}")

    return {
        "model": "fraud_net", "version": version,
        "n_samples": len(y_np), "base_rate": float(y_np.mean()),
        "attack": f"constrained PGD (steps={pgd_steps}), torch engine",
        "epsilon_units": "L_inf in standardized (z-score) feature space",
        "ensemble_weight": ensemble_weight,
        "smoothing": {"sigma": smoothing_sigma, "n": smoothing_samples},
        "defenses": defenses, "results": rows,
    }


def _clean_probs(name, wrapper, x_std, x_raw, mean_t, std_t,
                 ensemble_weight, smoothing_samples, smoothing_sigma, seed):
    """Clean (unperturbed) scores under the given defense transform."""
    if name == "clip_quantize":
        x_eval = clip_quantize(x_std, mean_t, std_t)
    else:
        x_eval = x_std
    if name == "ensemble_rules":
        with torch.no_grad():
            p_model = wrapper.prob(x_eval)
        return ensemble_weight * p_model + (1 - ensemble_weight) * rule_score(x_raw)
    if name == "smoothing":
        return smoothed_probs(wrapper, x_eval, sigma=smoothing_sigma,
                              n_samples=smoothing_samples, seed=seed)
    with torch.no_grad():
        return wrapper.prob(x_eval)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def render_report(results: dict) -> str:
    lines = [
        "# fraud_net post-defense evasion report",
        "",
        f"- Attack: {results['attack']} — {results['epsilon_units']}",
        f"- Eval set: held-out test split, n={results['n_samples']}, "
        f"base rate={results['base_rate']:.4f}",
        f"- Ensemble blend: {results['ensemble_weight']:.1f}*model + "
        f"{1-results['ensemble_weight']:.1f}*rules",
        f"- Smoothing: {results['smoothing']['n']} draws, "
        f"sigma={results['smoothing']['sigma']}",
        "",
        "## Defenses evaluated",
        "",
    ]
    for name, meta in results["defenses"].items():
        lines.append(f"- **{name}** — {meta['description']}")
    lines += [
        "- **adversarial_training** — implemented in "
        "`ml/adversarial/adv_train.py` (constrained PGD training from v3 "
        "init -> fraud_net v4); measured comparison in "
        "`docs/ADVERSARIAL_TRAINING.md`.",
        "",
        "## Results (AUC-PR / evasion success under constrained PGD)",
        "",
        "| defense | eps | AUC-PR | AUC-ROC | evasion@0.3 | evasion@0.8 |",
        "|---|---|---|---|---|---|",
    ]
    for r in results["results"]:
        lines.append(
            f"| {r['defense']} | {r['epsilon']} | {r['auc_pr']:.4f} | "
            f"{r['auc_roc']:.4f} | "
            f"{r['evasion@review']['success_rate']:.3f} "
            f"({r['evasion@review']['evaded']}/{r['evasion@review']['fraud_detected_clean']}) | "
            f"{r['evasion@block']['success_rate']:.3f} "
            f"({r['evasion@block']['evaded']}/{r['evasion@block']['fraud_detected_clean']}) |")

    base_worst = max((r for r in results["results"] if r["defense"] == "none"),
                     key=lambda r: r["evasion@review"]["success_rate"])
    best_by_eps: dict[float, dict] = {}
    for r in results["results"]:
        if r["defense"] == "none":
            continue
        cur = best_by_eps.get(r["epsilon"])
        if cur is None or r["evasion@review"]["success_rate"] < cur["evasion@review"]["success_rate"]:
            best_by_eps[r["epsilon"]] = r
    lines += ["", "## Residual risk", ""]
    lines.append(
        f"- Undefended worst-case evasion@0.3: "
        f"**{base_worst['evasion@review']['success_rate']:.1%}** at "
        f"eps={base_worst['epsilon']} (AUC-PR {base_worst['auc_pr']:.4f}).")
    for eps in sorted(best_by_eps):
        r = best_by_eps[eps]
        lines.append(
            f"- eps={eps}: best defense = **{r['defense']}**, residual "
            f"evasion@0.3 = {r['evasion@review']['success_rate']:.1%}, "
            f"AUC-PR {r['auc_pr']:.4f}.")
    lines += [
        "",
        "Residual-risk notes:",
        "",
        "1. **Adaptive attackers remain.** All defenses except the rule "
        "ensemble are differentiable or noise-averaged; BPDA/Expectation-over-"
        "Transformation attacks can partially bypass gradient masking. The "
        "rule ensemble is gradient-free but its thresholds are probed easily "
        "— treat it as a cost-raiser, not a guarantee.",
        "2. **Clean-accuracy cost.** Quantization and smoothing degrade clean "
        "AUC-PR; the tables above quantify the trade-off per defense.",
        "3. **Feature-recapture risk.** A fraudster who cannot perturb "
        "features enough may instead change behaviour so the *raw* features "
        "look benign (low velocity, aged devices, no fan-in). Defenses here "
        "only cover numeric perturbation, not behavioural mimicry; that is "
        "covered by the velocity/rule layer and GNN mule detection.",
        "4. **Next steps.** Adversarial training is now implemented "
        "(`ml/adversarial/adv_train.py`, v4 artifact) — see "
        "`docs/ADVERSARIAL_TRAINING.md` for the measured (mixed) outcome; "
        "certify with randomized smoothing at the review threshold; re-run "
        "this evaluation on every model promotion (wire into registry "
        "promotion gates).",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default="v3")
    ap.add_argument("--max-samples", type=int, default=4000)
    ap.add_argument("--epsilon-grid",
                    default=",".join(map(str, DEFAULT_DEFENSE_EPSILONS)))
    ap.add_argument("--pgd-steps", type=int, default=20)
    ap.add_argument("--smoothing-samples", type=int, default=25)
    ap.add_argument("--smoothing-sigma", type=float, default=0.1)
    ap.add_argument("--ensemble-weight", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=str(REPORT_DIR / "defenses_report.md"))
    ap.add_argument("--json-out",
                    default=str(REPORT_DIR / "defenses_report.json"))
    args = ap.parse_args(argv)

    grid = tuple(float(e) for e in args.epsilon_grid.split(",") if e != "")
    results = evaluate_defenses(
        version=args.version, max_samples=args.max_samples,
        epsilon_grid=grid, pgd_steps=args.pgd_steps, seed=args.seed,
        smoothing_samples=args.smoothing_samples,
        smoothing_sigma=args.smoothing_sigma,
        ensemble_weight=args.ensemble_weight)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(results))
    Path(args.json_out).write_text(json.dumps(results, indent=2))
    print(f"wrote {out}")
    return results


if __name__ == "__main__":
    main()
