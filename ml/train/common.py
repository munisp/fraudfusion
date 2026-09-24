"""Shared training utilities: metrics, early stopping, seeds, artifacts."""
from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

ML_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ML_ROOT.parent))
DATA_DIR = Path(os.environ.get("FRAUDFUSION_DATA", ML_ROOT / "data" / "generated"))
ARTIFACT_ROOT = ML_ROOT / "artifacts"


def set_seed(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(False)


def metrics_dict(y_true, y_score, fixed_fpr: float = 0.01) -> dict:
    y_true = np.asarray(y_true)
    y_score = np.asarray(y_score)
    out = {
        "auc_pr": float(average_precision_score(y_true, y_score)),
        "auc_roc": float(roc_auc_score(y_true, y_score)),
        "f1": float(f1_score(y_true, y_score > 0.5)),
        "base_rate": float(y_true.mean()),
    }
    # recall @ fixed FPR
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(y_true, y_score)
    idx = np.searchsorted(fpr, fixed_fpr, side="right") - 1
    out[f"recall_at_fpr_{fixed_fpr}"] = float(tpr[max(idx, 0)])
    return out


class EarlyStopper:
    def __init__(self, patience: int = 5, mode: str = "max"):
        self.patience, self.mode = patience, mode
        self.best = None
        self.bad_epochs = 0
        self.best_state = None

    def step(self, value: float, model: torch.nn.Module) -> bool:
        improved = (self.best is None or
                    (value > self.best if self.mode == "max" else value < self.best))
        if improved:
            self.best = value
            self.bad_epochs = 0
            self.best_state = {k: v.detach().clone()
                               for k, v in model.state_dict().items()}
        else:
            self.bad_epochs += 1
        return self.bad_epochs >= self.patience


def save_artifacts(model_name: str, version: str, model: torch.nn.Module,
                   metrics: dict, extra_files: dict[str, str] | None = None,
                   provenance: str = "synthetic") -> Path:
    """Save weights + metrics.json + model card under artifacts/<name>/<ver>/."""
    dest = ARTIFACT_ROOT / model_name / version
    dest.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), dest / "weights.pt")
    (dest / "metrics.json").write_text(json.dumps(metrics, indent=2))
    if extra_files:
        for fname, content in extra_files.items():
            (dest / fname).write_text(content)
    return dest


def model_card(model_name: str, version: str, metrics: dict,
               data_desc: str, notes: str = "") -> str:
    lines = [
        f"# Model Card: {model_name} ({version})",
        "",
        f"- **Training data**: {data_desc} (provenance: **synthetic** — no real fraud data)",
        f"- **Framework**: PyTorch {torch.__version__} (CPU)",
        "",
        "## Metrics (held-out test split)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for k, v in metrics.items():
        if isinstance(v, float):
            lines.append(f"| {k} | {v:.4f} |")
        else:
            lines.append(f"| {k} | {v} |")
    lines += ["", "## Limitations", "",
              "- Trained exclusively on synthetic data; performance on real "
              "Nigerian production traffic is unvalidated.",
              "- Fraud labels contain ~2% injected noise by design.",
              "- Model is a baseline, not production-ready." + (" " + notes if notes else ""),
              ""]
    return "\n".join(lines)
