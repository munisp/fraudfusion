"""Tabular fraud classifier: MLP with categorical embeddings + numeric
normalization, focal loss for class imbalance, temperature scaling for
calibration."""
from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

EMBED_DIM = 8


class FraudNet(nn.Module):
    def __init__(self, cat_cardinalities: dict[str, int], n_numeric: int,
                 hidden: int = 128, dropout: float = 0.3):
        super().__init__()
        self.cat_names = sorted(cat_cardinalities)
        self.embeddings = nn.ModuleDict({
            name: nn.Embedding(card + 1, EMBED_DIM)  # +1 for UNK=0
            for name, card in cat_cardinalities.items()
        })
        self.num_norm = nn.BatchNorm1d(n_numeric)
        in_dim = n_numeric + EMBED_DIM * len(self.cat_names)
        self.mlp = nn.Sequential(
            nn.Linear(in_dim, hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, 64), nn.ReLU(),
            nn.Linear(64, 1),
        )
        # temperature for calibration (log-initialized to 0 => T=1)
        self.log_temperature = nn.Parameter(torch.zeros(1))

    def forward(self, x_num: torch.Tensor, x_cat: torch.Tensor) -> torch.Tensor:
        embs = [self.embeddings[name](x_cat[:, i])
                for i, name in enumerate(self.cat_names)]
        z = torch.cat([self.num_norm(x_num)] + embs, dim=1)
        return self.mlp(z).squeeze(-1)  # raw logits

    def calibrated_logits(self, x_num, x_cat):
        return self.forward(x_num, x_cat) / self.log_temperature.exp().clamp(0.05, 100)

    def prob(self, x_num, x_cat, calibrated: bool = True):
        logits = self.calibrated_logits(x_num, x_cat) if calibrated else self.forward(x_num, x_cat)
        return torch.sigmoid(logits)


class FocalLoss(nn.Module):
    """Binary focal loss (Lin et al. 2017)."""

    def __init__(self, alpha: float = 0.25, gamma: float = 2.0):
        super().__init__()
        self.alpha, self.gamma = alpha, gamma

    def forward(self, logits, targets):
        bce = F.binary_cross_entropy_with_logits(logits, targets, reduction="none")
        p = torch.sigmoid(logits)
        pt = torch.where(targets == 1, p, 1 - p)
        w = torch.where(targets == 1, self.alpha, 1 - self.alpha)
        return (w * (1 - pt) ** self.gamma * bce).mean()


def fit_temperature(model: FraudNet, x_num, x_cat, y, max_iter: int = 200) -> float:
    """Temperature scaling on validation logits (Guo et al. 2017)."""
    model.eval()
    with torch.no_grad():
        logits = model(x_num, x_cat)
    log_t = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([log_t], lr=0.05, max_iter=max_iter)
    y = y.float()

    def closure():
        opt.zero_grad()
        loss = F.binary_cross_entropy_with_logits(logits / log_t.exp().clamp(0.05, 100), y)
        loss.backward()
        return loss

    opt.step(closure)
    with torch.no_grad():
        model.log_temperature.copy_(log_t.detach())
    return float(np.exp(log_t.item()))


def encode_categoricals(df, cat_features, vocab: dict | None = None):
    """Map categorical strings to ids; 0 = UNK. Returns (ids, vocab).

    Columns are emitted in sorted(cat_features) order to match model
    embedding ModuleDict ordering."""
    cat_features = sorted(cat_features)
    if vocab is None:
        vocab = {}
        for c in cat_features:
            vals = sorted(df[c].astype(str).unique())
            vocab[c] = {v: i + 1 for i, v in enumerate(vals)}
    ids = np.zeros((len(df), len(cat_features)), dtype=np.int64)
    for j, c in enumerate(cat_features):
        m = vocab[c]
        ids[:, j] = df[c].astype(str).map(m).fillna(0).to_numpy()
    return ids, vocab


def cardinalities(vocab: dict) -> dict[str, int]:
    return {c: len(m) for c, m in vocab.items()}
