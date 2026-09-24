"""Credit default scorer: MLP producing PD (probability of default) plus a
score mapping (higher score = lower risk, 300-850 bureau-style scale)."""
from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn

EMBED_DIM = 6

CREDIT_NUMERIC = ["age", "monthly_income", "bureau_score", "loan_amount_ngn",
                  "loan_term_months", "dti", "past_delinquencies"]
CREDIT_CATEGORICAL = ["employment", "state", "bank", "purpose"]


class CreditNet(nn.Module):
    def __init__(self, cat_cardinalities: dict[str, int],
                 n_numeric: int = len(CREDIT_NUMERIC), hidden: int = 96,
                 dropout: float = 0.25):
        super().__init__()
        self.cat_names = sorted(cat_cardinalities)
        self.embeddings = nn.ModuleDict({
            name: nn.Embedding(card + 1, EMBED_DIM)
            for name, card in cat_cardinalities.items()
        })
        self.num_norm = nn.BatchNorm1d(n_numeric)
        in_dim = n_numeric + EMBED_DIM * len(self.cat_names)
        self.mlp = nn.Sequential(
            nn.Linear(in_dim, hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, hidden // 2), nn.ReLU(),
            nn.Linear(hidden // 2, 1),
        )

    def forward(self, x_num, x_cat):
        embs = [self.embeddings[n](x_cat[:, i]) for i, n in enumerate(self.cat_names)]
        z = torch.cat([self.num_norm(x_num)] + embs, dim=1)
        return self.mlp(z).squeeze(-1)

    def pd(self, x_num, x_cat) -> torch.Tensor:
        """Probability of default."""
        return torch.sigmoid(self.forward(x_num, x_cat))


def pd_to_score(pd: np.ndarray, base_score: float = 650.0,
                base_odds: float = 19.0, pdo: float = 40.0) -> np.ndarray:
    """Scorecard mapping: score = base - factor*ln(odds), odds = (1-PD)/PD."""
    pd = np.clip(pd, 1e-5, 1 - 1e-5)
    odds = (1 - pd) / pd
    factor = pdo / np.log(2)
    score = base_score + factor * np.log(odds / base_odds)
    return np.clip(score, 300, 850).round(1)
