"""Deep autoencoder for unsupervised anomaly (novelty fraud) detection.

Trained on legitimate transactions only; reconstruction error is the anomaly
score."""
from __future__ import annotations

import torch
import torch.nn as nn


class FraudAutoencoder(nn.Module):
    def __init__(self, in_dim: int, latent: int = 6, hidden: int = 32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, hidden), nn.ReLU(),
            nn.Linear(hidden, hidden // 2), nn.ReLU(),
            nn.Linear(hidden // 2, latent),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden // 2), nn.ReLU(),
            nn.Linear(hidden // 2, hidden), nn.ReLU(),
            nn.Linear(hidden, in_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample MSE reconstruction error."""
        rec = self.forward(x)
        return ((rec - x) ** 2).mean(dim=1)
