"""Identity (biometric / document) embedding network.

Projects a capture-SDK feature vector (face or document feature vector) into a
128-d embedding space trained with a margin contrastive loss so that samples
of the same identity cluster and different identities separate.

The service hook `services/python/identity-theft-detector` loads this model
either as a TorchScript file (preferred — no code dependency) or, if the
service shipped a `model_def.py`, as a state_dict. Both artifacts are
produced by `ml/train/train_embedder.py`.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

# Input contract: the capture SDK emits a fixed-length float32 feature vector.
# 128 matches the identity-theft-detector default IDENTITY_EMBEDDING_DIM.
DEFAULT_INPUT_DIM = 128
DEFAULT_EMBED_DIM = 128


class IdentityEmbedder(nn.Module):
    """Small MLP projector: in_dim -> 256 -> embed_dim (L2-normalised).

    L2 normalisation inside the module keeps the TorchScript/ONNX exports
    self-contained; the service additionally normalises defensively.
    """

    def __init__(self, in_dim: int = DEFAULT_INPUT_DIM,
                 embed_dim: int = DEFAULT_EMBED_DIM, hidden: int = 256):
        super().__init__()
        self.in_dim = in_dim
        self.embed_dim = embed_dim
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.BatchNorm1d(hidden),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden, hidden),
            nn.BatchNorm1d(hidden),
            nn.ReLU(),
            nn.Linear(hidden, embed_dim, bias=False),
        )
        # affine-free BN centres embeddings before normalisation, preventing
        # collapse onto a shared constant direction (impostor-sim inflation).
        self.center = nn.BatchNorm1d(embed_dim, affine=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.center(self.net(x))
        return F.normalize(z, p=2, dim=-1)


class ContrastiveLoss(nn.Module):
    """Margin contrastive loss (Hadsell et al.) on embedding pairs.

    y=1 for same-identity pairs, y=0 for different-identity pairs.
    """

    def __init__(self, margin: float = 1.0):
        super().__init__()
        self.margin = margin

    def forward(self, z1: torch.Tensor, z2: torch.Tensor,
                y: torch.Tensor) -> torch.Tensor:
        d = F.pairwise_distance(z1, z2)
        pos = y * d.pow(2)
        neg = (1 - y) * F.relu(self.margin - d).pow(2)
        return (pos + neg).mean()


def cosine_similarity(z1: torch.Tensor, z2: torch.Tensor) -> torch.Tensor:
    return F.cosine_similarity(z1, z2, dim=-1)
