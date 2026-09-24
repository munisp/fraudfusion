"""GNN for mule-account network detection.

Uses torch_geometric.SAGEConv when available; otherwise falls back to a clean
pure-PyTorch GraphSAGE-style layer (mean aggregation over in-edges + linear).
Trains on the synthetic transaction graph from ml/data/synthetic_nigeria.py.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import SAGEConv  # type: ignore
    HAS_PYG = True
except Exception:  # pragma: no cover - depends on env
    HAS_PYG = False


class SAGELayer(nn.Module):
    """Pure-PyTorch GraphSAGE layer: h' = W1 h_v + W2 mean_{u in N_in(v)} h_u."""

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.lin_self = nn.Linear(in_dim, out_dim)
        self.lin_neigh = nn.Linear(in_dim, out_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        src, dst = edge_index[0], edge_index[1]
        agg = torch.zeros_like(x)
        agg.index_add_(0, dst, x[src])
        deg = torch.zeros(x.size(0), device=x.device)
        deg.index_add_(0, dst, torch.ones_like(dst, dtype=torch.float))
        agg = agg / deg.clamp(min=1).unsqueeze(-1)
        return F.relu(self.lin_self(x) + self.lin_neigh(agg))


class MuleGNN(nn.Module):
    """2-layer GraphSAGE node classifier with a linear head."""

    def __init__(self, in_dim: int, hidden: int = 64, dropout: float = 0.3,
                 use_pyg: bool | None = None):
        super().__init__()
        self.use_pyg = HAS_PYG if use_pyg is None else (use_pyg and HAS_PYG)
        if self.use_pyg:
            self.conv1 = SAGEConv(in_dim, hidden)
            self.conv2 = SAGEConv(hidden, hidden)
        else:
            self.conv1 = SAGELayer(in_dim, hidden)
            self.conv2 = SAGELayer(hidden, hidden)
        self.dropout = dropout
        self.head = nn.Linear(hidden, 1)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        if self.use_pyg:
            h = F.relu(self.conv1(x, edge_index))
            h = F.dropout(h, self.dropout, self.training)
            h = F.relu(self.conv2(h, edge_index))
        else:
            h = self.conv1(x, edge_index)
            h = F.dropout(h, self.dropout, self.training)
            h = self.conv2(h, edge_index)
        return self.head(h).squeeze(-1)

    def prob(self, x, edge_index):
        return torch.sigmoid(self.forward(x, edge_index))


def backend_name() -> str:
    return "torch_geometric.SAGEConv" if HAS_PYG else "pure-torch SAGELayer"
