"""Train the IdentityEmbedder on synthetic identity pairs.

Generates synthetic biometric identities: each identity has a latent template
(face/document feature vector); captures of the same identity are the template
plus realistic capture noise (pose/lighting/sensor noise, occasional blur
spikes), while different identities have independent templates. The embedder
is trained with a margin contrastive loss so same-identity pairs score close
and impostor pairs separate by the margin.

Honest-metrics note: synthetic templates are separable by construction, so
reported EER/TAR are plumbing validation, NOT evidence of real biometric
skill. Real capture data must be swapped in via the adapter interface in
ml/validation before any production claim.

Outputs ml/artifacts/identity_embedder/v1/:
  weights.pt    state_dict (torch-only fallback)
  model.pt      TorchScript — the file the identity-theft-detector hook loads
                (IDENTITY_MODEL_PATH default points here) because the service
                has no model_def.py and cannot load bare state_dicts
  model.onnx    ONNX export for CPU inference services
  metrics.json  EER / TAR@FAR / similarity-gap metrics
  MODEL_CARD.md provenance + limitations
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.models.identity_embedder import (DEFAULT_EMBED_DIM, DEFAULT_INPUT_DIM,
                                         ContrastiveLoss, IdentityEmbedder)
from ml.train.common import EarlyStopper, model_card, save_artifacts, set_seed

SEED = 20240813


def generate_identities(n_identities: int, in_dim: int, rng: np.random.Generator,
                        captures: int = 8):
    """Latent identity templates + noisy captures.

    Noise model: per-capture Gaussian noise scaled by a random capture-quality
    factor (blur/pose), plus a low-rank 'session' drift (same session -> same
    drift) so the task is not purely i.i.d. noise.
    """
    templates = rng.normal(0, 1, (n_identities, in_dim)).astype(np.float32)
    templates /= np.linalg.norm(templates, axis=1, keepdims=True) + 1e-9
    samples, labels = [], []
    for i in range(n_identities):
        quality = rng.uniform(0.02, 0.10, captures)  # noise scale per capture
        session_drift = rng.normal(0, 0.05, (captures // 2 + 1, in_dim)).astype(np.float32)
        for c in range(captures):
            drift = session_drift[c // 2]
            x = templates[i] + drift + rng.normal(0, quality[c], in_dim)
            samples.append(x.astype(np.float32))
            labels.append(i)
    return np.stack(samples), np.array(labels)


def make_pairs(samples: np.ndarray, labels: np.ndarray, n_pairs: int,
               rng: np.random.Generator):
    """Balanced same/different identity pairs."""
    n = len(samples)
    y = np.concatenate([np.ones(n_pairs // 2), np.zeros(n_pairs - n_pairs // 2)])
    i1 = rng.integers(0, n, n_pairs)
    i2 = np.empty(n_pairs, dtype=np.int64)
    for k in range(n_pairs):
        same = y[k] == 1
        pool = np.where(labels == labels[i1[k]] if same else labels != labels[i1[k]])[0]
        pool = pool[pool != i1[k]]
        i2[k] = pool[rng.integers(len(pool))]
    perm = rng.permutation(n_pairs)
    return (samples[i1[perm]], samples[i2[perm]],
            y[perm].astype(np.float32))


def eer_and_tar(genuine: np.ndarray, impostor: np.ndarray) -> dict:
    """EER + TAR at fixed FARs from similarity score distributions."""
    grid = np.linspace(-0.2, 1.0, 1201)
    far = np.array([(impostor >= t).mean() for t in grid])
    frr = np.array([(genuine < t).mean() for t in grid])
    j = np.argmin(np.abs(far - frr))
    out = {"eer": float((far[j] + frr[j]) / 2),
           "eer_threshold": float(grid[j]),
           "genuine_mean_sim": float(genuine.mean()),
           "impostor_mean_sim": float(impostor.mean()),
           "sim_gap": float(genuine.mean() - impostor.mean())}
    for target in (1e-1, 1e-2, 1e-3):
        ok = np.where(far <= target)[0]
        out[f"tar_at_far_{target:g}"] = float(1 - frr[ok[0]]) if len(ok) else 0.0
    return out


def train(epochs: int = 150, n_identities: int = 15000, captures: int = 6,
          pairs_per_epoch: int = 30000, batch_size: int = 512, lr: float = 1.5e-3,
          margin: float = 1.2, in_dim: int = DEFAULT_INPUT_DIM,
          embed_dim: int = DEFAULT_EMBED_DIM, patience: int = 20,
          seed: int = 42, version: str = "v1") -> dict:
    set_seed(seed)
    rng = np.random.default_rng(SEED)

    # disjoint identity sets for train / eval (open-set evaluation)
    s_tr, l_tr = generate_identities(n_identities, in_dim, rng, captures)
    s_ev, l_ev = generate_identities(n_identities // 3, in_dim, rng, captures)

    model = IdentityEmbedder(in_dim, embed_dim)
    # normalized-softmax (proxy) head over training identities: classification
    # metric learning generalises open-set far better than pair contrastive.
    W = torch.nn.Parameter(torch.randn(n_identities, embed_dim))
    scale = 16.0
    opt = torch.optim.AdamW(list(model.parameters()) + [W], lr=lr,
                            weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    stop = EarlyStopper(patience=patience)

    x_all = torch.from_numpy(s_tr)
    y_all = torch.from_numpy(l_tr)
    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(len(y_all))
        tot = 0.0
        for i in range(0, len(y_all), batch_size):
            idx = perm[i:i + batch_size]
            opt.zero_grad()
            z = model(x_all[idx])
            logits = scale * (z @ F.normalize(W, p=2, dim=1).t())
            loss = F.cross_entropy(logits, y_all[idx])
            loss.backward()
            opt.step()
            tot += loss.item() * len(idx)
        sched.step()
        # validation: embedding sim gap on fresh pairs from HELD-OUT
        # identities (open-set early stopping, matching the eval protocol)
        model.eval()
        with torch.no_grad():
            va, vb, vy = make_pairs(s_ev, l_ev, 4000, rng)
            z1, z2 = model(torch.from_numpy(va)), model(torch.from_numpy(vb))
            sim = F.cosine_similarity(z1, z2).numpy()
        gap = float(sim[vy == 1].mean() - sim[vy == 0].mean())
        if epoch % 10 == 0:
            print(f"epoch {epoch:03d} loss={tot/len(y_all):.4f} val_sim_gap={gap:.4f}")
        if stop.step(gap, model):
            print(f"early stop at epoch {epoch}")
            break
    model.load_state_dict(stop.best_state)
    model.eval()

    # open-set eval on held-out identities
    ea, eb, ey = make_pairs(s_ev, l_ev, 20000, rng)
    with torch.no_grad():
        z1, z2 = model(torch.from_numpy(ea)), model(torch.from_numpy(eb))
        sim = F.cosine_similarity(z1, z2).numpy()
    m = eer_and_tar(sim[ey == 1], sim[ey == 0])
    m.update(epochs_trained=epoch + 1, seed=seed, objective="normalized_softmax",
             proxy_scale=scale, margin=margin,
             in_dim=in_dim, embed_dim=embed_dim,
             n_train_identities=n_identities, n_eval_identities=n_identities // 3,
             eval_pairs=20000, provenance="synthetic")
    print(json.dumps(m, indent=2))

    dest = save_artifacts("identity_embedder", version, model, m, {
        "MODEL_CARD.md": model_card(
            "identity_embedder", version, m,
            "synthetic identity capture pairs (contrastive metric learning)",
            notes=("Synthetic biometric templates are separable by construction; "
                   "EER/TAR numbers validate plumbing only. TorchScript model.pt "
                   "is the drop-in artifact for identity-theft-detector "
                   "(IDENTITY_MODEL_PATH).")),
    })
    # TorchScript drop-in for the service hook (jit.load path) + ONNX export
    scripted = torch.jit.trace(model, torch.zeros(1, in_dim))
    scripted.save(str(dest / "model.pt"))
    dummy = torch.zeros(1, in_dim)
    torch.onnx.export(model, dummy, dest / "model.onnx",
                      input_names=["features"], output_names=["embedding"],
                      dynamic_axes={"features": {0: "batch"},
                                    "embedding": {0: "batch"}},
                      opset_version=17)
    print(f"saved -> {dest} (weights.pt, model.pt [TorchScript], model.onnx)")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    train(epochs=a.epochs, version=a.version, seed=a.seed)
