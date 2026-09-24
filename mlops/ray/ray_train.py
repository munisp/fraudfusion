"""Distributed fraud_net training with Ray Train/Tune.

Converts the single-process fraud training loop (ml/train) into a Ray Train
TorchTrainer job reading the parquet lakehouse. The model architecture here
mirrors the ml/ lane contract: a small MLP over the canonical feature vector
(FEATURE_NAMES in mlops/serving/aml_service.py) producing a fraud logit.
Keep the architecture in sync with ml/train so exported weights remain
load-compatible with the serving stack.

Usage:
    python mlops/ray/ray_train.py --num-workers 2 --epochs 5 \
        --lakehouse-dir mlops/data/lakehouse

    # Tune hyperparameters instead:
    python mlops/ray/ray_train.py --tune --num-samples 8
"""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ray-train")

LAKEHOUSE_DIR = Path(os.getenv("LAKEHOUSE_DIR", "mlops/data/lakehouse"))
# ml lane numeric feature contract (mirrors ml/data/synthetic_nigeria.py).
FEATURE_COLUMNS = [
    "log_amount", "hour", "dow", "is_month_end", "is_market_day",
    "amount_vs_sender_avg", "sender_txns_24h", "sender_unique_receivers_72h",
    "receiver_fanin_72h", "mins_since_last_txn", "device_emulator",
    "sim_swap_7d", "new_device", "cross_state", "cross_bank", "is_night",
]
INPUT_DIM = len(FEATURE_COLUMNS)


class FraudNet(nn.Module):
    """Keep architecture in sync with ml/train/fraud_net."""

    def __init__(self, input_dim: int = INPUT_DIM, hidden: int = 64) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(hidden, hidden), nn.ReLU(),
            nn.Linear(hidden, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)


def load_lakehouse(lakehouse_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    import pyarrow.dataset as ds

    nested = lakehouse_dir / "transactions"
    root = nested if nested.is_dir() else lakehouse_dir
    files = [str(p) for p in sorted(root.rglob("*.parquet"))]
    if not files:
        raise SystemExit(f"no lakehouse partitions under {root}; run mlops/lakehouse/export.py --synthetic")
    df = ds.dataset(files, format="parquet").to_table().to_pandas()
    label_col = "is_fraud" if "is_fraud" in df.columns else "label"
    df = df[df[label_col].notna()]
    if df.empty:
        raise SystemExit("no labeled rows in lakehouse; run mlops/lakehouse/ingest_labels.py")
    x = df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y = df[label_col].to_numpy(dtype=np.float32)
    return x, y


def train_loop_per_worker(config: dict) -> None:
    import ray.train as ray_train
    from ray.train.torch import TorchTrainer  # noqa: F401  (import validates env)

    x, y = load_lakehouse(Path(config["lakehouse_dir"]))
    dataset = torch.utils.data.TensorDataset(torch.from_numpy(x), torch.from_numpy(y))
    sampler = torch.utils.data.distributed.DistributedSampler(
        dataset, num_replicas=ray_train.get_context().get_world_size(),
        rank=ray_train.get_context().get_world_rank(), shuffle=True,
    ) if ray_train.get_context().get_world_size() > 1 else None
    loader = torch.utils.data.DataLoader(
        dataset, batch_size=config["batch_size"], shuffle=sampler is None, sampler=sampler,
    )

    model = FraudNet(hidden=config["hidden"])
    model = ray_train.torch.prepare_model(model)
    optimizer = torch.optim.Adam(model.parameters(), lr=config["lr"])
    criterion = nn.BCEWithLogitsLoss()

    for epoch in range(config["epochs"]):
        model.train()
        total_loss, batches = 0.0, 0
        for features, labels in loader:
            optimizer.zero_grad()
            loss = criterion(model(features), labels)
            loss.backward()
            optimizer.step()
            total_loss += float(loss)
            batches += 1
        ray_train.report(
            {"loss": total_loss / max(batches, 1), "epoch": epoch},
        )

    # Checkpoint from rank 0 (or single worker).
    world_rank = ray_train.get_context().get_world_rank()
    if world_rank == 0:
        with tempfile.TemporaryDirectory() as tmpdir:
            torch.save(model.state_dict(), Path(tmpdir) / "fraud_net.pt")
            from ray.train import Checkpoint

            ray_train.report({"done": 1.0}, checkpoint=Checkpoint.from_directory(tmpdir))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-workers", type=int, default=int(os.getenv("RAY_NUM_WORKERS", "1")))
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--hidden", type=int, default=64)
    parser.add_argument("--lakehouse-dir", type=Path, default=LAKEHOUSE_DIR)
    parser.add_argument("--tune", action="store_true", help="run a Tune hyperparameter sweep")
    parser.add_argument("--num-samples", type=int, default=8)
    args = parser.parse_args()

    import ray
    from ray.train import RunConfig, ScalingConfig
    from ray.train.torch import TorchTrainer

    ray.init(ignore_reinit_error=True, include_dashboard=False)

    train_config = {
        # absolute path: Ray workers may run with a different cwd
        "lakehouse_dir": str(args.lakehouse_dir.resolve()),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "lr": args.lr,
        "hidden": args.hidden,
    }
    trainer = TorchTrainer(
        train_loop_per_worker,
        train_loop_config=train_config,
        scaling_config=ScalingConfig(num_workers=args.num_workers, use_gpu=False),
        run_config=RunConfig(name="fraud_net_ray_train"),
    )

    if args.tune:
        from ray import tune

        tuner = tune.Tuner(
            trainer,
            param_space={
                "train_loop_config": {
                    **train_config,
                    "lr": tune.loguniform(1e-4, 1e-2),
                    "hidden": tune.choice([32, 64, 128]),
                }
            },
            tune_config=tune.TuneConfig(num_samples=args.num_samples, metric="loss", mode="min"),
        )
        results = tuner.fit()
        best = results.get_best_result()
        logger.info("best config: %s loss=%.4f", best.config, best.metrics.get("loss", float("nan")))
    else:
        result = trainer.fit()
        logger.info("training finished: metrics=%s checkpoint=%s", result.metrics, result.checkpoint)
    ray.shutdown()


if __name__ == "__main__":
    main()
