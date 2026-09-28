"""Train the Cultural Intelligence layer (MCMC posteriors over Nigeria's
culturally-patterned financial rhythms: ajo/esusu legitimacy, cultural
calendar uplift, market-week cycles, religious giving rhythm, and
culturally-specific fraud-typology base rates).

Thin wrapper around ``ml.bayesian.cultural_intelligence.fit_all`` following
the Bayesian-lane artifact contract: ships
``ml/artifacts/cultural_intelligence/<version>/`` with per-submodel
posterior npz files + serving.npz + summaries.json + metrics.json +
MODEL_CARD.md.

    python -m ml.train.train_cultural_intel [--version v1] [--seed 42] [--quick]

Refresh cadence: intended to run weekly/monthly from continuous training
once real feeds land in the cultural_* tables; until then it refits the
documented synthetic generator (seeded).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.bayesian.cultural_intelligence import fit_all  # noqa: E402


def main() -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--quick", action="store_true",
                    help="thin chains for CI smoke runs (diagnostics still "
                         "reported, but NOT the shipped configuration)")
    a = ap.parse_args()
    return fit_all(version=a.version, seed=a.seed, quick=a.quick)


if __name__ == "__main__":
    main()
