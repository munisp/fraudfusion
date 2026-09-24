"""Drift detection over lakehouse parquet batches.

Compares a reference window (training/baseline partitions) against a current
window of scored transactions:

- PSI (Population Stability Index) per numeric feature and for the
  prediction score itself.
- KS statistic (two-sample Kolmogorov-Smirnov) per feature.

Outputs:
- JSON report (default stdout, or --output)
- Prometheus-style textfile (--textfile, for node_exporter textfile collector)

Alert thresholds (env-overridable):
    DRIFT_PSI_WARN (0.1)  DRIFT_PSI_ALERT (0.25)  DRIFT_KS_ALERT (0.1)

Usage:
    python mlops/monitoring/drift.py \
        --lakehouse-dir mlops/data/lakehouse \
        --reference 2026-01-01:2026-01-07 --current 2026-01-08:2026-01-09
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("drift")

PSI_WARN = float(os.getenv("DRIFT_PSI_WARN", "0.1"))
PSI_ALERT = float(os.getenv("DRIFT_PSI_ALERT", "0.25"))
KS_ALERT = float(os.getenv("DRIFT_KS_ALERT", "0.1"))
SCORE_COLUMN = os.getenv("DRIFT_SCORE_COLUMN", "risk_score")
EPS = 1e-6


def parse_window(spec: str) -> list[str]:
    """'YYYY-MM-DD:YYYY-MM-DD' inclusive -> list of dt partition strings."""
    start_s, end_s = spec.split(":")
    start, end = date.fromisoformat(start_s), date.fromisoformat(end_s)
    days = []
    while start <= end:
        days.append(start.isoformat())
        start += timedelta(days=1)
    return days


def resolve_dataset_dir(lakehouse_dir: Path) -> Path:
    """Accept either the lakehouse root or the transactions dataset dir."""
    nested = lakehouse_dir / "transactions"
    return nested if nested.is_dir() else lakehouse_dir


def load_window(lakehouse_dir: Path, partitions: list[str]) -> Any:
    import pyarrow.dataset as ds

    lakehouse_dir = resolve_dataset_dir(lakehouse_dir)
    files = []
    for part in partitions:
        candidate = lakehouse_dir / f"dt={part}"
        if candidate.exists():
            files.extend(str(p) for p in sorted(candidate.glob("*.parquet")))
        else:
            logger.info("partition %s missing, skipping", candidate)
    if not files:
        raise SystemExit(f"no partitions found under {lakehouse_dir} for {partitions}")
    dataset = ds.dataset(files, format="parquet")
    return dataset.to_table().to_pandas()


def numeric_columns(df) -> list[str]:
    cols = [c for c in df.columns if str(df[c].dtype).startswith(("float", "int"))]
    return [c for c in cols if c not in {"label", "is_fraud"}]


def psi(reference: np.ndarray, current: np.ndarray, bins: int = 10) -> float:
    quantiles = np.quantile(reference, np.linspace(0, 1, bins + 1))
    quantiles[0], quantiles[-1] = -np.inf, np.inf
    edges = np.unique(quantiles)
    if len(edges) < 2:
        return 0.0
    ref_counts, _ = np.histogram(reference, bins=edges)
    cur_counts, _ = np.histogram(current, bins=edges)
    ref_pct = np.maximum(ref_counts / max(ref_counts.sum(), 1), EPS)
    cur_pct = np.maximum(cur_counts / max(cur_counts.sum(), 1), EPS)
    return float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))


def ks_statistic(reference: np.ndarray, current: np.ndarray) -> float:
    """Two-sample KS statistic (exact via sorted arrays; scipy if present)."""
    try:
        from scipy.stats import ks_2samp

        return float(ks_2samp(reference, current).statistic)
    except ImportError:
        all_values = np.sort(np.concatenate([reference, current]))
        ref_cdf = np.searchsorted(np.sort(reference), all_values, side="right") / len(reference)
        cur_cdf = np.searchsorted(np.sort(current), all_values, side="right") / len(current)
        return float(np.max(np.abs(ref_cdf - cur_cdf)))


def drift_report(reference_df, current_df, features: list[str]) -> dict[str, Any]:
    report: dict[str, Any] = {
        "reference_rows": int(len(reference_df)),
        "current_rows": int(len(current_df)),
        "thresholds": {"psi_warn": PSI_WARN, "psi_alert": PSI_ALERT, "ks_alert": KS_ALERT},
        "features": {},
        "alerts": [],
    }
    columns = features or numeric_columns(reference_df)
    for col in columns:
        if col not in reference_df.columns or col not in current_df.columns:
            continue
        ref = reference_df[col].dropna().to_numpy(dtype=float)
        cur = current_df[col].dropna().to_numpy(dtype=float)
        if len(ref) < 10 or len(cur) < 10:
            report["features"][col] = {"status": "insufficient_data"}
            continue
        psi_value = psi(ref, cur)
        ks_value = ks_statistic(ref, cur)
        status = "ok"
        if psi_value >= PSI_ALERT or ks_value >= KS_ALERT:
            status = "alert"
        elif psi_value >= PSI_WARN:
            status = "warn"
        report["features"][col] = {
            "psi": round(psi_value, 6),
            "ks": round(ks_value, 6),
            "status": status,
            "reference_mean": round(float(ref.mean()), 6),
            "current_mean": round(float(cur.mean()), 6),
        }
        if status in {"warn", "alert"}:
            report["alerts"].append({
                "feature": col,
                "kind": "score_drift" if col == SCORE_COLUMN else "feature_drift",
                "psi": round(psi_value, 6),
                "ks": round(ks_value, 6),
                "status": status,
            })
    report["status"] = "alert" if any(a["status"] == "alert" for a in report["alerts"]) else (
        "warn" if report["alerts"] else "ok"
    )
    return report


def render_prometheus(report: dict[str, Any]) -> str:
    lines = [
        "# HELP fraudfusion_drift_psi PSI per feature vs reference window",
        "# TYPE fraudfusion_drift_psi gauge",
    ]
    for feature, stats in report["features"].items():
        if "psi" in stats:
            lines.append(f'fraudfusion_drift_psi{{feature="{feature}"}} {stats["psi"]}')
            lines.append(f'fraudfusion_drift_ks{{feature="{feature}"}} {stats["ks"]}')
    status_value = {"ok": 0, "warn": 1, "alert": 2}[report["status"]]
    lines += [
        "# HELP fraudfusion_drift_status 0=ok 1=warn 2=alert",
        "# TYPE fraudfusion_drift_status gauge",
        f"fraudfusion_drift_status {status_value}",
        "# HELP fraudfusion_drift_alerts_total active drift alerts",
        "# TYPE fraudfusion_drift_alerts_total gauge",
        f"fraudfusion_drift_alerts_total {len(report['alerts'])}",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lakehouse-dir", type=Path, default=Path(os.getenv("LAKEHOUSE_DIR", "mlops/data/lakehouse")))
    parser.add_argument("--reference", required=True, help="YYYY-MM-DD:YYYY-MM-DD inclusive")
    parser.add_argument("--current", required=True, help="YYYY-MM-DD:YYYY-MM-DD inclusive")
    parser.add_argument("--features", nargs="*", default=None, help="Columns to check (default: all numeric)")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--textfile", type=Path, default=None, help="Prometheus textfile collector path")
    args = parser.parse_args()

    reference_df = load_window(args.lakehouse_dir, parse_window(args.reference))
    current_df = load_window(args.lakehouse_dir, parse_window(args.current))
    report = drift_report(reference_df, current_df, args.features or [])

    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    if args.textfile:
        args.textfile.parent.mkdir(parents=True, exist_ok=True)
        args.textfile.write_text(render_prometheus(report), encoding="utf-8")
        logger.info("wrote prometheus textfile to %s", args.textfile)
    raise SystemExit(0 if report["status"] != "alert" else 2)


if __name__ == "__main__":
    main()
