"""Rolling performance tracker — the label feedback loop consumer.

Joins scored events (router log or lakehouse risk_score) with investigator
labels, then computes precision / recall / F1 over sliding daily windows and
emits degradation alerts when metrics fall below thresholds.

Usage:
    python mlops/monitoring/performance.py \
        --lakehouse-dir mlops/data/lakehouse \
        --window-days 7 --threshold-f1 0.6 \
        --textfile monitoring/out/performance.prom
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("performance")

SCORE_THRESHOLD = float(os.getenv("PERF_SCORE_THRESHOLD", "0.5"))
MIN_F1 = float(os.getenv("PERF_MIN_F1", "0.6"))
MIN_PRECISION = float(os.getenv("PERF_MIN_PRECISION", "0.5"))
MIN_RECALL = float(os.getenv("PERF_MIN_RECALL", "0.5"))


def resolve_dataset_dir(lakehouse_dir: Path) -> Path:
    nested = lakehouse_dir / "transactions"
    return nested if nested.is_dir() else lakehouse_dir


def load_labeled(lakehouse_dir: Path) -> Any:
    """Load all partitions that carry labels (ingest_labels.py output).

    Label column: 'is_fraud' (ml lane contract); 'label' accepted as alias.
    """
    import pyarrow.dataset as ds

    lakehouse_dir = resolve_dataset_dir(lakehouse_dir)
    files = [str(p) for p in sorted(lakehouse_dir.rglob("*.parquet"))]
    if not files:
        raise SystemExit(f"no partitions under {lakehouse_dir}")
    table = ds.dataset(files, format="parquet").to_table()
    df = table.to_pandas()
    if "label" not in df.columns and "is_fraud" in df.columns:
        df = df.rename(columns={"is_fraud": "label"})
    if "label" not in df.columns or "risk_score" not in df.columns:
        raise SystemExit("lakehouse rows must contain 'is_fraud' (or 'label') and 'risk_score' columns")
    labeled = df[df["label"].notna()].copy()
    return labeled


def window_metrics(rows, threshold: float) -> dict[str, Any]:
    tp = int(((rows["risk_score"] >= threshold) & (rows["label"] == 1)).sum())
    fp = int(((rows["risk_score"] >= threshold) & (rows["label"] == 0)).sum())
    fn = int(((rows["risk_score"] < threshold) & (rows["label"] == 1)).sum())
    tn = int(((rows["risk_score"] < threshold) & (rows["label"] == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall)
        else None
    )
    return {
        "support": tp + fp + fn + tn,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 6) if precision is not None else None,
        "recall": round(recall, 6) if recall is not None else None,
        "f1": round(f1, 6) if f1 is not None else None,
    }


def rolling_report(labeled, window_days: int, threshold: float) -> dict[str, Any]:
    if "dt" in labeled.columns:
        labeled = labeled.assign(day=labeled["dt"].astype(str))
    elif "ts" in labeled.columns:
        labeled = labeled.assign(day=labeled["ts"].astype(str).str[:10])
    else:
        raise SystemExit("rows need a 'dt' partition column or 'ts' timestamp")

    by_day: dict[str, Any] = defaultdict(list)
    for day, group in labeled.groupby("day"):
        by_day[day] = group

    days = sorted(by_day)
    windows: list[dict[str, Any]] = []
    for end_day in days:
        end = date.fromisoformat(end_day)
        start = end - timedelta(days=window_days - 1)
        frames = [by_day[d] for d in days if start <= date.fromisoformat(d) <= end]
        if not frames:
            continue
        import pandas as pd

        merged = pd.concat(frames)
        metrics = window_metrics(merged, threshold)
        windows.append({"window_start": start.isoformat(), "window_end": end_day, **metrics})

    latest = windows[-1] if windows else None
    alerts = []
    if latest and latest["f1"] is not None:
        if latest["f1"] < MIN_F1:
            alerts.append({"metric": "f1", "value": latest["f1"], "threshold": MIN_F1})
        if latest["precision"] is not None and latest["precision"] < MIN_PRECISION:
            alerts.append({"metric": "precision", "value": latest["precision"], "threshold": MIN_PRECISION})
        if latest["recall"] is not None and latest["recall"] < MIN_RECALL:
            alerts.append({"metric": "recall", "value": latest["recall"], "threshold": MIN_RECALL})
    return {
        "window_days": window_days,
        "score_threshold": threshold,
        "thresholds": {"min_f1": MIN_F1, "min_precision": MIN_PRECISION, "min_recall": MIN_RECALL},
        "windows": windows,
        "latest": latest,
        "alerts": alerts,
        "status": "degraded" if alerts else "ok",
    }


def render_prometheus(report: dict[str, Any]) -> str:
    lines = [
        "# HELP fraudfusion_model_f1 rolling-window F1 on labeled outcomes",
        "# TYPE fraudfusion_model_f1 gauge",
    ]
    latest = report.get("latest") or {}
    for metric in ("precision", "recall", "f1"):
        if latest.get(metric) is not None:
            lines.append(f"fraudfusion_model_{metric} {latest[metric]}")
    lines += [
        "# HELP fraudfusion_model_degraded 1 if any performance alert is active",
        "# TYPE fraudfusion_model_degraded gauge",
        f"fraudfusion_model_degraded {1 if report['status'] == 'degraded' else 0}",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lakehouse-dir", type=Path, default=Path(os.getenv("LAKEHOUSE_DIR", "mlops/data/lakehouse")))
    parser.add_argument("--window-days", type=int, default=7)
    parser.add_argument("--score-threshold", type=float, default=SCORE_THRESHOLD)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--textfile", type=Path, default=None)
    args = parser.parse_args()

    labeled = load_labeled(args.lakehouse_dir)
    report = rolling_report(labeled, args.window_days, args.score_threshold)
    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    if args.textfile:
        args.textfile.parent.mkdir(parents=True, exist_ok=True)
        args.textfile.write_text(render_prometheus(report), encoding="utf-8")
    raise SystemExit(0 if report["status"] == "ok" else 2)


if __name__ == "__main__":
    main()
