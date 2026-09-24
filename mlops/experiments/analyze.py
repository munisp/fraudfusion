"""Analyze A/B experiment logs written by mlops/serving/model_router.py.

Reads the parquet (or jsonl fallback) router log, joins score events with
outcome (label) events on request_id, computes per-arm metrics, and runs a
two-proportion z-test on the fraud capture rate (recall on labeled fraud)
and on flag rates between champion and challenger.

Usage:
    python mlops/experiments/analyze.py --log-dir mlops/data/router_log
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def load_events(log_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    parquet_files = sorted(log_dir.rglob("*.parquet"))
    if parquet_files:
        import pyarrow.parquet as pq

        for path in parquet_files:
            events.extend(pq.read_table(path).to_pylist())
    jsonl = log_dir / "events.jsonl"
    if jsonl.exists():
        with open(jsonl, "r", encoding="utf-8") as fh:
            events.extend(json.loads(line) for line in fh if line.strip())
    return events


def two_proportion_ztest(x1: int, n1: int, x2: int, n2: int) -> dict[str, float]:
    """Two-proportion z-test: H0 p1 == p2. Returns z and two-sided p-value."""
    if n1 == 0 or n2 == 0:
        return {"z": float("nan"), "p_value": float("nan")}
    p1, p2 = x1 / n1, x2 / n2
    pooled = (x1 + x2) / (n1 + n2)
    se = math.sqrt(pooled * (1 - pooled) * (1 / n1 + 1 / n2))
    if se == 0:
        return {"z": 0.0, "p_value": 1.0}
    z = (p1 - p2) / se
    # two-sided p from normal CDF (erf, no scipy dependency required)
    p_value = math.erfc(abs(z) / math.sqrt(2))
    return {"z": z, "p_value": p_value}


def confusion(scored: list[dict[str, Any]]) -> dict[str, int]:
    tp = sum(1 for e in scored if e["risk_score"] is not None and e["risk_score"] >= 0.5 and e["label"] == 1)
    fp = sum(1 for e in scored if e["risk_score"] is not None and e["risk_score"] >= 0.5 and e["label"] == 0)
    fn = sum(1 for e in scored if e["risk_score"] is not None and e["risk_score"] < 0.5 and e["label"] == 1)
    tn = sum(1 for e in scored if e["risk_score"] is not None and e["risk_score"] < 0.5 and e["label"] == 0)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def safe_div(num: float, den: float) -> float | None:
    return round(num / den, 6) if den else None


def arm_report(arm: str, scored: list[dict[str, Any]]) -> dict[str, Any]:
    labeled = [e for e in scored if e["label"] is not None]
    cm = confusion(labeled)
    flagged = [e for e in scored if e["risk_score"] is not None and e["risk_score"] >= 0.5]
    return {
        "arm": arm,
        "total_scored": len(scored),
        "labeled": len(labeled),
        "flag_rate": safe_div(len(flagged), len(scored)),
        "precision": safe_div(cm["tp"], cm["tp"] + cm["fp"]),
        "recall": safe_div(cm["tp"], cm["tp"] + cm["fn"]),
        "f1": (
            safe_div(2 * cm["tp"], 2 * cm["tp"] + cm["fp"] + cm["fn"])
        ),
        "confusion": cm,
    }


def analyze(log_dir: Path) -> dict[str, Any]:
    events = load_events(log_dir)
    labels = {e["request_id"]: e for e in events if e.get("event_type") == "outcome"}
    scored: list[dict[str, Any]] = []
    for event in events:
        if event.get("event_type") != "score" or event.get("error"):
            continue
        merged = dict(event)
        outcome = labels.get(event["request_id"])
        if outcome:
            merged["label"] = outcome["label"]
        scored.append(merged)

    arms: dict[str, list[dict[str, Any]]] = {}
    for event in scored:
        arms.setdefault(event["arm"] or "unknown", []).append(event)

    reports = [arm_report(arm, evs) for arm, evs in sorted(arms.items())]
    report: dict[str, Any] = {"log_dir": str(log_dir), "arms": reports, "significance": None}

    if len(reports) == 2:
        a, b = reports
        # Compare flag rates (all scored) and recall (labeled fraud capture).
        flagged_a = round((a["flag_rate"] or 0) * a["total_scored"])
        flagged_b = round((b["flag_rate"] or 0) * b["total_scored"])
        recall_hits_a = a["confusion"]["tp"]
        recall_hits_b = b["confusion"]["tp"]
        frauds_a = a["confusion"]["tp"] + a["confusion"]["fn"]
        frauds_b = b["confusion"]["tp"] + b["confusion"]["fn"]
        report["significance"] = {
            "flag_rate_ztest": {
                "arms": [a["arm"], b["arm"]],
                **two_proportion_ztest(flagged_a, a["total_scored"], flagged_b, b["total_scored"]),
            },
            "recall_ztest": {
                "arms": [a["arm"], b["arm"]],
                **two_proportion_ztest(recall_hits_a, frauds_a, recall_hits_b, frauds_b),
            },
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, default=Path("mlops/data/router_log"))
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON report path")
    args = parser.parse_args()
    report = analyze(args.log_dir)
    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
