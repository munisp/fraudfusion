"""Generate an honest markdown validation report from a backtest run.

  python -m ml.validation.validation_report --dataset synthetic \
      --file ml/data/generated --model-version v3 --out report.md
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.validation.adapters import ADAPTERS
from ml.validation.backtest import backtest


def render(res: dict, dataset: str, source_file: str) -> str:
    o = res["overall_eval"]
    t = res["threshold_tuning"]
    lines = [
        f"# Fraud model validation report — {dataset}",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Source: `{source_file}` (adapter: `{dataset}`)",
        f"- Model: fraud_net **{res['model_version']}**",
        f"- Rows: {res['n_rows']:,} | fraud rate: {res['fraud_rate']:.4f}",
        f"- Replay window: {res['window']} | calibration windows: "
        f"{len(res['calibration_windows'])} | eval windows: {len(res['eval_windows'])}",
        "",
        "## Threshold (cost-tuned on calibration windows only)",
        "",
        f"- threshold = **{res['threshold']:.4f}** (cost_fp ₦{t['cost_fp']:,.0f}, "
        f"cost_fn ₦{t['cost_fn']:,.0f} median fraud amount)",
        f"- expected cost on calibration: ₦{t['expected_cost']:,.0f}",
        "",
        "## Overall (held-out eval windows, frozen threshold)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for k in ("precision", "recall", "f1", "alert_rate", "auc_pr", "auc_roc",
              "n", "fraud", "alerts"):
        v = o[k]
        lines.append(f"| {k} | {v:,.4f} |" if isinstance(v, float)
                     else f"| {k} | {v:,} |")
    lines += ["", "## Per-window replay", "",
              "| Window | n | fraud | alerts | precision | recall | f1 |",
              "|---|---|---|---|---|---|---|"]
    for w in res["per_window"]:
        lines.append(
            f"| {w['window']} | {w['n']:,} | {w['fraud']:,} | {w['alerts']:,} "
            f"| {w['precision']:.4f} | {w['recall']:.4f} | {w['f1']:.4f} |")
    lines += [
        "",
        "## Honesty notes",
        "",
        "- Temporal replay only; the alert threshold was tuned on the earliest",
        "  windows and frozen before evaluation (no peeking).",
        "- Metrics on external datasets (PaySim/IEEE-CIS) are SCHEMA-COMPATIBILITY",
        "  checks: feature mappings are partial, so scores understate in-distribution",
        "  performance and must not be quoted as production expectations.",
        "- Synthetic results measure generator self-consistency, not real-world skill.",
        "",
    ]
    return "\n".join(lines)


def main() -> str:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="synthetic", choices=sorted(ADAPTERS))
    ap.add_argument("--file", default="ml/data/generated")
    ap.add_argument("--model-version", default="v1")
    ap.add_argument("--window", default="7D")
    ap.add_argument("--cost-fp", type=float, default=500.0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        df = ADAPTERS[a.dataset].load(a.file)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)
    res = backtest(df, version=a.model_version, window=a.window,
                   cost_fp=a.cost_fp)
    md = render(res, a.dataset, a.file)
    Path(a.out).write_text(md)
    print(f"report -> {a.out}")
    return md


if __name__ == "__main__":
    main()
