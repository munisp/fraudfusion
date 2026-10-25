"""Backtest harness: replay labeled cases through the detectors and report
honest detection metrics.

Input: JSONL, one case per line:
  {"detector": "mule", "label": "fraud"|"legit",
   "payload": {...}, "history": [{"payload": {...}, "created_at": "..."}]}

For every detector the harness reports, at BOTH bands:
  * block band  (score >= BLOCK_MIN): precision/recall/FPR — "would we have
    stopped it, and how often would we have been wrong"
  * review band (score >= REVIEW_MIN): same, for the analyst queue

Labels come from the file, never inferred. Cases whose detector is unknown
are counted and skipped. No metric is hidden: small samples print the raw
counts so a 1/1 "100% recall" is visibly meaningless.

CLI:  python3 backtest.py cases.jsonl
Lib:  from backtest import backtest; report = backtest(cases)
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any, Iterable

import detectors as det


def _band_counts(cases: list[dict], threshold: float) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for c in cases:
        predicted = c["score"] >= threshold
        if c["label"] == "fraud":
            tp, fn = (tp + 1, fn) if predicted else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if predicted else (fp, tn + 1)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _metrics(counts: dict[str, int]) -> dict[str, Any]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    return {
        **counts,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "fpr": round(fp / (fp + tn), 4) if fp + tn else None,
        "accuracy": round((tp + tn) / (tp + fp + tn + fn), 4)
        if tp + fp + tn + fn else None,
    }


def backtest(cases: Iterable[dict]) -> dict[str, Any]:
    """Evaluate labeled cases; returns per-detector and overall metrics."""
    by_detector: dict[str, list[dict]] = defaultdict(list)
    skipped = 0
    for i, case in enumerate(cases):
        name = case.get("detector", "").replace("-", "_")
        label = case.get("label")
        if name not in det.DETECTORS or label not in ("fraud", "legit"):
            skipped += 1
            continue
        score, verdict, factors = det.DETECTORS[name](
            case.get("payload") or {}, case.get("history") or [])
        by_detector[name].append({
            "case_index": i, "label": label, "score": score,
            "verdict": verdict,
            "factor_codes": [f["code"] for f in factors],
        })

    report: dict[str, Any] = {"detectors": {}, "skipped_cases": skipped}
    all_scored: list[dict] = []
    for name, scored in sorted(by_detector.items()):
        all_scored.extend(scored)
        report["detectors"][name] = {
            "cases": len(scored),
            "fraud": sum(1 for c in scored if c["label"] == "fraud"),
            "legit": sum(1 for c in scored if c["label"] == "legit"),
            "block_band": _metrics(_band_counts(scored, det.BLOCK_MIN)),
            "review_band": _metrics(_band_counts(scored, det.REVIEW_MIN)),
            "results": scored,
        }
    report["overall"] = {
        "cases": len(all_scored),
        "block_band": _metrics(_band_counts(all_scored, det.BLOCK_MIN)),
        "review_band": _metrics(_band_counts(all_scored, det.REVIEW_MIN)),
    }
    return report


def _fmt(m: dict[str, Any]) -> str:
    def pct(v):
        return "  n/a" if v is None else f"{v:6.1%}"
    return (f"tp={m['tp']:>3} fp={m['fp']:>3} tn={m['tn']:>3} fn={m['fn']:>3}"
            f"  precision={pct(m['precision'])} recall={pct(m['recall'])}"
            f" fpr={pct(m['fpr'])}")


def render_text(report: dict[str, Any]) -> str:
    lines = ["fraud-signals backtest report",
             "(labels from the input file; small samples are shown raw)", ""]
    for name, d in report["detectors"].items():
        lines.append(f"{name}: {d['cases']} cases "
                     f"({d['fraud']} fraud / {d['legit']} legit)")
        lines.append(f"  block  band: {_fmt(d['block_band'])}")
        lines.append(f"  review band: {_fmt(d['review_band'])}")
    o = report["overall"]
    lines.append("")
    lines.append(f"OVERALL: {o['cases']} cases")
    lines.append(f"  block  band: {_fmt(o['block_band'])}")
    lines.append(f"  review band: {_fmt(o['review_band'])}")
    if report["skipped_cases"]:
        lines.append(f"skipped (unknown detector/label): "
                     f"{report['skipped_cases']}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python3 backtest.py cases.jsonl", file=sys.stderr)
        return 2
    with open(argv[1]) as fh:
        cases = [json.loads(line) for line in fh if line.strip()]
    report = backtest(cases)
    print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
