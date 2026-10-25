"""OCR-confidence forensics (Round 16).

When PaddleOCR (or any OCR adapter returning per-line confidences) reads a
document, the CONFIDENCE MAP is itself a tamper signal: a genuine print run
is produced in one pass, so character-level recognition confidence is
uniform. A name or date patched into a scan — re-typeset, re-rendered,
re-compressed — sits in a region whose recognition confidence breaks from
the document's baseline.

Pure functions over OCR line dicts ({text, confidence, box?}); never raise;
no OCR backend required (the lines are the input).
"""

from __future__ import annotations

import statistics
from typing import Any

# A line this far below the document median, in an otherwise confident
# document, is a patched-text suspect.
OUTLIER_DROP = 0.25
MIN_CONFIDENT_MEDIAN = 0.75


def confidence_inconsistency(ocr_lines: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect low-confidence outlier lines in an otherwise confident read.

    Returns the outlier lines (with text) so a reviewer sees exactly WHICH
    line is suspect — a patched surname is the classic case."""
    confs = []
    for line in ocr_lines:
        try:
            c = float(line.get("confidence"))
        except (TypeError, ValueError):
            continue
        text = str(line.get("text", "")).strip()
        if text:
            confs.append((text, c))
    if len(confs) < 4:
        return {"lines_scored": len(confs), "outliers": [],
                "suspected": False,
                "detail": "too few scored lines for a confidence baseline"}
    median = statistics.median(c for _, c in confs)
    if median < MIN_CONFIDENT_MEDIAN:
        return {"lines_scored": len(confs), "median_confidence": median,
                "outliers": [], "suspected": False,
                "detail": "document-wide confidence is low (capture quality), "
                          "no regional anomaly isolated"}
    outliers = [{"text": t, "confidence": c,
                 "drop_vs_median": round(median - c, 3)}
                for t, c in confs if c < median - OUTLIER_DROP]
    return {"lines_scored": len(confs), "median_confidence": median,
            "outliers": outliers, "suspected": bool(outliers),
            "detail": f"{len(outliers)} line(s) read far below the document "
                      f"median {median:.2f} — patched-text suspect"}
