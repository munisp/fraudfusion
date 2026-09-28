"""Local OpenCV document-forensics layer (no ML dependencies).

Every function here is genuinely implemented against cv2/numpy and unit-tested
on synthetic fixtures generated at test time. All thresholds are module-level
constants, documented and tunable — they are calibrated against the synthetic
fixtures in tests/test_local_cv.py and should be re-calibrated against real
captures before production thresholds are trusted.

Signals:
  * blur_score               — Laplacian variance (focus / motion blur)
  * glare_score              — saturated-region fraction (laminate glare)
  * screen_replay_integrity  — FFT periodic-peak (moire) analysis: a photo OF
                               a screen shows sharp periodic spectral peaks;
                               a flat digital screenshot or a real capture of
                               paper does not. Returns 1.0 = no replay sign.
  * edge_border_integrity    — dominant quadrilateral border detection: a real
                               captured card/document has a dominant 4-sided
                               contour; a flat render with no physical border
                               scores low.
  * resolution_sanity        — dimension / megapixel floor.
  * color_diversity          — quantized unique-colour count: flat digital
                               renders have a handful of colours; real camera
                               captures have hundreds.
"""

from __future__ import annotations

from typing import Any

import cv2
import numpy as np

# --- tunable thresholds ------------------------------------------------------

# Laplacian variance: below POOR the image is too blurred to read; at or above
# GOOD the capture is considered sharp.
BLUR_POOR_THRESHOLD = 40.0
BLUR_GOOD_THRESHOLD = 150.0

# Glare: pixels with V >= GLARE_VALUE_MIN and S <= GLARE_SAT_MAX are saturated
# glare; above GLARE_POOR_FRACTION of all pixels the image is unusable.
# GLARE_WHITEOUT_FRACTION: when nearly the whole frame is saturated the image
# is a blank/white background (e.g. a flat digital render), not glare — the
# signal is not measurable and the score is 0.
GLARE_VALUE_MIN = 245
GLARE_SAT_MAX = 40
GLARE_WARN_FRACTION = 0.05
GLARE_POOR_FRACTION = 0.20
GLARE_WHITEOUT_FRACTION = 0.90

# Resolution floor for a readable ID capture.
MIN_DIMENSION_PX = 200
MIN_MEGAPIXELS = 0.08

# Screen-replay (moire) FFT analysis. The power spectrum is computed on a
# FFT_SIZE x FFT_SIZE rescale. Axis-aligned spectral lines (document/card
# edges) and the central low-frequency disk are suppressed, then moire
# peakiness = mean of the 10 strongest peak-to-local-mean ratios in the
# remaining spectrum. A photographed screen's pixel grid produces isolated
# off-axis spectral peaks 50x+ above their neighbourhood; paper texture,
# flat renders and blurred captures sit around 10-15x. Calibrated against
# tests/fixtures (see tests/test_local_cv.py).
FFT_SIZE = 512
LOW_FREQ_EXCLUDE_FRAC = 0.02
AXIS_LINE_HALF_WIDTH = 3
LOCAL_MEAN_KERNEL = 15
MOIRE_TOP_PEAKS = 10
MOIRE_PEAKINESS_SUSPECT = 20.0   # peakiness above this starts costing score
MOIRE_PEAKINESS_REPLAY = 50.0    # peakiness at/above this => integrity ~0

# Border detection: a plausible document border is a 4-vertex contour whose
# area covers at least BORDER_MIN_AREA_FRACTION of the frame.
BORDER_MIN_AREA_FRACTION = 0.20
BORDER_FULL_AREA_FRACTION = 0.60  # area fraction that maps to score 1.0

# Colour diversity: colours quantized to COLOR_QUANT levels/channel; a flat
# digital render yields ~2 buckets, a real camera capture (with sensor noise
# and print texture) yields 30-100+. Score saturates at COLOR_DIVERSITY_FULL.
COLOR_QUANT = 24
COLOR_DIVERSITY_FULL = 50


def decode_image(image_bytes: bytes) -> np.ndarray | None:
    """Decode image bytes to a BGR ndarray; None when undecodable."""
    if not image_bytes:
        return None
    buf = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    return img


def blur_score(img: np.ndarray) -> float:
    """Variance of the Laplacian — higher is sharper."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return float(cv2.Laplacian(gray, cv2.CV_64F).var())


def glare_score(img: np.ndarray) -> float:
    """Fraction of pixels that are saturated (near-white, low saturation)."""
    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    sat = hsv[:, :, 1]
    val = hsv[:, :, 2]
    mask = (val >= GLARE_VALUE_MIN) & (sat <= GLARE_SAT_MAX)
    frac = float(np.count_nonzero(mask)) / float(mask.size)
    if frac >= GLARE_WHITEOUT_FRACTION:
        # Nearly all-white frame: blank background, glare not measurable.
        return 0.0
    return frac


def _moire_peakiness(img: np.ndarray) -> float:
    """Mean of the top-MOIRE_TOP_PEAKS peak-to-local-mean power ratios."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY).astype(np.float64)
    gray = cv2.resize(gray, (FFT_SIZE, FFT_SIZE), interpolation=cv2.INTER_LINEAR)
    gray -= gray.mean()
    window = np.outer(np.hanning(FFT_SIZE), np.hanning(FFT_SIZE))
    spectrum = np.fft.fftshift(np.fft.fft2(gray * window))
    power = np.abs(spectrum) ** 2
    c = FFT_SIZE // 2
    # Suppress axis-aligned spectral lines from document edges.
    w = AXIS_LINE_HALF_WIDTH
    power[max(0, c - w):c + w + 1, :] = 0.0
    power[:, max(0, c - w):c + w + 1] = 0.0
    # Suppress the DC / page-layout disk.
    r = int(FFT_SIZE * LOW_FREQ_EXCLUDE_FRAC)
    yy, xx = np.ogrid[:FFT_SIZE, :FFT_SIZE]
    power[(yy - c) ** 2 + (xx - c) ** 2 <= r * r] = 0.0
    local_mean = cv2.boxFilter(power, -1, (LOCAL_MEAN_KERNEL, LOCAL_MEAN_KERNEL),
                               normalize=True)
    ratio = np.zeros_like(power)
    np.divide(power, local_mean, out=ratio, where=local_mean > 0)
    top = np.sort(ratio.ravel())[::-1][:MOIRE_TOP_PEAKS]
    return float(top.mean())


def screen_replay_integrity(img: np.ndarray) -> float:
    """1.0 = no periodic screen pattern; ~0.0 = strong moire (photo of screen)."""
    peakiness = _moire_peakiness(img)
    if peakiness <= MOIRE_PEAKINESS_SUSPECT:
        return 1.0
    if peakiness >= MOIRE_PEAKINESS_REPLAY:
        return 0.0
    return round(1.0 - (peakiness - MOIRE_PEAKINESS_SUSPECT)
                 / (MOIRE_PEAKINESS_REPLAY - MOIRE_PEAKINESS_SUSPECT), 3)


def edge_border_integrity(img: np.ndarray) -> float:
    """Score 0-1 for presence of a dominant quadrilateral document border."""
    h, w = img.shape[:2]
    frame_area = float(h * w)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(gray, 50, 150)
    edges = cv2.dilate(edges, np.ones((3, 3), np.uint8), iterations=1)
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL,
                                   cv2.CHAIN_APPROX_SIMPLE)
    best = 0.0
    for contour in contours:
        area = cv2.contourArea(contour)
        frac = area / frame_area
        if frac < BORDER_MIN_AREA_FRACTION:
            continue
        peri = cv2.arcLength(contour, True)
        approx = cv2.approxPolyDP(contour, 0.02 * peri, True)
        if len(approx) != 4 or not cv2.isContourConvex(approx):
            continue
        best = max(best, min(1.0, frac / BORDER_FULL_AREA_FRACTION))
    return round(best, 3)


def resolution_sanity(img: np.ndarray) -> dict[str, Any]:
    h, w = img.shape[:2]
    mp = (h * w) / 1e6
    ok = min(h, w) >= MIN_DIMENSION_PX and mp >= MIN_MEGAPIXELS
    reason = None
    if min(h, w) < MIN_DIMENSION_PX:
        reason = (f"smallest dimension {min(h, w)}px below "
                  f"{MIN_DIMENSION_PX}px minimum")
    elif mp < MIN_MEGAPIXELS:
        reason = f"{mp:.3f}MP below {MIN_MEGAPIXELS}MP minimum"
    return {"width": int(w), "height": int(h), "megapixels": round(mp, 4),
            "ok": ok, "reason": reason}


def color_diversity(img: np.ndarray) -> dict[str, Any]:
    """Quantized unique-colour count; flat renders score near 0."""
    quantized = (img // COLOR_QUANT).reshape(-1, 3)
    unique = np.unique(quantized, axis=0).shape[0]
    return {
        "unique_colors": int(unique),
        "score": round(min(1.0, unique / COLOR_DIVERSITY_FULL), 3),
    }


def analyze_document_image(image_bytes: bytes) -> dict[str, Any]:
    """Full local analysis. Never raises: undecodable input is reported."""
    img = decode_image(image_bytes)
    if img is None:
        return {
            "decode_ok": False,
            "quality": "poor",
            "quality_scores": {},
            "screen_replay_integrity": None,
            "printed_cutout_integrity": None,
            "verdict_reasons": [
                "image bytes could not be decoded as a supported image format"
            ],
        }

    blur = blur_score(img)
    glare = glare_score(img)
    res = resolution_sanity(img)
    diversity = color_diversity(img)
    replay = screen_replay_integrity(img)
    border = edge_border_integrity(img)
    # Printed-cutout / physical-document signal: a genuinely captured printed
    # document has a physical border AND photographic colour texture. A flat
    # digital render has neither; a screenshot of a document may have a
    # border but no texture.
    cutout = round(0.5 * border + 0.5 * diversity["score"], 3)

    reasons: list[str] = []
    if not res["ok"]:
        reasons.append(f"resolution inadequate: {res['reason']}")
    if blur < BLUR_POOR_THRESHOLD:
        reasons.append(f"image blurred (Laplacian variance {blur:.1f} below "
                       f"{BLUR_POOR_THRESHOLD})")
    if glare > GLARE_POOR_FRACTION:
        reasons.append(f"severe glare: {glare:.1%} of pixels saturated")
    elif glare > GLARE_WARN_FRACTION:
        reasons.append(f"glare present: {glare:.1%} of pixels saturated")
    if replay < 0.35:
        reasons.append("periodic screen pattern (moire) detected — likely a "
                       "photograph of a screen, not a physical document")
    if border < 0.2:
        reasons.append("no dominant document border detected")

    if (not res["ok"]) or blur < BLUR_POOR_THRESHOLD or glare > GLARE_POOR_FRACTION:
        quality = "poor"
    elif blur >= BLUR_GOOD_THRESHOLD and glare <= GLARE_WARN_FRACTION:
        quality = "good"
    else:
        quality = "acceptable"

    return {
        "decode_ok": True,
        "quality": quality,
        "quality_scores": {
            "blur": round(blur, 2),
            "glare": round(glare, 4),
            "resolution": res,
            "color_diversity": diversity,
            "edge_border_integrity": border,
        },
        "screen_replay_integrity": round(replay, 3),
        "printed_cutout_integrity": cutout,
        "verdict_reasons": reasons,
    }
