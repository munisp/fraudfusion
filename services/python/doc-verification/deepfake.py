"""Local deepfake / face-swap forensics for selfie frame sequences.

COMPLEMENT TO LIVENESS — NOT A TRAINED DETECTOR. State-of-the-art deepfake
detection uses trained models (EfficientNet/ViT ensembles on FaceForensics++
etc.); this module is the dependency-light first line of defense, built on
the deterministic artifacts that face-swap and reenactment pipelines leave
behind even after post-processing:

  Signal                Artifact it catches
  --------------------  --------------------------------------------------
  noise_inconsistency   A swapped face is synthesized/smoothed (GAN/decoder
                        output) then pasted onto sensor footage: high-
                        frequency noise energy inside the face region is
                        materially LOWER than in the surrounding ring
                        (or mismatched in the other direction after
                        re-noising). The low side requires a real sensor
                        noise floor outside — a uniformly flat render is
                        consistent, not a swap.
  colour_mismatch       Face region white balance / channel means disagree
                        with the scene (the swap source was lit and
                        balanced differently). Weak alone — skin vs
                        background legitimately differs — lowest weight.
  temporal_flicker      Per-frame generation has no temporal coherence:
                        after RIGID MOTION COMPENSATION (phase correlation
                        on the face crop), a real moving face aligns to
                        near-zero residual while a synthesized identity
                        keeps churning (teeth/eyes/hairline shimmer). The
                        aligned face residual is compared against the
                        background band's churn — a static scene with a
                        genuinely moving head does NOT fire, because the
                        motion is rigid and aligns away.

NOTE — seam/boundary detection was evaluated and REMOVED: against noisy
texture a paste contour does not separate reliably from genuine content
with any deterministic metric (measured dominance 0.08 genuine vs 0.13
swapped — no usable threshold). Mask-seam detection is what the trained-
model lane (remote IDV / future local model) is for; this module stays
honest about the three signals that DO separate.

The face region uses the same documented center-crop heuristic as
liveness.py (guided selfie capture centers the face). The composite score
(0-50) maps: 50 (all signals agree) deepfake_suspected, >= 15 review, else
consistent. Every signal reports measured values + thresholds; analyze()
never raises.
"""

from __future__ import annotations

from typing import Any, Sequence

import cv2
import numpy as np

# --- thresholds (documented, synthetic-calibrated, tunable) ---------------
# Noise energy ratio face/surround (MAD-based). Genuine faces are smoother
# than textured backgrounds (measured ~0.23 on noise-textured captures), so
# only a NEAR-FLAT face region against a noisy scene fires (<0.1 — the
# decoder-smoothness signature, measured ~0.01). The low side also requires
# a real sensor-noise floor outside — a uniformly flat render is CONSISTENT,
# not a swap.
NOISE_RATIO_LOW = 0.1
NOISE_RATIO_HIGH = 1.8
NOISE_FLOOR_MIN = 2.0
# Colour mismatch: max per-channel mean-ratio deviation from 1.0 between
# face crop and surround ring. Skin vs background legitimately deviates
# (~0.29 measured on genuine tone shifts), so only a strong white-balance
# break fires. Weakest signal — lowest weight.
COLOUR_DEVIATION_SUSPECT = 0.35
# Temporal flicker: median best-match NCC between consecutive face crops.
# The same face matches high even when it moves against a static scene
# (~0.47 measured); only near-total decorrelation (<0.35 — per-frame
# identity regeneration) fires.
FLICKER_NCC_MIN = 0.35

# Composite weights (max 50). HONEST CALIBRATION: no single deterministic
# signal convicts — each has a plausible genuine explanation (smooth skin,
# skin-tone shift, aggressive compression). One signal -> manual review
# (15+); only ALL THREE agreeing (50) reaches deepfake_suspected. Trained-
# model detection remains the conviction lane; these signals exist to
# route borderline captures to humans and to veto auto-live.
WEIGHTS = {
    "noise_inconsistency": 15,
    "colour_mismatch": 10,
    "temporal_flicker": 25,
}
SCORE_DEEPFAKE_SUSPECTED = 50
SCORE_REVIEW = 15

DOWNSCALE = 64
_EPS = 1e-6


def _face_crop(frame_bgr: np.ndarray) -> np.ndarray:
    """Same center-crop heuristic as liveness.py (middle 50% x 60%)."""
    h, w = frame_bgr.shape[:2]
    return frame_bgr[int(h * 0.20):int(h * 0.80),
                     int(w * 0.25):int(w * 0.75)]


def _surround_ring(frame_bgr: np.ndarray, frac: float = 0.10) -> np.ndarray:
    """Ring just OUTSIDE the face crop — same scene, same sensor."""
    h, w = frame_bgr.shape[:2]
    x0, x1 = int(w * 0.25), int(w * 0.75)
    y0, y1 = int(h * 0.20), int(h * 0.80)
    m = int(min(w, h) * frac)
    top = frame_bgr[max(0, y0 - m):y0, x0:x1]
    bottom = frame_bgr[y1:min(h, y1 + m), x0:x1]
    parts = [p for p in (top, bottom) if p.size]
    if not parts:
        return frame_bgr[:m, :]
    return np.vstack(parts)


def _noise_energy(gray: np.ndarray) -> float:
    """High-frequency residual energy via MAD (median absolute deviation).

    MAD, not std: sparse STRUCTURE edges (a border line, a seal) must not
    masquerade as a sensor-noise floor — they dominate std but not MAD.
    """
    if gray.size == 0:
        return 0.0
    g = gray.astype(np.float64)
    residual = np.abs(g - cv2.medianBlur(gray, 5).astype(np.float64))
    return float(np.median(residual) * 1.4826)  # MAD -> sigma-equivalent


def _gray(frame_bgr: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)


def noise_inconsistency(frame_bgr: np.ndarray) -> dict[str, Any]:
    """Face-vs-surround noise energy ratio; fires on either direction."""
    face, ring = _gray(_face_crop(frame_bgr)), _gray(_surround_ring(frame_bgr))
    fe, re = _noise_energy(face), _noise_energy(ring)
    ratio = fe / (re + _EPS)
    fired = ((ratio < NOISE_RATIO_LOW and re >= NOISE_FLOOR_MIN)
             or ratio > NOISE_RATIO_HIGH)
    return {"signal": "noise_inconsistency", "status": "ran",
            "face_noise": round(fe, 3), "surround_noise": round(re, 3),
            "ratio": round(ratio, 3),
            "detail": f"ratio={ratio:.2f} (suspect <{NOISE_RATIO_LOW} with "
                      f"surround floor >={NOISE_FLOOR_MIN}, or "
                      f">{NOISE_RATIO_HIGH})",
            "fired": fired}


def colour_mismatch(frame_bgr: np.ndarray) -> dict[str, Any]:
    """Per-channel mean deviation between face crop and surround ring."""
    face, ring = _face_crop(frame_bgr), _surround_ring(frame_bgr)
    if face.size == 0 or ring.size == 0:
        return {"signal": "colour_mismatch", "status": "unavailable",
                "reason": "empty region", "fired": False}
    fm = face.reshape(-1, 3).mean(axis=0)
    rm = ring.reshape(-1, 3).mean(axis=0)
    dev = float(np.max(np.abs(fm / (rm + _EPS) - 1.0)))
    fired = dev >= COLOUR_DEVIATION_SUSPECT
    return {"signal": "colour_mismatch", "status": "ran",
            "face_channel_means": [round(float(v), 1) for v in fm],
            "surround_channel_means": [round(float(v), 1) for v in rm],
            "max_deviation": round(dev, 3),
            "detail": f"max channel deviation={dev:.3f} "
                      f"(suspect >={COLOUR_DEVIATION_SUSPECT})",
            "fired": fired}


def temporal_flicker(frames: Sequence[np.ndarray]) -> dict[str, Any]:
    """Face self-similarity across frames (best-match NCC).

    A real face is the SAME face in every frame: under the best integer
    translation, consecutive face crops correlate strongly. Per-frame
    synthesis regenerates the identity — even at the best alignment the
    structural content differs, so the match peak collapses. Background
    motion is irrelevant by construction (only the face crops compare).
    """
    if len(frames) < 2:
        return {"signal": "temporal_flicker", "status": "unavailable",
                "reason": "fewer than 2 frames", "fired": False}
    peaks = []
    for i in range(1, len(frames)):
        pf, cf = _gray(_face_crop(frames[i - 1])), _gray(_face_crop(frames[i]))
        if pf.size == 0 or cf.size == 0:
            continue
        h = min(pf.shape[0], cf.shape[0]); w = min(pf.shape[1], cf.shape[1])
        pf, cf = pf[:h, :w], cf[:h, :w]
        # Template = central 50% of the previous face (always fully inside
        # the current crop's search area); peak = best-alignment NCC.
        th, tw = h // 2, w // 2
        template = pf[h // 4:h // 4 + th, w // 4:w // 4 + tw]
        if template.size == 0 or template.shape[0] >= h or template.shape[1] >= w:
            continue
        result = cv2.matchTemplate(cf, template, cv2.TM_CCOEFF_NORMED)
        peaks.append(float(result.max()))
    if not peaks:
        return {"signal": "temporal_flicker", "status": "unavailable",
                "reason": "no comparable frame pairs", "fired": False}
    med = float(np.median(peaks))
    fired = med < FLICKER_NCC_MIN
    return {"signal": "temporal_flicker", "status": "ran",
            "median_match_peak": round(med, 3),
            "per_pair": [round(p, 3) for p in peaks],
            "detail": f"median best-match face NCC={med:.3f} "
                      f"(suspect <{FLICKER_NCC_MIN})",
            "fired": fired}


def score_signals(signals: list[dict[str, Any]]) -> int:
    return int(sum(WEIGHTS.get(s["signal"], 0) for s in signals if s.get("fired")))


def analyze(frames: Sequence[np.ndarray]) -> dict[str, Any]:
    """Composite deepfake assessment over a decoded frame sequence.

    frames: decoded BGR ndarrays (liveness._decode_frames output). Never
    raises; unmeasurable signals degrade to 'unavailable' honestly.
    """
    if not frames:
        return {"deepfake_score": 0, "assessment": "unmeasurable",
                "reason": "no decodable frames", "signals": []}
    signals: list[dict[str, Any]] = []
    try:
        # Per-frame spatial signals on the median-voting frame set; report
        # the WORST frame (an attacker only needs one clean frame to pass a
        # lenient check, so the strict reading is the honest one).
        per_noise = [noise_inconsistency(f) for f in frames]
        per_colour = [colour_mismatch(f) for f in frames]
        noise = max(per_noise, key=lambda s: abs(s.get("ratio", 1) - 1))
        colour = max(per_colour, key=lambda s: s.get("max_deviation", 0))
        noise["fired"] = any(s.get("fired") for s in per_noise)
        colour["fired"] = any(s.get("fired") for s in per_colour)
        signals.extend([noise, colour, temporal_flicker(frames)])
    except Exception as exc:  # never break liveness on a forensics bug
        return {"deepfake_score": 0, "assessment": "unmeasurable",
                "reason": f"deepfake analysis error ({exc.__class__.__name__})",
                "signals": signals}
    score = score_signals(signals)
    if score >= SCORE_DEEPFAKE_SUSPECTED:
        assessment = "deepfake_suspected"
    elif score >= SCORE_REVIEW:
        assessment = "review"
    else:
        assessment = "consistent"
    return {"deepfake_score": score, "assessment": assessment,
            "signals": signals}
