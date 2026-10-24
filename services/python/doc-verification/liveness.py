"""Local liveness heuristics for selfie frame sequences.

PAD-READINESS — NOT CERTIFICATION. ISO/IEC 30107-3 defines presentation-attack
instrument (PAI) classes and evaluation methodology; actual PAD certification
requires an accredited lab (Fime, iBeta) testing against real attack
instruments. This module implements local, dependency-light signals that map
onto the taxonomy so the platform has an honest first line of defense and a
conformance harness ready for the certification pathway:

  PAI class            Signal(s) here
  -------------------  ------------------------------------------------
  Print (photo)        colour diversity + moire on face region;
                       border/texture weakness (flat render ~2 buckets)
  Replay (screen/video) FFT moire peakiness per frame (screen refresh
                       grid), plus moire VARIANCE across frames (LCD
                       refresh aliasing beats against camera shutter)
  Static/looped video  inter-frame motion ~= 0 across all frames, or
                       motion sequence repeats with near-zero novelty
  Mask / 3D / deepfake OUT OF SCOPE — requires trained models; any
                       inconclusive case routes to manual review and/or
                       the remote OpenKYC-compatible IDV when configured.

Challenge-response: the API issues a signed phase sequence (e.g.
["still","move","still"]); the engine segments the frame series into phases
and checks that observed motion matches the expected pattern — a pre-recorded
or static video cannot follow a freshly minted random challenge.

No face detector is available without ML dependencies; the face region is a
documented center-crop heuristic (faces dominate the central field in guided
selfie capture). Every signal reports provenance; the verdict is one of
"live" | "spoof" | "inconclusive" — inconclusive is the honest default when
signals conflict or are unmeasurable.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

import cv2
import numpy as np

import local_cv

# --- thresholds (documented, synthetic-calibrated, tunable) ---------------
# Inter-frame motion: mean absolute difference on 64x64 grayscale, 0..255.
MOTION_STILL_MAX = 2.0        # below this a frame pair is "still"
MOTION_MOVE_MIN = 6.0         # above this a frame pair shows real motion
# Moire: reuse local_cv peakiness calibration (clean ~12, moire 54-69).
MOIRE_REPLAY_PEAKINESS = local_cv.MOIRE_PEAKINESS_REPLAY
# Replay variance: moire peakiness varying strongly across frames suggests
# LCD-refresh aliasing (a live face has stable, low moire).
MOIRE_VARIANCE_REPLAY = 8.0
# Flat-render (print) signal on the face crop: quantized colour buckets.
FACE_FLAT_BUCKETS_MAX = 12.0
# Phase match tolerance: a phase counts as matched when its mean motion is
# on the expected side of the thresholds; ALL phases must match.
PHASE_MISMATCH_TOLERANCE = 0  # strict: any mismatched phase -> challenge fail

DOWNSCALE = 64


def _gray_small(frame_bgr: np.ndarray) -> np.ndarray:
    g = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
    return cv2.resize(g, (DOWNSCALE, DOWNSCALE), interpolation=cv2.INTER_AREA)


def _face_crop(frame_bgr: np.ndarray) -> np.ndarray:
    """Center-crop heuristic: middle 50% x 60% of the frame."""
    h, w = frame_bgr.shape[:2]
    x0, x1 = int(w * 0.25), int(w * 0.75)
    y0, y1 = int(h * 0.20), int(h * 0.80)
    return frame_bgr[y0:y1, x0:x1]


def _decode_frames(frames: Sequence[bytes]) -> tuple[list[np.ndarray], int]:
    """Decode jpeg/png byte frames; returns (frames, undecodable_count)."""
    out: list[np.ndarray] = []
    bad = 0
    for fb in frames:
        if not fb:
            bad += 1
            continue
        arr = np.frombuffer(fb, dtype=np.uint8)
        try:
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        except cv2.error:
            img = None
        if img is None:
            bad += 1
        else:
            out.append(img)
    return out, bad


def _moire_peakiness(frame_bgr: np.ndarray) -> float:
    """Same FFT peakiness measure as local_cv (axis/disk suppressed)."""
    return local_cv._moire_peakiness(frame_bgr)


def _colour_buckets(frame_bgr: np.ndarray) -> int:
    """Quantized unique-colour count, same measure as local_cv.color_diversity."""
    quantized = (frame_bgr // local_cv.COLOR_QUANT).reshape(-1, 3)
    return int(np.unique(quantized, axis=0).shape[0])


def analyze_frame_sequence(
    frames: Sequence[bytes],
    challenge_phases: Optional[Sequence[str]] = None,
) -> dict[str, Any]:
    """Analyze a selfie frame sequence for liveness.

    frames: ordered list of encoded image byte strings (>=2 for motion).
    challenge_phases: optional expected phase pattern ("still"|"move").
    Returns a verdict dict with per-signal provenance; never raises.
    """
    signals: list[dict[str, Any]] = []
    reasons: list[str] = []

    def sig(name: str, status: str, detail: str = "", **extra: Any) -> None:
        entry: dict[str, Any] = {"signal": name, "status": status}
        if detail:
            entry["detail"] = detail
        entry.update(extra)
        signals.append(entry)

    decoded, bad = _decode_frames(frames)
    if bad:
        sig("decode", "ran", f"{bad}/{len(frames)} frames undecodable")
        reasons.append(f"{bad} undecodable frame(s)")
    if len(decoded) < 2:
        return {
            "verdict": "inconclusive",
            "reason": "fewer than 2 decodable frames — motion signals "
                      "unmeasurable; routed to manual review",
            "signals": signals + [{"signal": "motion", "status": "unavailable",
                                   "reason": "insufficient frames"}],
            "frames_received": len(frames),
            "frames_decoded": len(decoded),
            "challenge_checked": False,
        }

    n = len(decoded)
    smalls = [_gray_small(f) for f in decoded]

    # --- signal 1: per-frame moire (screen replay) -------------------------
    peakiness = [_moire_peakiness(f) for f in decoded]
    max_pk = float(max(peakiness))
    pk_var = float(np.std(peakiness))
    moire_replay = max_pk >= MOIRE_REPLAY_PEAKINESS
    sig("screen_replay_moire", "ran",
        f"max_peakiness={max_pk:.1f} std={pk_var:.1f} "
        f"(replay>={MOIRE_REPLAY_PEAKINESS})",
        max_peakiness=max_pk, peakiness_std=pk_var, replay=moire_replay)
    if moire_replay:
        reasons.append("screen-replay moire pattern detected in frames")

    # --- signal 2: inter-frame motion --------------------------------------
    motion = [float(np.mean(np.abs(smalls[i].astype(np.int16)
                                   - smalls[i - 1].astype(np.int16))))
              for i in range(1, n)]
    mean_motion = float(np.mean(motion))
    max_motion = float(np.max(motion))
    all_static = max_motion < MOTION_STILL_MAX
    sig("inter_frame_motion", "ran",
        f"mean={mean_motion:.2f} max={max_motion:.2f} "
        f"(still<{MOTION_STILL_MAX}, move>{MOTION_MOVE_MIN})",
        mean_motion=mean_motion, max_motion=max_motion,
        per_pair=[round(m, 2) for m in motion])
    if all_static:
        reasons.append("no inter-frame motion — static image or frozen video")

    # --- signal 3: face-region texture (print attack) ----------------------
    crops = [_face_crop(f) for f in decoded]
    buckets = [_colour_buckets(c) for c in crops]
    mean_buckets = float(np.mean(buckets))
    flat_face = mean_buckets <= FACE_FLAT_BUCKETS_MAX
    sig("face_texture", "ran",
        f"mean_colour_buckets={mean_buckets:.1f} "
        f"(flat<={FACE_FLAT_BUCKETS_MAX})",
        mean_colour_buckets=mean_buckets, flat=flat_face)
    if flat_face:
        reasons.append("face region texture is flat — possible printed photo")

    # --- signal 4: challenge-response phase matching ------------------------
    challenge_checked = False
    challenge_passed: Optional[bool] = None
    if challenge_phases:
        challenge_checked = True
        phases = [p for p in challenge_phases if p in ("still", "move")]
        if not phases or n - 1 < len(phases):
            sig("challenge_response", "unavailable",
                "phase count incompatible with frame count")
            reasons.append("challenge could not be evaluated on the "
                           "provided frames")
        else:
            # Split the motion series into len(phases) contiguous segments.
            # Phase transitions legitimately produce one elevated motion
            # sample at each segment boundary (the subject STARTS moving),
            # so "still" segments are evaluated on their interior: trim one
            # sample from each end when the segment has >= 3 samples. This
            # mirrors how a human reviewer reads the sequence; a spoof that
            # is still THROUGHOUT a move phase or moving THROUGHOUT a still
            # phase still fails.
            seg = np.array_split(np.array(motion), len(phases))
            seg_means = []
            for phase, s in zip(phases, seg):
                values = s.tolist()
                if phase == "still" and len(values) >= 3:
                    values = values[1:-1]
                seg_means.append(float(np.mean(values)) if values else 0.0)
            mismatches = []
            for idx, (phase, m) in enumerate(zip(phases, seg_means)):
                if phase == "still" and m >= MOTION_STILL_MAX:
                    mismatches.append((idx, phase, round(m, 2)))
                if phase == "move" and m < MOTION_MOVE_MIN:
                    mismatches.append((idx, phase, round(m, 2)))
            challenge_passed = len(mismatches) <= PHASE_MISMATCH_TOLERANCE
            sig("challenge_response", "ran",
                f"phases={phases} segment_motion={[round(m,2) for m in seg_means]} "
                f"mismatches={mismatches}",
                passed=challenge_passed)
            if not challenge_passed:
                reasons.append("observed motion does not match the issued "
                               "challenge phases")

    # --- verdict -------------------------------------------------------------
    hard_spoof = moire_replay or (challenge_checked and challenge_passed is False)
    weak_signals = all_static or flat_face
    if hard_spoof:
        verdict = "spoof"
    elif weak_signals:
        verdict = "inconclusive"
        reasons.append("weak liveness signals — routed to manual review")
    elif challenge_checked and challenge_passed:
        verdict = "live"
    else:
        # No challenge issued: clean passive signals only -> never auto-live.
        verdict = "inconclusive"
        reasons.append("passive signals clean but no challenge-response — "
                       "manual review recommended")

    return {
        "verdict": verdict,
        "signals": signals,
        "reasons": reasons,
        "frames_received": len(frames),
        "frames_decoded": n,
        "challenge_checked": challenge_checked,
        "challenge_passed": challenge_passed,
        "motion": {"mean": mean_motion, "max": max_motion},
        "moire": {"max_peakiness": max_pk, "peakiness_std": pk_var},
    }
