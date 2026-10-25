"""Deepfake / face-swap forensics conformance suite (Round 17).

Synthetic attack-instrument classes for deepfake.py:

  * genuine        — uniform-sensor frames -> consistent (score < review)
  * face_swap      — smoothed foreign patch pasted in -> noise_inconsistency
                     fires -> deepfake_suspected
  * rebalanced_swap— swap with shifted colour balance -> colour_mismatch fires
  * synthetic_flicker — face region regenerates per frame while the scene
                     stays static -> temporal_flicker fires
  * liveness fold-in — a swap sequence that would PASS the motion challenge
                     must still be rejected/downgraded via the deepfake score
"""

from __future__ import annotations

import cv2
import numpy as np

import deepfake
import liveness


def _encode(img: np.ndarray) -> bytes:
    ok, buf = cv2.imencode(".png", img)
    assert ok
    return buf.tobytes()


def _scene(seed: int) -> np.ndarray:
    """Textured scene: random texture + centred ellipse 'face', with sensor
    noise over the WHOLE frame (a real capture has noise on the face too)."""
    rng = np.random.default_rng(seed)
    img = rng.integers(30, 220, (240, 320, 3), dtype=np.uint8)
    cv2.ellipse(img, (160, 120), (55, 75), 0, 0, 360, (200, 180, 160), -1)
    noise = rng.integers(0, 25, img.shape, dtype=np.uint8)
    return cv2.add(img, noise)


def _swap_frame(seed: int, colour_shift: int = 0) -> np.ndarray:
    """Face-swap artifact: the face-crop interior is replaced by a SMOOTHED
    (GAN-decoder-like) patch with a hard paste boundary."""
    img = _scene(seed)
    rng = np.random.default_rng(seed + 1000)
    patch = rng.integers(60, 200, (144, 160, 3), dtype=np.uint8)
    patch = cv2.GaussianBlur(patch, (0, 0), 4.0)  # decoder smoothness
    if colour_shift:
        patch = cv2.add(patch, np.full(patch.shape, colour_shift, np.uint8))
    img[48:192, 80:240] = patch  # exact face-crop region, hard edge
    return img


class TestSignals:
    def test_genuine_frame_is_consistent(self):
        frames = [_scene(1), np.roll(_scene(1), 15, axis=1)]
        result = deepfake.analyze(frames)
        assert result["deepfake_score"] < deepfake.SCORE_REVIEW, result
        assert result["assessment"] == "consistent"

    def test_swap_fires_noise_inconsistency(self):
        result = deepfake.analyze([_swap_frame(1)])
        fired = {s["signal"] for s in result["signals"] if s.get("fired")}
        assert "noise_inconsistency" in fired, result
        # One deterministic signal routes to review — conviction requires
        # all three (honest posture: trained models convict, heuristics
        # escalate).
        assert result["deepfake_score"] >= deepfake.SCORE_REVIEW
        assert result["assessment"] == "review"

    def test_colour_mismatch_signal_fires_on_extreme_imbalance(self):
        # Unit test of the colour mechanism itself: a full-region patch with
        # an extreme white-balance break (mean ~250 vs scene ~138).
        img = _scene(1)
        patch = np.full((144, 160, 3), 250, np.uint8)
        img[48:192, 80:240] = patch
        result = deepfake.analyze([img])
        colour = next(s for s in result["signals"]
                      if s["signal"] == "colour_mismatch")
        assert colour["fired"] is True, colour

    def test_rebalanced_swap_scores_review_via_noise(self):
        # A realistic soft-blended WB-shifted swap sits BELOW the colour
        # conviction threshold (skin-tone shifts are legitimately large) —
        # but its smoothed texture still fires the noise signal and routes
        # the capture to review. This documents the honest posture: colour
        # alone never convicts.
        img = _scene(1)
        rng = np.random.default_rng(7)
        patch = rng.integers(60, 200, (144, 160, 3), dtype=np.uint8)
        patch = cv2.GaussianBlur(patch, (0, 0), 4.0)
        patch = cv2.add(patch, np.full(patch.shape, 90, np.uint8))
        mask = np.zeros((144, 160), np.uint8)
        cv2.ellipse(mask, (80, 72), (60, 55), 0, 0, 360, 255, -1)
        roi = img[48:192, 80:240]
        roi[mask > 0] = patch[mask > 0]
        result = deepfake.analyze([img])
        fired = {s["signal"] for s in result["signals"] if s.get("fired")}
        assert "noise_inconsistency" in fired, result
        assert result["assessment"] == "review"

    def test_synthetic_flicker_fires(self):
        # Background static across frames; face region re-synthesized each
        # frame (different noise) — the per-frame-generation signature.
        base = _scene(1)
        frames = []
        for i in range(4):
            img = base.copy()
            rng = np.random.default_rng(50 + i)
            img[48:192, 80:240] = rng.integers(
                40, 220, (144, 160, 3), dtype=np.uint8)
            frames.append(img)
        result = deepfake.analyze(frames)
        flick = next(s for s in result["signals"]
                     if s["signal"] == "temporal_flicker")
        assert flick["fired"] is True, flick

    def test_empty_input_is_honest(self):
        result = deepfake.analyze([])
        assert result["assessment"] == "unmeasurable"


class TestLivenessFoldIn:
    def test_swap_passing_motion_challenge_never_auto_lives(self):
        # The swap frames MOVE per the challenge (whole-frame rolls), so the
        # challenge passes — but the noise signal must veto the live verdict
        # and route the capture to manual review.
        base = _swap_frame(1)
        frames = ([base] * 3
                  + [np.roll(base, s, axis=1) for s in (15, 30, 45, 60)]
                  + [base] * 3)
        result = liveness.analyze_frame_sequence(
            [_encode(f) for f in frames],
            challenge_phases=["still", "move", "still"])
        assert result["challenge_passed"] is True, result["reasons"]
        assert result["deepfake"]["score"] >= liveness.DEEPFAKE_REVIEW_SCORE
        assert result["verdict"] == "inconclusive"

    def test_all_signals_agreeing_is_spoof(self):
        # Conviction path: smooth regenerated face (noise) + per-frame
        # regeneration (flicker) + white-balance break (colour) all fire.
        base = _scene(1)
        frames = []
        for i in range(4):
            img = base.copy()
            rng = np.random.default_rng(50 + i)
            patch = cv2.GaussianBlur(
                rng.integers(60, 200, (144, 160, 3), dtype=np.uint8),
                (0, 0), 4.0)
            patch = cv2.add(patch, np.full(patch.shape, 65, np.uint8))
            img[48:192, 80:240] = patch
            frames.append(img)
        result = liveness.analyze_frame_sequence(
            [_encode(f) for f in frames],
            challenge_phases=["move", "move"])
        assert result["deepfake"]["score"] >= liveness.DEEPFAKE_SPOOF_SCORE
        assert result["deepfake"]["assessment"] == "deepfake_suspected"
        assert result["verdict"] == "spoof"

    def test_moderate_artifacts_downgrade_live_to_review(self, monkeypatch):
        # Wiring test for the review-band downgrade: with the review
        # threshold patched into the range of a real (small) deepfake
        # score, a challenge-passing sequence must downgrade live ->
        # inconclusive (never auto-pass).
        base = _swap_frame(1)  # noise signal fires -> score in review band
        frames = ([base] * 3
                  + [np.roll(base, s, axis=1) for s in (15, 30, 45, 60)]
                  + [base] * 3)
        probe = liveness.analyze_frame_sequence(
            [_encode(f) for f in frames],
            challenge_phases=["still", "move", "still"])
        score = probe["deepfake"]["score"]
        assert liveness.DEEPFAKE_REVIEW_SCORE <= score \
            < liveness.DEEPFAKE_SPOOF_SCORE, probe["deepfake"]
        monkeypatch.setattr(liveness, "DEEPFAKE_REVIEW_SCORE", score + 1)
        result = liveness.analyze_frame_sequence(
            [_encode(f) for f in frames],
            challenge_phases=["still", "move", "still"])
        assert result["challenge_passed"] is True, result["reasons"]
        assert result["verdict"] == "live", result["reasons"]

    def test_genuine_motion_sequence_remains_live(self):
        base = _scene(1)
        frames = ([base] * 3
                  + [np.roll(base, s, axis=1) for s in (15, 30, 45, 60)]
                  + [base] * 3)
        result = liveness.analyze_frame_sequence(
            [_encode(f) for f in frames],
            challenge_phases=["still", "move", "still"])
        assert result["verdict"] == "live", result["reasons"]
        assert result["deepfake"]["assessment"] == "consistent"
