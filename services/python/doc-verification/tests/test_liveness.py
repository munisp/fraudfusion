"""PAD-readiness conformance suite for the local liveness engine.

Generates SYNTHETIC attack-instrument classes (ISO/IEC 30107-3 mapping in
liveness.py's docstring) and asserts the engine classifies each correctly —
or degrades honestly to inconclusive, never to a fabricated verdict:

  * genuine       — textured frames with real inter-frame motion following
                    the issued challenge -> "live"
  * replay_attack — moire grid frames (photo of a screen) -> "spoof"
  * static_attack — duplicated frames (frozen video / still photo) ->
                    NOT live (inconclusive; challenge mismatch -> spoof)
  * challenge_evasion — motion that does NOT follow the issued phases ->
                    "spoof"
  * print_attack  — flat-render face region -> inconclusive (weak signal)
  * garbage       — undecodable frames -> inconclusive, never raises
"""

from __future__ import annotations

import cv2
import numpy as np
import pytest

import liveness
import local_cv


def _encode(img: np.ndarray) -> bytes:
    ok, buf = cv2.imencode(".png", img)
    assert ok
    return buf.tobytes()


def _textured_frame(seed: int, offset: int = 0) -> np.ndarray:
    """Noisy, textured 'real capture' frame with a shifted bright region."""
    rng = np.random.default_rng(seed)
    img = rng.integers(30, 220, (240, 320, 3), dtype=np.uint8)
    cv2.ellipse(img, (160 + offset, 120), (55, 75), 0, 0, 360,
                (200, 180, 160), -1)
    noise = rng.integers(0, 25, img.shape, dtype=np.uint8)
    return cv2.add(img, noise)


def _moire_frame(seed: int, period: int = 6) -> np.ndarray:
    """Screen-photograph fixture: sinusoidal grid over a textured base."""
    base = _textured_frame(seed).astype(np.float64)
    h, w = base.shape[:2]
    yy, xx = np.mgrid[0:h, 0:w]
    grid = 40 * np.sin(2 * np.pi * xx / period) * np.sin(2 * np.pi * yy / period)
    out = np.clip(base + grid[..., None], 0, 255)
    return out.astype(np.uint8)


def _flat_frame(seed: int) -> np.ndarray:
    """Flat digital render: few colours, no sensor noise."""
    img = np.full((240, 320, 3), (220, 215, 210), dtype=np.uint8)
    cv2.ellipse(img, (160, 120), (55, 75), 0, 0, 360, (180, 160, 150), -1)
    cv2.rectangle(img, (40, 30), (280, 210), (200, 200, 200), 2)
    return img


# --- genuine sequence -------------------------------------------------------

def test_genuine_sequence_with_matching_challenge_is_live():
    # 10 frames: still (3 identical) -> move (4 whole-frame shifts, as a head
    # turn moves the whole capture) -> still (3 identical). 9 motion pairs
    # split evenly [3,3,3]; boundary transitions are trimmed inside "still"
    # segments by the engine.
    base = _textured_frame(1, 0)
    still2 = _textured_frame(2, 0)
    frames = ([base] * 3
              + [np.roll(base, s, axis=1) for s in (15, 30, 45, 60)]
              + [still2] * 3)
    result = liveness.analyze_frame_sequence(
        [_encode(f) for f in frames],
        challenge_phases=["still", "move", "still"])
    assert result["challenge_checked"] is True
    assert result["challenge_passed"] is True, result["reasons"]
    assert result["verdict"] == "live", result["reasons"]


def test_genuine_sequence_without_challenge_is_inconclusive_not_live():
    frames = [_textured_frame(1, 0), _textured_frame(1, 15),
              _textured_frame(1, 30)]
    result = liveness.analyze_frame_sequence([_encode(f) for f in frames])
    assert result["verdict"] == "inconclusive"
    assert result["challenge_checked"] is False


# --- attack classes ---------------------------------------------------------

@pytest.mark.parametrize("period", [4, 6, 8, 10])
def test_replay_attack_moire_frames_are_spoof(period):
    frames = [_moire_frame(7, period), _moire_frame(8, period),
              _moire_frame(9, period)]
    result = liveness.analyze_frame_sequence(
        [_encode(f) for f in frames],
        challenge_phases=["still", "still"])
    assert result["moire"]["max_peakiness"] >= local_cv.MOIRE_PEAKINESS_REPLAY
    assert result["verdict"] == "spoof"


def test_static_attack_duplicated_frames_not_live():
    f = _encode(_textured_frame(3, 0))
    result = liveness.analyze_frame_sequence(
        [f, f, f, f], challenge_phases=["move", "move"])
    assert result["motion"]["max"] < liveness.MOTION_STILL_MAX
    assert result["verdict"] == "spoof"  # challenge mismatch: expected motion


def test_static_attack_without_challenge_is_inconclusive():
    f = _encode(_textured_frame(3, 0))
    result = liveness.analyze_frame_sequence([f, f, f])
    assert result["verdict"] == "inconclusive"
    assert any("motion" in r for r in result["reasons"])


def test_challenge_evasion_wrong_phases_is_spoof():
    # Motion during a "still" phase: classic pre-recorded video behaviour.
    frames = [_textured_frame(1, o * 15) for o in range(4)]
    frames += [_textured_frame(1, 60) for _ in range(3)]
    result = liveness.analyze_frame_sequence(
        [_encode(f) for f in frames],
        challenge_phases=["still", "still"])
    assert result["challenge_passed"] is False
    assert result["verdict"] == "spoof"


def test_print_attack_flat_render_is_inconclusive():
    frames = [_flat_frame(1), _flat_frame(1)]
    result = liveness.analyze_frame_sequence([_encode(f) for f in frames])
    tex = next(s for s in result["signals"] if s["signal"] == "face_texture")
    assert tex["flat"] is True
    assert result["verdict"] == "inconclusive"


def test_garbage_frames_inconclusive_never_raises():
    result = liveness.analyze_frame_sequence([b"not-an-image", b"", b"\x00"])
    assert result["verdict"] == "inconclusive"
    assert result["frames_decoded"] == 0


def test_single_frame_inconclusive():
    result = liveness.analyze_frame_sequence([_encode(_textured_frame(1))])
    assert result["verdict"] == "inconclusive"


def test_provenance_on_every_signal():
    frames = [_textured_frame(1, 0), _textured_frame(1, 20)]
    result = liveness.analyze_frame_sequence(
        [_encode(f) for f in frames], challenge_phases=["move"])
    for s in result["signals"]:
        assert s["status"] in ("ran", "unavailable", "skipped")
        assert "signal" in s
