"""Shared synthetic fixtures for doc-verification tests.

All images are generated at test time with cv2/numpy — no binary fixtures.

  * clean_card   — textured, noisy, bordered document-like capture
  * blurry       — Gaussian-blurred version of clean_card
  * glare        — clean_card with a large saturated (white) ellipse overlay
  * moire        — clean_card + sinusoidal grid (simulated photo of a screen)
  * flat_render  — uniform white background + text, no border, no noise
"""

from __future__ import annotations

import sys
from pathlib import Path

import cv2
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _base_card() -> np.ndarray:
    img = np.full((480, 720, 3), (60, 70, 80), np.uint8)  # desk background
    cv2.rectangle(img, (40, 40), (680, 440), (230, 228, 220), -1)  # card
    cv2.rectangle(img, (40, 40), (680, 440), (40, 40, 40), 3)      # border
    lines = ["FEDERAL REPUBLIC OF NIGERIA", "NATIONAL IDENTITY CARD",
             "Name: ADAEZE EZE", "NIN: 12345678901", "DOB: 20/05/1990"]
    for i, text in enumerate(lines):
        cv2.putText(img, text, (70, 110 + i * 60), cv2.FONT_HERSHEY_SIMPLEX,
                    0.8, (20, 20, 20), 2)
    return img


@pytest.fixture(scope="session")
def clean_card() -> np.ndarray:
    img = _base_card()
    rng = np.random.default_rng(7)
    # sensor noise: this is what separates a real capture from a flat render
    noise = rng.normal(0, 6, img.shape)
    return np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)


@pytest.fixture(scope="session")
def blurry(clean_card) -> np.ndarray:
    return cv2.GaussianBlur(clean_card, (15, 15), 0)


@pytest.fixture(scope="session")
def glare(clean_card) -> np.ndarray:
    overlay = np.full_like(clean_card, 255)
    cv2.ellipse(overlay, (360, 240), (300, 200), 0, 0, 360, (255, 255, 255), -1)
    mask = cv2.cvtColor(overlay, cv2.COLOR_BGR2GRAY) > 0
    out = clean_card.copy()
    out[mask] = (0.3 * clean_card[mask] + 0.7 * 255).astype(np.uint8)
    return out


@pytest.fixture(scope="session")
def moire(clean_card) -> np.ndarray:
    yy, xx = np.mgrid[0:clean_card.shape[0], 0:clean_card.shape[1]]
    # amplitude 12 keeps pixels off the 255 clip rail so the glare signal
    # stays quiet and only the FFT periodicity drives detection
    grid = 12 * (np.sin(2 * np.pi * xx / 5.0) * np.sin(2 * np.pi * yy / 6.0))
    return np.clip(clean_card.astype(np.float64) + grid[:, :, None],
                   0, 255).astype(np.uint8)


@pytest.fixture(scope="session")
def flat_render() -> np.ndarray:
    img = np.full((480, 720, 3), 255, np.uint8)
    lines = ["FEDERAL REPUBLIC OF NIGERIA", "Name: ADAEZE EZE",
             "NIN: 12345678901"]
    for i, text in enumerate(lines):
        cv2.putText(img, text, (70, 130 + i * 70), cv2.FONT_HERSHEY_SIMPLEX,
                    0.9, (0, 0, 0), 2)
    return img


def to_png(img: np.ndarray) -> bytes:
    return cv2.imencode(".png", img)[1].tobytes()
