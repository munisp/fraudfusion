"""Perceptual document fingerprints (Round 14).

Cryptographic hashes detect byte-identical resubmission; perceptual hashes
detect the SAME document re-photographed, re-scanned, re-compressed, or
slightly cropped — the "same forged C-of-O submitted to five lenders"
pattern.

  * dhash — 8x8 difference hash (robust to re-encoding/crop)
  * phash — DCT hash (robust to colour/lighting changes)

hamming(a, b) on 64-bit ints; combined distance guides the near-duplicate
registry lookup. Pure numpy/cv2; never raises.
"""

from __future__ import annotations

from typing import Any, Optional

import cv2
import numpy as np


def _prep(image_bytes: bytes, size: tuple[int, int]) -> Optional[np.ndarray]:
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None
    return cv2.resize(img, size, interpolation=cv2.INTER_AREA)


def _to_int(bits: np.ndarray) -> int:
    return int(np.packbits(bits.astype(np.uint8).flatten()).tobytes().hex(), 16)


def dhash(image_bytes: bytes) -> Optional[int]:
    small = _prep(image_bytes, (9, 8))
    if small is None:
        return None
    return _to_int(small[:, 1:] > small[:, :-1])


def phash(image_bytes: bytes) -> Optional[int]:
    small = _prep(image_bytes, (32, 32))
    if small is None:
        return None
    dct = cv2.dct(small.astype(np.float64))[:8, :8]
    med = float(np.median(dct[1:, 1:]))
    return _to_int(dct > med)


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def fingerprint(image_bytes: bytes) -> dict[str, Any]:
    return {"dhash": dhash(image_bytes), "phash": phash(image_bytes)}


# Combined-distance bands (0-128 possible). <=12: same document,
# re-captured. <=22: suspiciously similar — manual review.
SAME_DOCUMENT_THRESHOLD = 12
SIMILAR_THRESHOLD = 22


def distance(fp_a: dict[str, Any], fp_b: dict[str, Any]) -> Optional[int]:
    if None in (fp_a.get("dhash"), fp_a.get("phash"),
                fp_b.get("dhash"), fp_b.get("phash")):
        return None
    return hamming(fp_a["dhash"], fp_b["dhash"]) + hamming(fp_a["phash"], fp_b["phash"])
