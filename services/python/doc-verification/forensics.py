"""Pixel-level forgery forensics (Round 14, document intelligence engine).

Pure cv2/numpy detectors for the forgery patterns that dominate Nigerian
document fraud: a genuine scan/photo is digitally homogeneous — one capture
event, one compression history, one noise signature. A forgery (portrait
swapped, date patched, name spliced from another document, regions cloned
to hide stamps) breaks that homogeneity:

  * error_level_analysis   — spliced regions have a DIFFERENT JPEG
    compression history; re-saving at a known quality makes them glow.
  * noise_inconsistency    — sensor/printer noise std varies per block;
    a pasted region carries its source's noise signature.
  * copy_move_detect       — block-hash matching finds cloned regions
    (duplicated stamp/paper texture used to cover a name or date).
  * jpeg_ghost / double_compression — a re-compressed or re-saved image
    betrays a prior compression generation (digitally re-touched).
  * jpeg_grid_misalignment — spliced JPEG content rarely aligns to the
    host's 8x8 DCT grid.

Every metric is documented, deterministic, and NEVER raises on partial
data — a detector that cannot run reports None and contributes nothing.
"""

from __future__ import annotations

from typing import Any, Optional

import cv2
import numpy as np

# Signal thresholds (tuned on synthetic forgery corpora; each is reported
# with its raw metric so integrators can re-tune).
ELA_INCONSISTENCY_THRESHOLD = 0.8      # std/mean ratio of block ELA means
ELA_MAX_MEDIAN_THRESHOLD = 2.5         # hottest block vs median — splice glow
NOISE_CV_THRESHOLD = 0.55              # coefficient of variation, block noise
COPY_MOVE_MIN_CLONES = 6               # matching non-adjacent blocks
JPEG_GHOST_MIN_DELTA = 1.5             # re-save diff minimum at q != anchor
DOUBLE_JPEG_MIN_DELTA = 1.2

_BLOCK = 32


def _decode(image_bytes: bytes) -> Optional[np.ndarray]:
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    return img


def _gray(img: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)


def _resave_diff(img: np.ndarray, quality: int) -> np.ndarray:
    ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        return np.zeros(_gray(img).shape, dtype=np.float64)
    resaved = cv2.imdecode(enc, cv2.IMREAD_COLOR)
    return np.abs(_gray(img).astype(np.float64)
                  - _gray(resaved).astype(np.float64))


def _block_map(values: np.ndarray, block: int = _BLOCK) -> np.ndarray:
    """Mean-pool a 2-D map into block means (edge blocks dropped)."""
    h, w = values.shape
    bh, bw = h // block, w // block
    if bh == 0 or bw == 0:
        return np.zeros((0, 0))
    cropped = values[: bh * block, : bw * block]
    return cropped.reshape(bh, block, bw, block).mean(axis=(1, 3))


def error_level_analysis(img: np.ndarray) -> dict[str, Any]:
    """ELA: re-save at q90; a spliced region (different compression
    generation) responds differently. Homogeneity metric = std/mean of
    block ELA means — high values mean the document is a patchwork."""
    ela = _resave_diff(img, 90)
    blocks = _block_map(ela)
    if blocks.size == 0:
        return {"ela_mean": float(ela.mean()), "ela_inconsistency": None}
    mean = float(blocks.mean())
    inconsistency = float(blocks.std() / mean) if mean > 1e-6 else 0.0
    median = float(np.median(blocks))
    max_median = float(blocks.max() / median) if median > 1e-6 else 1.0
    suspected = (inconsistency > ELA_INCONSISTENCY_THRESHOLD
                 or max_median > ELA_MAX_MEDIAN_THRESHOLD)
    return {"ela_mean": mean, "ela_inconsistency": inconsistency,
            "ela_max_median_ratio": max_median, "splice_suspected": suspected}


def noise_inconsistency(img: np.ndarray) -> dict[str, Any]:
    """Per-block high-frequency noise std (median-residual energy). One
    capture => one noise signature; a paste imports foreign noise."""
    gray = _gray(img).astype(np.float64)
    residual = gray - cv2.medianBlur(gray.astype(np.uint8), 3).astype(np.float64)
    h, w = residual.shape
    bh, bw = h // _BLOCK, w // _BLOCK
    if bh == 0 or bw == 0:
        return {"noise_cv": None}
    stds = np.array([[residual[r * _BLOCK:(r + 1) * _BLOCK,
                               c * _BLOCK:(c + 1) * _BLOCK].std()
                      for c in range(bw)] for r in range(bh)])
    mean = float(stds.mean())
    cv = float(stds.std() / mean) if mean > 1e-6 else 0.0
    return {"noise_cv": cv, "noise_mean": mean,
            "inconsistent": cv > NOISE_CV_THRESHOLD}


def _block_hash(block: np.ndarray) -> int:
    small = cv2.resize(block, (8, 8), interpolation=cv2.INTER_AREA)
    med = float(np.median(small))
    bits = (small > med).flatten()
    return int(np.packbits(bits).tobytes().hex(), 16)


def copy_move_detect(img: np.ndarray) -> dict[str, Any]:
    """Cloned regions (duplicated stamp/texture hiding a name) appear as
    identical non-adjacent blocks. Hash every 32px block; count pairs that
    match exactly but are not neighbours."""
    gray = _gray(img)
    h, w = gray.shape
    bh, bw = h // _BLOCK, w // _BLOCK
    if bh < 2 or bw < 2:
        return {"clone_pairs": 0, "copy_move_suspected": False}
    hashes: dict[int, list[tuple[int, int]]] = {}
    for r in range(bh):
        for c in range(bw):
            block = gray[r * _BLOCK:(r + 1) * _BLOCK, c * _BLOCK:(c + 1) * _BLOCK]
            if block.std() < 2.0:   # flat paper blocks match trivially
                continue
            hashes.setdefault(_block_hash(block), []).append((r, c))
    def _mad(a: np.ndarray, b: np.ndarray) -> float:
        # A true clone is near-identical PIXEL FOR PIXEL (MAD ~ 0-1.5 even
        # after re-compression); repeated print texture (same geometry,
        # independent noise) sits at MAD >= 2.3. Edge/correlation verifiers
        # fail here because all bar-edge blocks share edge geometry.
        return float(np.abs(a.astype(np.float64)
                            - b.astype(np.float64)).mean())

    offsets: dict[tuple[int, int], int] = {}
    offset_sources: dict[tuple[int, int], set[tuple[int, int]]] = {}
    pairs = verified = 0
    for positions in hashes.values():
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                (r1, c1), (r2, c2) = positions[i], positions[j]
                if abs(r1 - r2) + abs(c1 - c2) <= 2:   # neighbours excluded
                    continue
                pairs += 1
                # Hash equality is only a CANDIDATE; pixel-parity verifies.
                b1 = gray[r1 * _BLOCK:(r1 + 1) * _BLOCK, c1 * _BLOCK:(c1 + 1) * _BLOCK]
                b2 = gray[r2 * _BLOCK:(r2 + 1) * _BLOCK, c2 * _BLOCK:(c2 + 1) * _BLOCK]
                if _mad(b1, b2) >= 2.0:
                    continue
                verified += 1
                key = (r1 - r2, c1 - c2)
                offsets[key] = offsets.get(key, 0) + 1
                offset_sources.setdefault(key, set()).add((r1, c1))
    max_coherent = max(offsets.values(), default=0)
    dominant = max(offsets, key=offsets.get) if offsets else None
    sources = offset_sources.get(dominant, set()) if dominant else set()
    src_rows = {r for r, _ in sources}
    src_cols = {c for _, c in sources}
    # A genuine clone is a 2-D REGION (>=2 rows AND >=2 cols of source
    # blocks sharing one translation vector). A 1-D run of matches along a
    # single row is a long printed line, not a clone.
    is_region = len(src_rows) >= 2 and len(src_cols) >= 2
    return {"clone_pairs": pairs, "verified_clone_pairs": verified,
            "coherent_offset_pairs": max_coherent,
            "clone_region_blocks": len(sources) if is_region else 0,
            "copy_move_suspected": is_region
            and max_coherent >= COPY_MOVE_MIN_CLONES}


def jpeg_ghost(img: np.ndarray) -> dict[str, Any]:
    """Re-save sweep: a once-compressed image has minimum response when
    re-saved at ITS original quality; content pasted from another
    generation (or a fully re-touched image) distorts that profile."""
    responses = {}
    for q in (70, 80, 90, 95):
        responses[q] = float(_resave_diff(img, q).mean())
    anchor = responses[95]
    best_other = min(responses[q] for q in (70, 80, 90))
    delta = anchor - best_other
    return {"resave_responses": responses, "ghost_delta": delta,
            "prior_compression_suspected": delta > JPEG_GHOST_MIN_DELTA}


def jpeg_grid_misalignment(img: np.ndarray) -> dict[str, Any]:
    """JPEG operates on an 8x8 grid. Compare edge energy on grid-aligned
    boundaries vs shifted ones; genuinely single-generation images show a
    strong aligned peak, spliced content dilutes it."""
    gray = _gray(img).astype(np.float64)
    gx = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
    energy = np.abs(gx).mean(axis=0)
    aligned = float(energy[7::8].mean())
    shifted = float(np.delete(energy, np.s_[7::8]).mean())
    ratio = aligned / shifted if shifted > 1e-6 else 1.0
    return {"grid_alignment_ratio": ratio}


def analyze(image_bytes: bytes) -> dict[str, Any]:
    """Run every pixel-forensics detector; never raises."""
    img = _decode(image_bytes)
    if img is None:
        return {"decode_ok": False, "signals": [], "metrics": {}}
    metrics: dict[str, Any] = {}
    signals: list[dict[str, Any]] = []

    ela = error_level_analysis(img)
    metrics["ela"] = {k: v for k, v in ela.items() if k != "splice_suspected"}
    if ela.get("splice_suspected"):
        signals.append({"code": "ela_splice",
                        "detail": f"ELA max/median {ela['ela_max_median_ratio']:.1f}, "
                                  f"block inconsistency {ela['ela_inconsistency']:.2f} — "
                                  f"regions have different compression histories "
                                  f"(spliced content)"})

    noise = noise_inconsistency(img)
    metrics["noise"] = {k: v for k, v in noise.items() if k != "inconsistent"}
    if noise.get("inconsistent"):
        signals.append({"code": "noise_inconsistency",
                        "detail": f"block noise CV {noise['noise_cv']:.2f} — "
                                  f"multiple capture/print sources in one image"})

    clones = copy_move_detect(img)
    metrics["copy_move"] = clones
    if clones["copy_move_suspected"]:
        signals.append({"code": "copy_move",
                        "detail": f"{clones['coherent_offset_pairs']} block pairs share "
                                  f"one translation vector — a region was cloned "
                                  f"(stamp/texture cover-up)"})

    ghost = jpeg_ghost(img)
    metrics["jpeg_ghost"] = {k: v for k, v in ghost.items()
                             if k != "prior_compression_suspected"}
    if ghost["prior_compression_suspected"]:
        signals.append({"code": "double_compression",
                        "detail": "re-save ghost detected — image has a prior "
                                  "compression generation (digitally re-touched)"})

    metrics["jpeg_grid"] = jpeg_grid_misalignment(img)
    return {"decode_ok": True, "signals": signals, "metrics": metrics}
