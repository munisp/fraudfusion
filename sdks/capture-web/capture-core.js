/**
 * @fraudfusion/capture-web — PURE LOGIC CORE (no DOM, no browser APIs).
 *
 * Client-side capture-quality metrics that mirror the server-side cv2
 * thresholds (services/python/doc-verification/local_cv.py) so the widget
 * can give real-time feedback and auto-capture when quality passes. Keeping
 * this DOM-free makes it fully testable under `node --test` with synthetic
 * pixel arrays; the browser widget (capture-widget.js) is a thin shell over
 * these functions.
 *
 * All functions operate on raw grayscale luminance arrays (Uint8Array or
 * number[]) plus width/height, so they work on canvas ImageData (after
 * rgba->gray) in the browser and on plain arrays in tests.
 */

"use strict";

/** Convert RGBA pixel data (Uint8ClampedArray) to grayscale luminance. */
function rgbaToGray(rgba, width, height) {
  const gray = new Float64Array(width * height);
  for (let i = 0; i < width * height; i++) {
    const o = i * 4;
    gray[i] = 0.299 * rgba[o] + 0.587 * rgba[o + 1] + 0.114 * rgba[o + 2];
  }
  return gray;
}

/**
 * Blur score: variance of the 4-neighbor discrete Laplacian. Matches the
 * server's Laplacian-variance approach; higher = sharper. Server thresholds:
 * blur < 40 poor, > 150 good.
 */
function blurScore(gray, width, height) {
  let sum = 0;
  let sumSq = 0;
  let n = 0;
  for (let y = 1; y < height - 1; y++) {
    for (let x = 1; x < width - 1; x++) {
      const i = y * width + x;
      const lap = 4 * gray[i] - gray[i - 1] - gray[i + 1]
        - gray[i - width] - gray[i + width];
      sum += lap;
      sumSq += lap * lap;
      n++;
    }
  }
  if (n === 0) return 0;
  const mean = sum / n;
  return sumSq / n - mean * mean;
}

/**
 * Glare score: fraction of pixels at/near saturation. A nearly all-white
 * frame is a blank background, NOT glare (mirrors the server's whiteout
 * guard) and reports glare unmeasurable (-1).
 */
function glareScore(gray, saturatedThreshold = 245, whiteoutFraction = 0.95) {
  let sat = 0;
  for (let i = 0; i < gray.length; i++) {
    if (gray[i] >= saturatedThreshold) sat++;
  }
  const frac = sat / gray.length;
  if (frac >= whiteoutFraction) return -1; // whiteout: honestly unmeasurable
  return frac;
}

/**
 * Colour-diversity proxy for flat renders: count of occupied luminance
 * buckets (server uses 24-level/channel RGB quantization; luminance buckets
 * are the DOM-free equivalent). Flat renders occupy very few buckets.
 */
function luminanceBuckets(gray, bucketWidth = 24) {
  const buckets = new Set();
  for (let i = 0; i < gray.length; i++) {
    buckets.add(Math.floor(gray[i] / bucketWidth));
  }
  return buckets.size;
}

/** Quality label from the client-side scores (mirrors server bands). */
function qualityLabel({ blur, glare, buckets }) {
  if (blur < 40 || (glare >= 0 && glare > 0.2) || buckets <= 2) return "poor";
  if (blur > 150 && (glare < 0 || glare < 0.05) && buckets >= 5) return "good";
  return "acceptable";
}

/**
 * Inter-frame motion: mean absolute difference of two equal-size grayscale
 * frames. Server thresholds: < 2.0 still, > 6.0 moving.
 */
function frameMotion(grayA, grayB) {
  if (grayA.length !== grayB.length || grayA.length === 0) return 0;
  let sum = 0;
  for (let i = 0; i < grayA.length; i++) {
    sum += Math.abs(grayA[i] - grayB[i]);
  }
  return sum / grayA.length;
}

const MOTION_STILL_MAX = 2.0;
const MOTION_MOVE_MIN = 6.0;

/**
 * Evaluate observed per-segment mean motion against issued challenge phases
 * ("still" | "move"). motions: array of inter-frame motion values in capture
 * order; phases: the issued sequence. The motion series is split into
 * len(phases) contiguous segments; for "still" segments the first/last
 * sample is dropped when the segment has >= 3 samples (boundary transitions
 * are legitimate — mirrors the server engine).
 */
function evaluateChallenge(motions, phases) {
  if (!phases || phases.length === 0) {
    return { checked: false, passed: null, reason: "no challenge issued" };
  }
  if (motions.length < phases.length) {
    return { checked: false, passed: null,
             reason: "fewer motion samples than phases" };
  }
  const segSize = motions.length / phases.length;
  const segments = phases.map((_, i) =>
    motions.slice(Math.floor(i * segSize), Math.floor((i + 1) * segSize)));
  const mismatches = [];
  const segmentMeans = segments.map((seg, i) => {
    let values = seg;
    if (phases[i] === "still" && values.length >= 3) {
      values = values.slice(1, -1);
    }
    const mean = values.length
      ? values.reduce((a, b) => a + b, 0) / values.length
      : 0;
    if (phases[i] === "still" && mean >= MOTION_STILL_MAX) {
      mismatches.push({ phase: i, expected: "still", mean });
    }
    if (phases[i] === "move" && mean < MOTION_MOVE_MIN) {
      mismatches.push({ phase: i, expected: "move", mean });
    }
    return mean;
  });
  return { checked: true, passed: mismatches.length === 0,
           mismatches, segmentMeans };
}

/** Downscale a grayscale frame to at most maxDim on the long edge. */
function downscale(gray, width, height, maxDim = 64) {
  const scale = Math.min(1, maxDim / Math.max(width, height));
  const w = Math.max(1, Math.round(width * scale));
  const h = Math.max(1, Math.round(height * scale));
  const out = new Float64Array(w * h);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const sx = Math.min(width - 1, Math.floor(x / scale));
      const sy = Math.min(height - 1, Math.floor(y / scale));
      out[y * w + x] = gray[sy * width + sx];
    }
  }
  return { gray: out, width: w, height: h };
}

module.exports = {
  rgbaToGray, blurScore, glareScore, luminanceBuckets, qualityLabel,
  frameMotion, evaluateChallenge, downscale,
  MOTION_STILL_MAX, MOTION_MOVE_MIN,
};
