"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const core = require("../capture-core.js");

// --- synthetic frame builders ----------------------------------------------

function noisyGray(seed, size = 64) {
  // deterministic pseudo-noise (LCG) so tests are reproducible
  let s = seed >>> 0;
  const out = new Float64Array(size * size);
  for (let i = 0; i < out.length; i++) {
    s = (s * 1664525 + 1013904223) >>> 0;
    out[i] = 30 + (s % 190);
  }
  return out;
}

function flatGray(value, size = 64) {
  return new Float64Array(size * size).fill(value);
}

function blurredNoise(seed, size = 64) {
  // box-blur the noise: kills high frequency -> low Laplacian variance
  const src = noisyGray(seed, size);
  const out = new Float64Array(size * size);
  for (let y = 1; y < size - 1; y++) {
    for (let x = 1; x < size - 1; x++) {
      let sum = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          sum += src[(y + dy) * size + (x + dx)];
        }
      }
      out[y * size + x] = sum / 9;
    }
  }
  return out;
}

// --- tests -------------------------------------------------------------------

test("rgbaToGray converts with luma weights", () => {
  const rgba = new Uint8ClampedArray([255, 0, 0, 255, 0, 255, 0, 255]);
  const gray = core.rgbaToGray(rgba, 2, 1);
  assert.ok(Math.abs(gray[0] - 76.245) < 0.01); // pure red
  assert.ok(Math.abs(gray[1] - 149.685) < 0.01); // pure green
});

test("blurScore: sharp noise >> blurred noise > flat", () => {
  const sharp = core.blurScore(noisyGray(1), 64, 64);
  const blurred = core.blurScore(blurredNoise(1), 64, 64);
  const flat = core.blurScore(flatGray(128), 64, 64);
  assert.ok(sharp > 150, `sharp ${sharp}`);
  assert.ok(blurred < sharp / 10, `blurred ${blurred} vs sharp ${sharp}`);
  assert.equal(flat, 0);
});

test("glareScore: saturated fraction; whiteout honestly unmeasurable", () => {
  const some = flatGray(0);
  some[0] = 255;
  some[1] = 250;
  const g = core.glareScore(some);
  assert.ok(Math.abs(g - 2 / some.length) < 1e-12);
  assert.equal(core.glareScore(flatGray(255)), -1); // whiteout guard
});

test("luminanceBuckets: flat render occupies 1 bucket", () => {
  assert.equal(core.luminanceBuckets(flatGray(128)), 1);
  assert.ok(core.luminanceBuckets(noisyGray(3)) >= 5);
});

test("qualityLabel bands", () => {
  assert.equal(core.qualityLabel({ blur: 10, glare: 0, buckets: 8 }), "poor");
  assert.equal(core.qualityLabel({ blur: 300, glare: 0, buckets: 8 }), "good");
  assert.equal(core.qualityLabel({ blur: 90, glare: 0.1, buckets: 4 }),
    "acceptable");
  assert.equal(core.qualityLabel({ blur: 300, glare: 0.3, buckets: 8 }),
    "poor");
});

test("frameMotion: identical = 0, shifted noise is large", () => {
  const a = noisyGray(5);
  assert.equal(core.frameMotion(a, a), 0);
  const b = noisyGray(6);
  assert.ok(core.frameMotion(a, b) > core.MOTION_MOVE_MIN);
});

test("evaluateChallenge: matching phases pass", () => {
  // still (low), move (high), still (low) with boundary spikes in still segs
  const motions = [0.1, 0.2, 9.0, 8.0, 8.5, 8.2, 7.9, 0.1, 0.0];
  const res = core.evaluateChallenge(motions, ["still", "move", "still"]);
  assert.equal(res.checked, true);
  assert.equal(res.passed, true, JSON.stringify(res.mismatches));
});

test("evaluateChallenge: motion during still phase fails", () => {
  const motions = [8.0, 8.1, 7.9, 0.1, 0.2, 0.1, 0.0, 0.1, 0.2];
  const res = core.evaluateChallenge(motions, ["still", "move", "still"]);
  assert.equal(res.passed, false);
  assert.equal(res.mismatches[0].expected, "still");
});

test("evaluateChallenge: static video fails move phase", () => {
  const motions = [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1];
  const res = core.evaluateChallenge(motions, ["still", "move", "still"]);
  assert.equal(res.passed, false);
  assert.ok(res.mismatches.some((m) => m.expected === "move"));
});

test("evaluateChallenge: no challenge is honestly unchecked", () => {
  const res = core.evaluateChallenge([1, 2, 3], []);
  assert.equal(res.checked, false);
  assert.equal(res.passed, null);
});

test("downscale halves dimensions preserving values", () => {
  const g = flatGray(77, 128);
  const d = core.downscale(g, 128, 128, 64);
  assert.equal(d.width, 64);
  assert.equal(d.height, 64);
  assert.equal(d.gray[0], 77);
});
