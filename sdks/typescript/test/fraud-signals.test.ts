/**
 * Parity contract test: the TypeScript detectors must reproduce the Python
 * reference scores/verdicts/factor-codes in detector_cases.json exactly.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS, DetectorName, HistoryEvent } from "../src/fraud-signals.js";

interface Case {
  detector: DetectorName;
  payload: Record<string, unknown>;
  history: HistoryEvent[];
  expected: { score: number; verdict: string; factor_codes: string[] };
}
interface Fixture { generated_at: string; cases: Case[] }

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(
  here, "../../../../services/python/fraud-signals/fixtures/detector_cases.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as Fixture;
const now = new Date(fixture.generated_at);

for (const [i, c] of fixture.cases.entries()) {
  test(`parity ${i}: ${c.detector} -> ${c.expected.verdict} (${c.expected.score})`, () => {
    const r = DETECTORS[c.detector](c.payload, c.history, now);
    assert.equal(r.score, c.expected.score, "score");
    assert.equal(r.verdict, c.expected.verdict, "verdict");
    assert.deepEqual(r.factors.map((f) => f.code), c.expected.factor_codes, "factor codes");
  });
}
