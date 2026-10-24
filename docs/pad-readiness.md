# PAD Readiness — ISO/IEC 30107-3 Position Statement

**Status: PAD-READY, not PAD-certified.** Certification is a lab assessment
(Fime, iBeta) performed on a deployed system against physical attack
instruments — a procurement step. This document maps what exists in code to
the standard so the certification conversation starts from evidence.

## Attack-instrument taxonomy → implemented controls

| ISO 30107-3 PAI class | Example | FraudFusion control (code) | Verdict behavior |
|---|---|---|---|
| Print attack (2D photo) | Printed portrait held to camera | `liveness.py` face-region texture (colour-bucket flatness) + border/texture weakness | weak → `inconclusive` → manual review |
| Replay attack (screen) | Phone/laptop playing a video | Per-frame FFT moire peakiness (screen refresh grid) + cross-frame moire variance; calibrated 54–69 attack vs ~12 genuine | hard signal → `spoof` |
| Static/loop attack | Frozen frame or looped clip | Inter-frame motion analysis; duplicated/static sequences cannot pass a fresh challenge | challenge mismatch → `spoof`; passive static → `inconclusive` |
| Challenge evasion | Pre-recorded generic motion | Stateless HMAC-signed random phase sequence (120s TTL); observed per-phase motion must match | mismatch → `spoof` |
| 3D mask / deepfake | — | **Out of scope honestly declared** — requires trained models; routes to remote OpenKYC-compatible IDV when configured, else manual review | — |

## What the conformance suite proves today

`services/python/doc-verification/tests/test_liveness.py` generates synthetic
attack classes and asserts correct classification: genuine-with-challenge →
`live`; moire replay (4 grid periods) → `spoof`; duplicated/static → not
live; challenge-evasion → `spoof`; flat-render print → `inconclusive`;
garbage → honest `inconclusive`, never raises. 13/13 green, plus 8
endpoint-level integration tests (signed challenge issuance, tamper 401,
expiry 410, hash-only audit, cap enforcement).

## Gap to certification (honest)

1. Synthetic fixtures ≠ physical attack instruments; thresholds are
   synthetic-calibrated and must be re-baselined on real captures.
2. No trained PAD model (no ML dependencies in the local layer); face region
   is a center-crop heuristic, not a detector.
3. Lab assessment requires a frozen release + device matrix + attack
   materials — schedule after the first design-partner deployment.
4. Recommended pathway: deploy local liveness + remote IDV hybrid → collect
   real attack telemetry (hash-only) → engage Fime/iBeta for Level 1, then
   Level 2 PAD assessment.
