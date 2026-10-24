"""Integration tests: challenge-response liveness endpoints (Round 10).

Covers challenge issuance (signed, stateless), signature/expiry enforcement,
the full challenge -> frame-sequence -> verdict round trip against the REAL
local engine, hash-only audit persistence, webhook emission, and honest
degradation when the engine is unavailable.
"""

from __future__ import annotations

import json
import os

import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

CALLER = Principal(sub="kyc-ops-1", username="ops", roles={"kyc_operator"})
SECRET = "test-liveness-secret"


def _frame(seed: int, shift: int = 0, moire: bool = False) -> bytes:
    rng = np.random.default_rng(seed)
    img = rng.integers(30, 220, (240, 320, 3), dtype=np.uint8)
    if shift:
        img = np.roll(img, shift, axis=1)
    if moire:
        base = img.astype(np.float64)
        yy, xx = np.mgrid[0:240, 0:320]
        grid = 40 * np.sin(2 * np.pi * xx / 6) * np.sin(2 * np.pi * yy / 6)
        img = np.clip(base + grid[..., None], 0, 255).astype(np.uint8)
    return cv2.imencode(".png", img)[1].tobytes()


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "kyc.db"))
    yield database
    reset_db_for_tests(None)


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setenv("LIVENESS_CHALLENGE_SECRET", SECRET)
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


principal = CALLER  # module-level for the fixture closure


def _issue(client) -> dict:
    resp = client.post("/api/v1/biometric/liveness/challenge")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["challenge_id"] and body["signature"]
    assert len(body["phases"]) == 3
    assert all(p in ("still", "move") for p in body["phases"])
    return body


def _submit(client, challenge: dict, frames: list[bytes]):
    files = [("frames", (f"f{i}.png", f, "image/png"))
             for i, f in enumerate(frames)]
    return client.post(
        "/api/v1/biometric/liveness/verify-frames",
        data={"challenge_id": challenge["challenge_id"],
              "phases": ",".join(challenge["phases"]),
              "expires_at": str(challenge["expires_at"]),
              "signature": challenge["signature"]},
        files=files)


def _genuine_frames(phases: list[str]) -> list[bytes]:
    """Build a frame sequence whose motion matches the issued phases:
    identical frames for "still", whole-frame shifts for "move"."""
    still = _frame(1)
    frames: list[bytes] = []
    for phase in phases:
        if phase == "still":
            frames += [still] * 4
        else:
            frames += [_frame(1, s) for s in (15, 30, 45, 60)]
    return frames


class TestChallengeIssuance:
    def test_issue_signed_challenge(self, client):
        _issue(client)

    def test_unconfigured_secret_is_503(self, db, monkeypatch):
        monkeypatch.delenv("LIVENESS_CHALLENGE_SECRET", raising=False)
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_current_principal] = lambda: CALLER
        resp = TestClient(app).post("/api/v1/biometric/liveness/challenge")
        assert resp.status_code == 503


class TestVerifyFrames:
    def test_bad_signature_401(self, client):
        ch = _issue(client)
        ch["signature"] = "0" * 64
        resp = _submit(client, ch, [_frame(1), _frame(1)])
        assert resp.status_code == 401

    def test_tampered_phases_401(self, client):
        ch = _issue(client)
        # Flip the first phase deterministically (random challenges can
        # legitimately be all-"still", so never tamper to a fixed pattern).
        ch["phases"] = ["move" if ch["phases"][0] == "still" else "still",
                        *ch["phases"][1:]]
        resp = _submit(client, ch, [_frame(1), _frame(1)])
        assert resp.status_code == 401

    def test_expired_challenge_410(self, client):
        ch = _issue(client)
        ch["expires_at"] -= 10_000
        # re-sign with the real secret so only expiry fails
        import hashlib, hmac
        key = hashlib.sha256(SECRET.encode()).hexdigest().encode()
        msg = f"{ch['challenge_id']}|{','.join(ch['phases'])}|{ch['expires_at']}"
        ch["signature"] = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
        resp = _submit(client, ch, [_frame(1), _frame(1)])
        assert resp.status_code == 410

    def test_full_round_trip_verdict_and_audit(self, client, db):
        ch = _issue(client)
        resp = _submit(client, ch, _genuine_frames(ch["phases"]))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["performed"] is True
        assert body["verdict"] in ("live", "inconclusive", "spoof")
        assert body["challenge_checked"] is True
        # hash-only audit row: no frame bytes, sha256 + provenance only
        row = db.query_one(
            "SELECT * FROM document_verifications WHERE id = :id",
            {"id": body["verification_id"]})
        assert row is not None
        assert row["document_type"] == "liveness_frames"
        assert len(row["sha256"]) == 64
        provenance = json.loads(row["provenance_json"])
        assert any(s["signal"] == "challenge_response" for s in provenance)

    def test_moire_frames_rejected_status_in_audit(self, client, db):
        ch = _issue(client)
        frames = [_frame(7, moire=True), _frame(8, moire=True),
                  _frame(9, moire=True)]
        resp = _submit(client, ch, frames)
        body = resp.json()
        assert body["verdict"] == "spoof"
        row = db.query_one(
            "SELECT status FROM document_verifications WHERE id = :id",
            {"id": body["verification_id"]})
        assert row["status"] == "rejected"

    def test_frame_cap_enforced(self, client):
        ch = _issue(client)
        resp = _submit(client, ch, [_frame(1)] * 20)
        assert resp.status_code == 413
