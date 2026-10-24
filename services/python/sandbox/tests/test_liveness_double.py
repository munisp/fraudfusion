"""Sandbox liveness doubles: signed challenge + filename-magic verdicts."""

from __future__ import annotations

import hashlib
import hmac

from fastapi.testclient import TestClient

from app.fixtures import WEBHOOK_DEMO_SECRET
from app.main import create_app

KEY = {"X-API-Key": "ffk_test_liveness"}
KEY_BYTES = hashlib.sha256(WEBHOOK_DEMO_SECRET.encode()).hexdigest().encode()


def _client():
    return TestClient(create_app())


def _issue(client) -> dict:
    resp = client.post("/api/v1/biometric/liveness/challenge", headers=KEY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["synthetic"] is True
    return body


def _sign(ch: dict) -> str:
    msg = f"{ch['challenge_id']}|{','.join(ch['phases'])}|{ch['expires_at']}"
    return hmac.new(KEY_BYTES, msg.encode(), hashlib.sha256).hexdigest()


def _submit(client, ch, filenames, signature=None):
    files = [("frames", (name, b"\x89PNG fake", "image/png"))
             for name in filenames]
    return client.post(
        "/api/v1/biometric/liveness/verify-frames",
        data={"challenge_id": ch["challenge_id"],
              "phases": ",".join(ch["phases"]),
              "expires_at": str(ch["expires_at"]),
              "signature": signature or ch["signature"]},
        files=files, headers=KEY)


def test_challenge_signature_matches_issued_value():
    ch = _issue(_client())
    assert hmac.compare_digest(_sign(ch), ch["signature"])


def test_verify_frames_round_trip_live_magic():
    client = _client()
    ch = _issue(client)
    resp = _submit(client, ch, ["frame1_live.png", "frame2.png"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["verdict"] == "live"
    assert resp.json()["synthetic"] is True


def test_verify_frames_spoof_magic_and_default_inconclusive():
    client = _client()
    ch = _issue(client)
    assert _submit(client, ch, ["spoof_screen.png"]).json()["verdict"] == "spoof"
    ch2 = _issue(client)
    assert _submit(client, ch2, ["f1.png", "f2.png"]).json()[
        "verdict"] == "inconclusive"


def test_tampered_signature_401():
    client = _client()
    ch = _issue(client)
    resp = _submit(client, ch, ["f.png"], signature="0" * 64)
    assert resp.status_code == 401


def test_expired_challenge_410():
    client = _client()
    ch = _issue(client)
    ch["expires_at"] -= 10_000
    resp = _submit(client, ch, ["f.png"], signature=_sign(ch))
    assert resp.status_code == 410
