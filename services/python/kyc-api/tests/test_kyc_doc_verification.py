"""Integration tests: kyc-api wired to the doc-verification engine.

Covers the REAL behavior now behind /document/* and /biometric/*:
  * quality-check returns cv2 blur/glare/resolution scores for images
  * verify runs the layered pipeline with per-layer provenance and persists a
    hash-only audit row (document_verifications)
  * forgery-check returns real integrity scores for images
  * ocr stays honestly unavailable when no OCR backend is configured
  * biometric endpoints really call the OpenKYC-compatible IDV server when
    IDV_SERVER_URL is configured (MockTransport), and stay honestly
    not-performed otherwise

Run: python3 -m pytest tests/ -q   (from services/python/kyc-api)
"""

from __future__ import annotations

import json

import cv2
import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import docverification
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

CALLER = Principal(sub="kyc-ops-1", username="ops", roles={"kyc_operator"})


def make_png(kind: str = "clean") -> bytes:
    """Synthetic document captures (same recipe as doc-verification tests)."""
    if kind == "flat":
        img = np.full((480, 720, 3), 255, np.uint8)
        cv2.putText(img, "NIN: 12345678901", (70, 200),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 0), 2)
    else:
        img = np.full((480, 720, 3), (60, 70, 80), np.uint8)
        cv2.rectangle(img, (40, 40), (680, 440), (230, 228, 220), -1)
        cv2.rectangle(img, (40, 40), (680, 440), (40, 40, 40), 3)
        for i, t in enumerate(["FEDERAL REPUBLIC OF NIGERIA",
                               "Name: ADAEZE EZE", "NIN: 12345678901"]):
            cv2.putText(img, t, (70, 110 + i * 60), cv2.FONT_HERSHEY_SIMPLEX,
                        0.8, (20, 20, 20), 2)
        rng = np.random.default_rng(7)
        img = np.clip(img.astype(np.int16) + rng.normal(0, 6, img.shape),
                      0, 255).astype(np.uint8)
        if kind == "moire":
            yy, xx = np.mgrid[0:480, 0:720]
            grid = 12 * (np.sin(2 * np.pi * xx / 5.0)
                         * np.sin(2 * np.pi * yy / 6.0))
            img = np.clip(img.astype(np.float64) + grid[:, :, None],
                          0, 255).astype(np.uint8)
    return cv2.imencode(".png", img)[1].tobytes()


CLEAN_PNG = make_png("clean")
MOIRE_PNG = make_png("moire")


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "kyc.db"))
    yield database
    reset_db_for_tests(None)


def make_client(db, principal=CALLER):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


class TestQualityCheckReal:
    def test_clean_capture_scores_good_with_real_scores(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/document/quality-check",
                           files={"document": ("id.png", CLEAN_PNG, "image/png")})
        body = resp.json()
        assert body["quality"] == "good"
        assert body["analysis_layer"] == "local_cv"
        assert body["quality_scores"]["blur"] > 150
        assert body["screen_replay_integrity"] == 1.0

    def test_moire_capture_flagged(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/document/quality-check",
                           files={"document": ("id.png", MOIRE_PNG, "image/png")})
        body = resp.json()
        assert body["screen_replay_integrity"] < 0.35
        assert any("moire" in i or "screen" in i for i in body["issues"])

    def test_garbage_stays_poor(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/quality-check",
            files={"document": ("id.bin", b"\x00\xffgarbage",
                                "application/octet-stream")})
        assert resp.json()["quality"] == "poor"


class TestDocumentVerifyPipeline:
    def test_image_runs_pipeline_with_provenance(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/verify",
            files={"document": ("id.png", CLEAN_PNG, "image/png")},
            data={"document_type": "nin_slip", "check_forgery": "true"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "manual_review"  # no OCR/VLM configured here
        verdict = body["pipeline"]
        assert verdict["document_type_canonical"] == "nin_slip"
        by_layer = {p["layer"]: p["status"] for p in verdict["provenance"]}
        assert by_layer["local_cv"] == "ran"
        assert by_layer["ocr"] == "unavailable"
        assert by_layer["vlm"] == "unavailable"
        assert verdict["extracted_fields"] == {}  # nothing fabricated
        assert verdict["authenticity"]["screen_replay_integrity"] == 1.0

    def test_moire_image_rejected(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/verify",
            files={"document": ("id.png", MOIRE_PNG, "image/png")},
            data={"document_type": "drivers_license", "check_forgery": "true"},
        )
        body = resp.json()
        assert body["status"] == "rejected"
        assert body["pipeline"]["authenticity"]["screen_replay_integrity"] < 0.35

    def test_verdict_persisted_hash_only(self, db):
        import hashlib
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/verify",
            files={"document": ("id.png", CLEAN_PNG, "image/png")},
            data={"document_type": "nin_slip", "check_forgery": "true"},
        )
        vid = resp.json()["verification_id"]
        row = db.query_one(
            "SELECT * FROM document_verifications WHERE id = :id", {"id": vid})
        assert row is not None
        assert row["sha256"] == hashlib.sha256(CLEAN_PNG).hexdigest()
        assert row["status"] == "manual_review"
        provenance = json.loads(row["provenance_json"])
        assert {p["layer"] for p in provenance} == {"local_cv", "ocr", "vlm"}


class TestForgeryCheckReal:
    def test_image_gets_real_integrity_score(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/forgery-check",
            files={"document": ("id.png", CLEAN_PNG, "image/png")},
            data={"document_type": "national_id"},
        )
        body = resp.json()
        assert body["performed"] is True
        assert body["confidence"] == 1.0  # screen-replay integrity
        assert body["forgery_detected"] is False
        assert body["cv_analysis"]["quality"] == "good"

    def test_moire_image_detected(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/forgery-check",
            files={"document": ("id.png", MOIRE_PNG, "image/png")},
            data={"document_type": "national_id"},
        )
        body = resp.json()
        assert body["forgery_detected"] is True
        assert body["confidence"] < 0.35


class TestOcrHonest:
    def test_image_ocr_unavailable_with_per_backend_reasons(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/ocr",
            files={"document": ("id.png", CLEAN_PNG, "image/png")},
            data={"document_type": "nin_slip"},
        )
        body = resp.json()
        assert body["status"] == "unavailable"
        assert body["extracted_fields"] == {}
        assert "ocr:" in body["reason"] and "vlm:" in body["reason"]


class _MockIDV:
    """OpenKYC-compatible adapter backed by httpx.MockTransport."""

    def __init__(self, handler):
        from adapters import OpenKYCCompatibleIDVAdapter
        self._adapter = OpenKYCCompatibleIDVAdapter(
            server_url="http://idv-test:7860", access_token="t",
            transport=httpx.MockTransport(handler))

    @property
    def available(self):
        return True

    def __getattr__(self, name):
        return getattr(self._adapter, name)


def _idv_handler(request: httpx.Request) -> httpx.Response:
    # POST /gradio_api/call/<fn>; GET /gradio_api/call/<fn>/<event_id>
    if request.method == "POST":
        return httpx.Response(200, json={"event_id": "ev-1"})
    fn = request.url.path.rstrip("/").split("/")[-2]
    if fn == "face_liveness_base64":
        payload = [{"is_live": True, "liveness_score": 0.97}]
    else:
        payload = [{"match": True, "similarity": 0.91}]
    return httpx.Response(
        200, text=f"event: complete\ndata: {json.dumps(payload)}\n\n",
        headers={"content-type": "text/event-stream"})


@pytest.fixture()
def idv_server(monkeypatch):
    monkeypatch.setattr(docverification, "get_idv_adapter",
                        lambda: _MockIDV(_idv_handler))
    yield


class TestBiometricWithIDV:
    def test_face_match_performed_when_idv_configured(self, db, idv_server):
        client = make_client(db)
        resp = client.post(
            "/api/v1/biometric/face-match",
            files={"image1": ("a.png", CLEAN_PNG, "image/png"),
                   "image2": ("b.png", CLEAN_PNG, "image/png")})
        body = resp.json()
        assert body["performed"] is True
        assert body["match"] is True
        assert body["score"] == 0.91
        assert body["adapter"] == "openkyc_compatible_idv"

    def test_liveness_performed_when_idv_configured(self, db, idv_server):
        client = make_client(db)
        resp = client.post("/api/v1/biometric/liveness",
                           files={"image": ("s.png", CLEAN_PNG, "image/png")})
        body = resp.json()
        assert body["performed"] is True
        assert body["result"] == "live"
        assert body["score"] == 0.97

    def test_combined_verify_uses_idv(self, db, idv_server):
        import base64
        client = make_client(db)
        resp = client.post("/api/v1/biometric/verify", json={
            "selfie_image_base64": base64.b64encode(CLEAN_PNG).decode(),
            "reference_image_base64": base64.b64encode(CLEAN_PNG).decode(),
            "check_liveness": True,
        })
        body = resp.json()
        assert body["status"] == "verified"
        assert body["liveness"]["result"] == "live"
        assert body["face_match"]["match"] is True

    def test_idv_failure_fails_closed(self, db, monkeypatch):
        def broken(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        monkeypatch.setattr(docverification, "get_idv_adapter",
                            lambda: _MockIDV(broken))
        client = make_client(db)
        resp = client.post("/api/v1/biometric/liveness",
                           files={"image": ("s.png", CLEAN_PNG, "image/png")})
        body = resp.json()
        assert body["performed"] is False
        assert body["result"] == "not_evaluated"
        assert "unreachable" in body["reason"]
