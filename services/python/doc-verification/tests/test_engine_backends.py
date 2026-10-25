"""Round 16 tests: OCR/VLM/docling backend integration factors.

  * VLMAdapter defaults to qwen2.5vl:7b; inspect() parses template anomalies
  * ocr_forensics confidence-outlier detection (patched-line suspects)
  * engine end-to-end with injected backends: OCR-confidence and VLM-anomaly
    factors land in the composite score; unavailable backends degrade honestly

Run: python3 -m pytest tests/test_engine_backends.py -q
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import cv2
import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import adapters  # noqa: E402
import ocr_forensics  # noqa: E402
import pipeline  # noqa: E402
from doc_intelligence import (DocIntelStore, IntelligenceInput, create_app,  # noqa: E402
                              reset_store_for_tests, run_intelligence)


def _img(seed: int = 5) -> bytes:
    rng = np.random.default_rng(seed)
    img = rng.normal(225, 6, (384, 512, 3)).clip(0, 255).astype(np.uint8)
    y = 40
    while y < 320:
        cv2.rectangle(img, (40, y), (40 + int(rng.integers(200, 420)), y + 14),
                      (40, 40, 40), -1)
        y += int(rng.integers(28, 55))
    ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    return enc.tobytes()


class TestVLMAdapter:
    def test_default_model_is_qwen(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_VISION_MODEL", raising=False)
        monkeypatch.setenv("OLLAMA_URL", "http://ollama:11434")
        assert adapters.VLMAdapter().model == "qwen2.5vl:7b"

    def test_inspect_parses_anomalies(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_URL", "http://ollama:11434")

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            assert payload["format"] == "json"
            return httpx.Response(200, json={
                "response": json.dumps({
                    "anomalies": ["signature panel on wrong page for a deed",
                                  "guilloche pattern absent"],
                    "template_match": False})})

        adapter = adapters.VLMAdapter(transport=httpx.MockTransport(handler))
        result = adapter.inspect(_img(), "deed_of_assignment")
        assert result["status"] == "ok"
        assert result["template_match"] is False
        assert len(result["anomalies"]) == 2

    def test_inspect_fail_closed(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_URL", "http://ollama:11434")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        adapter = adapters.VLMAdapter(transport=httpx.MockTransport(handler))
        assert adapter.inspect(_img(), "nin_slip")["status"] == "unavailable"


class TestOCRForensics:
    def _lines(self, patched: bool) -> list[dict]:
        lines = [{"text": f"printed line {i}", "confidence": 0.93}
                 for i in range(8)]
        if patched:
            lines[4] = {"text": "CHIEF FORGED NAME", "confidence": 0.41}
        return lines

    def test_patched_line_flagged(self):
        result = ocr_forensics.confidence_inconsistency(self._lines(True))
        assert result["suspected"] is True
        assert result["outliers"][0]["text"] == "CHIEF FORGED NAME"
        assert result["median_confidence"] == 0.93

    def test_uniform_document_clean(self):
        assert ocr_forensics.confidence_inconsistency(
            self._lines(False))["suspected"] is False

    def test_low_quality_document_no_regional_claim(self):
        lines = [{"text": f"blurry {i}", "confidence": 0.5} for i in range(6)]
        result = ocr_forensics.confidence_inconsistency(lines)
        assert result["suspected"] is False
        assert "capture quality" in result["detail"]

    def test_too_few_lines_skips(self):
        assert ocr_forensics.confidence_inconsistency(
            [{"text": "only", "confidence": 0.9}])["suspected"] is False


# --- engine end-to-end with injected backends ---------------------------------

class _StubOCR:
    name = "stub_ocr"
    unavailable_reason = "stub"

    def __init__(self, lines):
        self._lines = lines

    def availability(self):
        return {"available": bool(self._lines), "reason": None}

    def ocr(self, image_bytes):
        return {"status": "ok", "lines": self._lines}


class _StubVLM:
    name = "stub_vlm"
    unavailable_reason = "stub"

    def __init__(self, fields=None, anomalies=None):
        self._fields = fields or {}
        self._anomalies = anomalies

    def availability(self):
        return {"available": True, "reason": None}

    def extract(self, image_bytes, doc_type):
        return {"status": "ok", "fields": self._fields, "model": "stub"}

    def inspect(self, image_bytes, doc_type):
        if self._anomalies is None:
            return {"status": "unavailable", "reason": "inspect unsupported"}
        return {"status": "ok", "anomalies": self._anomalies,
                "template_match": not self._anomalies, "model": "stub"}


class _NoDocling:
    name = "no_docling"
    unavailable_reason = "docling not installed"

    def availability(self):
        return {"available": False, "reason": self.unavailable_reason}


@pytest.fixture()
def store(tmp_path):
    s = DocIntelStore(database_url="", sqlite_path=str(tmp_path / "di.db"))
    reset_store_for_tests(s)
    yield s
    reset_store_for_tests(None)


def _backends(ocr_lines=None, vlm=None):
    return pipeline.Backends(ocr=_StubOCR(ocr_lines or []),
                             vlm=vlm or _StubVLM(), docling=_NoDocling())


class TestEngineBackendFactors:
    def test_ocr_confidence_factor_reaches_score(self, store):
        lines = [{"text": f"line {i}", "confidence": 0.93} for i in range(8)]
        lines[3] = {"text": "PATCHED SURNAME", "confidence": 0.40}
        payload = IntelligenceInput(
            image_base64=base64.b64encode(_img()).decode(), doc_type="nin_slip")
        result = run_intelligence(store, payload, _backends(ocr_lines=lines))
        assert "ocr_confidence_outlier" in {f["code"] for f in result["factors"]}
        layers = {p["layer"]: p["status"] for p in result["provenance"]}
        assert layers["ocr_forensics"] == "ran"

    def test_vlm_template_anomaly_factor(self, store):
        vlm = _StubVLM(anomalies=["font family inconsistent with NIMC 2024 slips"])
        payload = IntelligenceInput(
            image_base64=base64.b64encode(_img()).decode(), doc_type="nin_slip")
        result = run_intelligence(store, payload, _backends(vlm=vlm))
        assert "vlm_template_anomaly" in {f["code"] for f in result["factors"]}
        layers = {p["layer"]: p["status"] for p in result["provenance"]}
        assert layers["vlm_inspect"] == "ran"

    def test_unavailable_backends_degrade_honestly(self, store):
        vlm = _StubVLM(anomalies=None)  # inspect unsupported
        payload = IntelligenceInput(
            image_base64=base64.b64encode(_img()).decode(), doc_type="nin_slip")
        result = run_intelligence(store, payload, _backends(vlm=vlm))
        codes = {f["code"] for f in result["factors"]}
        assert "vlm_template_anomaly" not in codes
        assert "ocr_confidence_outlier" not in codes
        layers = {p["layer"]: p["status"] for p in result["provenance"]}
        assert layers["vlm_inspect"] == "unavailable"
        # Nothing fabricated: unavailable layers contribute zero factors.
        assert all(f["code"] not in ("vlm_template_anomaly",)
                   for f in result["factors"])

    def test_api_still_green_with_default_backends(self, store):
        client = TestClient(create_app())
        r = client.post("/api/v1/documents/intelligence",
                        json={"image_base64": base64.b64encode(_img()).decode(),
                              "doc_type": "c_of_o"})
        assert r.status_code == 200
        layers = {p["layer"] for p in r.json()["provenance"]}
        assert "ocr_forensics" in layers and "vlm_inspect" in layers
