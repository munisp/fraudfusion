"""Adapter tests: honest unavailability and fail-closed HTTP behaviour.

paddleocr/docling are NOT installed in this environment, so those adapters
must report available=False with an explicit reason (and if a deployment
DOES install them, the real-implementation tests exercise the happy path).
HTTP adapters are tested with httpx.MockTransport — fail-closed on
connection error, non-200, malformed payloads — plus a full happy-path
SSE round-trip for the OpenKYC-compatible adapter.

Run: python3 -m pytest tests/ -q   (from services/python/doc-verification)
"""

from __future__ import annotations

import json

import httpx
import pytest

import adapters
from conftest import to_png


class TestPaddleOCRAdapter:
    def test_unavailable_when_disabled_by_env(self, monkeypatch):
        monkeypatch.setenv("PADDLEOCR_ENABLED", "false")
        adapter = adapters.PaddleOCRAdapter()
        assert adapter.available is False
        assert "PADDLEOCR_ENABLED" in adapter.unavailable_reason

    def test_unavailable_or_real(self, monkeypatch, clean_card):
        monkeypatch.delenv("PADDLEOCR_ENABLED", raising=False)
        adapter = adapters.PaddleOCRAdapter()
        result = adapter.ocr(to_png(clean_card))
        if adapter.available:
            # Real install: OCR genuinely ran and returned lines.
            assert result["status"] == "ok"
            assert isinstance(result["lines"], list)
        else:
            assert result["status"] == "unavailable"
            assert "paddleocr" in result["reason"]
        assert result["adapter"] == "paddleocr"


class TestDoclingAdapter:
    def test_unavailable_or_real(self):
        adapter = adapters.DoclingAdapter()
        result = adapter.parse_pdf(b"%PDF-1.4 fake\n%%EOF\n")
        if adapter.available:
            assert result["status"] == "ok"
            assert "blocks" in result
        else:
            assert result["status"] == "unavailable"
            assert "docling" in result["reason"]
        assert result["adapter"] == "docling"


class TestVLMAdapter:
    def test_unavailable_when_url_unset(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_URL", raising=False)
        adapter = adapters.VLMAdapter(base_url="")
        assert adapter.available is False
        assert "OLLAMA_URL" in adapter.unavailable_reason
        result = adapter.extract(b"img", "nin_slip")
        assert result["status"] == "unavailable"

    def test_fail_closed_on_connection_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        adapter = adapters.VLMAdapter(
            base_url="http://ollama:11434",
            transport=httpx.MockTransport(handler))
        result = adapter.extract(b"img", "nin_slip")
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]
        assert result["adapter"] == "ollama_vlm"

    def test_fail_closed_on_non_200(self):
        adapter = adapters.VLMAdapter(
            base_url="http://ollama:11434",
            transport=httpx.MockTransport(
                lambda req: httpx.Response(500, text="boom")))
        result = adapter.extract(b"img", "nin_slip")
        assert result["status"] == "unavailable"
        assert "HTTP 500" in result["reason"]

    def test_fail_closed_on_non_json_extraction(self):
        adapter = adapters.VLMAdapter(
            base_url="http://ollama:11434",
            transport=httpx.MockTransport(lambda req: httpx.Response(
                200, json={"response": "sorry, I cannot read this"})))
        result = adapter.extract(b"img", "nin_slip")
        assert result["status"] == "unavailable"
        assert "non-JSON" in result["reason"]

    def test_happy_path_extracts_and_cleans_fields(self):
        fields = {"name": "ADAEZE EZE", "nin": "12345678901",
                  "date_of_birth": "20/05/1990", "gender": None, "phone": "  "}

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            assert body["model"]
            assert body["images"] and body["format"] == "json"
            assert "nin_slip" in body["prompt"]
            return httpx.Response(200, json={"response": json.dumps(fields)})

        adapter = adapters.VLMAdapter(
            base_url="http://ollama:11434",
            transport=httpx.MockTransport(handler))
        result = adapter.extract(b"img", "nin_slip")
        assert result["status"] == "ok"
        # nulls and blank strings are dropped — they mean "nothing legible"
        assert result["fields"] == {"name": "ADAEZE EZE", "nin": "12345678901",
                                    "date_of_birth": "20/05/1990"}
        assert result["source"] == "http://ollama:11434"


class TestOpenKYCCompatibleIDVAdapter:
    def test_unavailable_when_url_unset(self):
        adapter = adapters.OpenKYCCompatibleIDVAdapter(server_url="")
        assert adapter.available is False
        assert "IDV_SERVER_URL" in adapter.unavailable_reason
        result = adapter.face_liveness_base64(b"img")
        assert result["status"] == "unavailable"

    def test_fail_closed_on_connection_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        adapter = adapters.OpenKYCCompatibleIDVAdapter(
            server_url="http://idv:7860",
            transport=httpx.MockTransport(handler))
        result = adapter.compare_face_base64(b"a", b"b")
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]
        assert result["function"] == "compare_face_base64"

    def test_fail_closed_on_call_non_200(self):
        adapter = adapters.OpenKYCCompatibleIDVAdapter(
            server_url="http://idv:7860",
            transport=httpx.MockTransport(
                lambda req: httpx.Response(503, text="down")))
        result = adapter.face_liveness_base64(b"img")
        assert result["status"] == "unavailable"
        assert "HTTP 503" in result["reason"]

    def test_fail_closed_on_missing_event_id(self):
        adapter = adapters.OpenKYCCompatibleIDVAdapter(
            server_url="http://idv:7860",
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, json={"unexpected": True})))
        result = adapter.face_liveness_base64(b"img")
        assert result["status"] == "unavailable"
        assert "event_id" in result["reason"]

    def test_fail_closed_on_error_event(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/face_liveness_base64"):
                return httpx.Response(200, json={"event_id": "ev-1"})
            return httpx.Response(
                200, text="event: error\ndata: null\n\n",
                headers={"content-type": "text/event-stream"})

        adapter = adapters.OpenKYCCompatibleIDVAdapter(
            server_url="http://idv:7860",
            transport=httpx.MockTransport(handler))
        result = adapter.face_liveness_base64(b"img")
        assert result["status"] == "unavailable"
        assert "error event" in result["reason"]

    def test_happy_path_sse_round_trip(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                seen["auth"] = request.headers.get("authorization")
                seen["path"] = request.url.path
                seen["body"] = json.loads(request.content)
                return httpx.Response(200, json={"event_id": "ev-42"})
            assert request.url.path.endswith("/compare_face_base64/ev-42")
            return httpx.Response(
                200,
                text="event: generating\ndata: [null]\n\n"
                     "event: complete\ndata: [{\"match\": true, "
                     "\"similarity\": 0.93}]\n\n",
                headers={"content-type": "text/event-stream"})

        adapter = adapters.OpenKYCCompatibleIDVAdapter(
            server_url="http://idv:7860", access_token="secret",
            transport=httpx.MockTransport(handler))
        result = adapter.compare_face_base64(b"img-one", b"img-two")
        assert result["status"] == "ok"
        assert result["result"] == [{"match": True, "similarity": 0.93}]
        assert result["adapter"] == "openkyc_compatible_idv"
        assert seen["path"].endswith("/gradio_api/call/compare_face_base64")
        assert seen["auth"] == "Bearer secret"
        # both images were sent base64-encoded in the data array
        assert len(seen["body"]["data"]) == 2

    def test_env_based_selection(self, monkeypatch):
        monkeypatch.delenv("IDV_SERVER_URL", raising=False)
        assert adapters.get_idv_adapter().available is False
        monkeypatch.setenv("IDV_SERVER_URL", "http://idv:7860")
        assert adapters.get_idv_adapter().available is True
