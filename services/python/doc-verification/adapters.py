"""Fail-closed backend adapters for document verification.

Pattern follows services/python/identity-theft-detector/registry.py exactly:
an abstract adapter, HTTP/lazy-import variants that return
status="unavailable" with an explicit reason on ANY failure (never a
fabricated result), env-based selection, and `adapter` + `source` provenance
on every result.

Adapters:
  * PaddleOCRAdapter — lazy `from paddleocr import PaddleOCR`; ImportError ->
    available=False with reason. Real OCR when installed.
  * VLMAdapter — ollama HTTP vision model (OLLAMA_URL / OLLAMA_VISION_MODEL,
    same env conventions as services/python/kg-qa/app/compose.py). Structured
    JSON extraction per Nigerian doc type; fail-closed on any error.
  * DoclingAdapter — lazy `import docling`; PDF -> text blocks + tables.
  * OpenKYCCompatibleIDVAdapter — ORIGINAL reimplementation of the Gradio-style
    remote IDV API shape popularized by FaceOnLive/ID-Verification-OpenKYC
    (POST /gradio_api/call/<fn> then poll the event_id SSE endpoint).
    LICENSE NOTE: FaceOnLive/ID-Verification-OpenKYC ships NO LICENSE file
    (all rights reserved) and no models; NOT A SINGLE LINE of its code was
    copied here. Only the public API *shape* (endpoint layout, event_id
    polling, function names face_liveness_base64 / compare_face_base64 /
    id_liveness_base64) is reimplemented from scratch against the documented
    Gradio client protocol.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_TIMEOUT_S = float(os.getenv("OLLAMA_TIMEOUT_S", "30"))
IDV_TIMEOUT_S = float(os.getenv("IDV_TIMEOUT_S", "30"))
IDV_MAX_POLLS = int(os.getenv("IDV_MAX_POLLS", "120"))


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


class BackendAdapter:
    """Interface: report availability honestly; never fabricate a result."""

    name = "abstract"
    available = False
    unavailable_reason = "abstract adapter"

    def availability(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "available": self.available,
            "reason": None if self.available else self.unavailable_reason,
        }


# ---------------------------------------------------------------------------
# PaddleOCR
# ---------------------------------------------------------------------------

class PaddleOCRAdapter(BackendAdapter):
    """Local OCR via PaddleOCR, lazily imported.

    PADDLEOCR_ENABLED=false forces unavailable (deployment kill-switch).
    Without paddleocr installed the adapter is honestly unavailable — the
    package is an optional extra, see requirements.txt.
    """

    name = "paddleocr"

    def __init__(self, enabled: Optional[bool] = None,
                 language: str = "en"):
        if enabled is None:
            enabled = _env("PADDLEOCR_ENABLED", "true").lower() not in (
                "0", "false", "no", "off")
        self._engine = None
        if not enabled:
            self.available = False
            self.unavailable_reason = "disabled by PADDLEOCR_ENABLED"
            return
        try:
            from paddleocr import PaddleOCR  # noqa: PLC0415 (lazy optional)
        except ImportError:
            self.available = False
            self.unavailable_reason = (
                "paddleocr not installed (optional heavy extra; install "
                "paddleocr+paddlepaddle to enable local OCR)"
            )
            return
        try:
            self._engine = PaddleOCR(use_angle_cls=True, lang=language,
                                     show_log=False)
            self.available = True
        except Exception as exc:  # model download failures etc.
            self.available = False
            self.unavailable_reason = (
                f"paddleocr engine init failed ({exc.__class__.__name__})")

    def ocr(self, image_bytes: bytes) -> dict[str, Any]:
        """Run OCR; returns text lines + confidences. Fail-closed."""
        base = {"adapter": self.name, "source": "paddleocr-local"}
        if not self.available:
            return {"status": "unavailable", "reason": self.unavailable_reason,
                    **base}
        import numpy as np  # local dep, always present with cv2
        import cv2
        img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8),
                           cv2.IMREAD_COLOR)
        if img is None:
            return {"status": "unavailable",
                    "reason": "image bytes could not be decoded", **base}
        try:
            raw = self._engine.ocr(img, cls=True)
        except Exception as exc:
            logger.error("paddleocr inference failed: %s", exc)
            return {"status": "unavailable",
                    "reason": f"ocr inference failed ({exc.__class__.__name__})",
                    **base}
        lines = []
        for block in raw or []:
            for entry in block or []:
                box, (text, conf) = entry
                lines.append({"text": str(text), "confidence": round(float(conf), 4),
                              "box": [[float(x), float(y)] for x, y in box]})
        return {"status": "ok", "lines": lines, **base}


# ---------------------------------------------------------------------------
# Ollama vision-language model
# ---------------------------------------------------------------------------

class VLMAdapter(BackendAdapter):
    """Structured field extraction via an ollama vision model.

    Env (kg-qa conventions): OLLAMA_URL (unset -> unavailable),
    OLLAMA_VISION_MODEL (default llama3.2-vision), OLLAMA_TIMEOUT_S.
    Fail-closed: connection error / non-200 / invalid JSON -> unavailable
    with reason, never invented fields.
    """

    name = "ollama_vlm"

    def __init__(self, base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 timeout: float = OLLAMA_TIMEOUT_S,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = (base_url if base_url is not None
                         else _env("OLLAMA_URL")).rstrip("/")
        self.model = model or _env("OLLAMA_VISION_MODEL", "llama3.2-vision")
        self.timeout = timeout
        self._transport = transport
        if not self.base_url:
            self.available = False
            self.unavailable_reason = "OLLAMA_URL not configured"
        else:
            self.available = True

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, transport=self._transport)

    def _build_prompt(self, doc_type: str) -> str:
        import nigerian_docs
        spec = nigerian_docs.get_spec(doc_type)
        schema = nigerian_docs.extraction_schema(doc_type)
        if not spec or not schema:
            schema = {"name": "full name as printed",
                      "date_of_birth": "date of birth as printed",
                      "document_number": "document number as printed"}
            hints = "Unknown document type; extract generic identity fields."
        else:
            hints = spec["layout_hints"]
        fields = "\n".join(f'  "{k}": "{v}"' for k, v in schema.items())
        return (
            "You are an identity-document field extractor for Nigerian KYC. "
            f"Document type: {doc_type}. Layout hints: {hints}\n"
            "Transcribe ONLY what is legibly printed on the document — never "
            "guess or invent a value; use null for illegible/absent fields.\n"
            "Respond with a single JSON object, no prose, with these keys:\n"
            f"{{\n{fields}\n}}"
        )

    def extract(self, image_bytes: bytes, doc_type: str) -> dict[str, Any]:
        """Extract structured fields; validates JSON shape. Fail-closed."""
        base = {"adapter": self.name, "source": self.base_url or None}
        if not self.available:
            return {"status": "unavailable", "reason": self.unavailable_reason,
                    **base}
        payload = {
            "model": self.model,
            "prompt": self._build_prompt(doc_type),
            "images": [base64.b64encode(image_bytes).decode()],
            "stream": False,
            "format": "json",
        }
        try:
            with self._client() as client:
                resp = client.post(f"{self.base_url}/api/generate", json=payload)
        except httpx.HTTPError as exc:
            logger.error("ollama vision unreachable: %s", exc)
            return {"status": "unavailable",
                    "reason": f"ollama endpoint unreachable "
                              f"({exc.__class__.__name__})", **base}
        if resp.status_code != 200:
            return {"status": "unavailable",
                    "reason": f"ollama returned HTTP {resp.status_code}", **base}
        try:
            body = resp.json()
            text = body.get("response", "")
            fields = json.loads(text)
        except (ValueError, AttributeError):
            return {"status": "unavailable",
                    "reason": "ollama returned non-JSON extraction", **base}
        if not isinstance(fields, dict):
            return {"status": "unavailable",
                    "reason": "ollama extraction was not a JSON object", **base}
        # Drop nulls/empties — a null means the model found nothing legible.
        clean = {k: str(v).strip() for k, v in fields.items()
                 if v is not None and str(v).strip()}
        return {"status": "ok", "fields": clean, "model": self.model, **base}


# ---------------------------------------------------------------------------
# Docling (PDF layout parsing)
# ---------------------------------------------------------------------------

class DoclingAdapter(BackendAdapter):
    """PDF parsing via docling, lazily imported.

    NOTE: docling's default pipeline downloads models from HuggingFace on
    first use; in network-restricted deployments init will fail and the
    adapter reports unavailable honestly.
    """

    name = "docling"

    def __init__(self):
        self._converter = None
        try:
            from docling.document_converter import DocumentConverter  # noqa: PLC0415
        except ImportError:
            self.available = False
            self.unavailable_reason = (
                "docling not installed (optional extra; install docling to "
                "enable PDF layout parsing)")
            return
        try:
            self._converter = DocumentConverter()
            self.available = True
        except Exception as exc:
            self.available = False
            self.unavailable_reason = (
                f"docling init failed ({exc.__class__.__name__}); its models "
                "download from HuggingFace on first use and may be blocked")

    def parse_pdf(self, pdf_bytes: bytes) -> dict[str, Any]:
        """Parse a PDF into text blocks + tables. Fail-closed."""
        base = {"adapter": self.name, "source": "docling-local"}
        if not self.available:
            return {"status": "unavailable", "reason": self.unavailable_reason,
                    **base}
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tmp:
                tmp.write(pdf_bytes)
                tmp.flush()
                result = self._converter.convert(tmp.name)
            doc = result.document
            blocks = [{"text": t, "kind": "text"}
                      for t in doc.export_to_markdown().split("\n") if t.strip()]
            tables = []
            for table in getattr(doc, "tables", []) or []:
                try:
                    tables.append(table.export_to_dataframe().to_dict())
                except Exception:
                    tables.append({"raw": str(table)})
            return {"status": "ok", "blocks": blocks, "tables": tables, **base}
        except Exception as exc:
            logger.error("docling parse failed: %s", exc)
            return {"status": "unavailable",
                    "reason": f"pdf parse failed ({exc.__class__.__name__})",
                    **base}


# ---------------------------------------------------------------------------
# OpenKYC-compatible remote IDV (Gradio-style API shape)
# ---------------------------------------------------------------------------

class OpenKYCCompatibleIDVAdapter(BackendAdapter):
    """Client for a remote identity-verification server exposing the
    Gradio-style call API shape popularized by FaceOnLive/ID-Verification-
    OpenKYC.

    LICENSE NOTE: FaceOnLive/ID-Verification-OpenKYC has NO LICENSE file (all
    rights reserved) and contains no models. This is an ORIGINAL
    reimplementation — no code was copied. Only the public API *shape* is
    adopted: POST {server}/gradio_api/call/<fn> returns an event_id, then
    GET {server}/gradio_api/call/<fn>/<event_id> streams SSE lines
    ("event: complete\\ndata: [...]"). Function names mirror the public shape:
    face_liveness_base64, compare_face_base64, id_liveness_base64.

    Env: IDV_SERVER_URL (unset -> unavailable), IDV_ACCESS_TOKEN (Bearer),
    IDV_TIMEOUT_S, IDV_MAX_POLLS. Fail-closed on any transport/protocol error.
    """

    name = "openkyc_compatible_idv"

    def __init__(self, server_url: Optional[str] = None,
                 access_token: Optional[str] = None,
                 timeout: float = IDV_TIMEOUT_S,
                 max_polls: int = IDV_MAX_POLLS,
                 transport: httpx.BaseTransport | None = None):
        self.server_url = (server_url if server_url is not None
                           else _env("IDV_SERVER_URL")).rstrip("/")
        self.access_token = (access_token if access_token is not None
                             else _env("IDV_ACCESS_TOKEN"))
        self.timeout = timeout
        self.max_polls = max_polls
        self._transport = transport
        if not self.server_url:
            self.available = False
            self.unavailable_reason = "IDV_SERVER_URL not configured"
        else:
            self.available = True

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, transport=self._transport)

    def _headers(self) -> dict[str, str]:
        if self.access_token:
            return {"Authorization": f"Bearer {self.access_token}"}
        return {}

    def _unavailable(self, reason: str, fn: str) -> dict[str, Any]:
        return {"status": "unavailable", "reason": reason,
                "adapter": self.name, "source": self.server_url or None,
                "function": fn}

    def _call_fn(self, fn: str, data: list[Any]) -> dict[str, Any]:
        """POST the call, then poll the event_id SSE endpoint for completion."""
        if not self.available:
            return self._unavailable(self.unavailable_reason, fn)
        try:
            with self._client() as client:
                resp = client.post(f"{self.server_url}/gradio_api/call/{fn}",
                                   json={"data": data}, headers=self._headers())
                if resp.status_code != 200:
                    return self._unavailable(
                        f"call {fn} returned HTTP {resp.status_code}", fn)
                try:
                    event_id = resp.json()["event_id"]
                except (ValueError, KeyError):
                    return self._unavailable(
                        f"call {fn} returned no event_id", fn)
                # Poll the SSE endpoint until the 'complete' event.
                with client.stream(
                        "GET",
                        f"{self.server_url}/gradio_api/call/{fn}/{event_id}",
                        headers=self._headers()) as stream:
                    if stream.status_code != 200:
                        return self._unavailable(
                            f"event stream for {fn} returned HTTP "
                            f"{stream.status_code}", fn)
                    event = None
                    for line in stream.iter_lines():
                        if line.startswith("event:"):
                            event = line.split(":", 1)[1].strip()
                            if event == "error":
                                return self._unavailable(
                                    f"remote {fn} reported an error event", fn)
                        elif line.startswith("data:") and event == "complete":
                            payload = line.split(":", 1)[1].strip()
                            try:
                                result = json.loads(payload)
                            except ValueError:
                                return self._unavailable(
                                    f"event stream for {fn} carried non-JSON "
                                    "data", fn)
                            return {"status": "ok", "function": fn,
                                    "result": result, "adapter": self.name,
                                    "source": self.server_url}
                    return self._unavailable(
                        f"event stream for {fn} ended without completion", fn)
        except httpx.HTTPError as exc:
            logger.error("IDV server unreachable: %s", exc)
            return self._unavailable(
                f"IDV server unreachable ({exc.__class__.__name__})", fn)

    # -- public functions (OpenKYC-compatible names) --

    @staticmethod
    def _b64(image: bytes | str) -> str:
        if isinstance(image, bytes):
            return base64.b64encode(image).decode()
        return image

    def face_liveness_base64(self, image: bytes | str) -> dict[str, Any]:
        return self._call_fn("face_liveness_base64", [self._b64(image)])

    def compare_face_base64(self, image1: bytes | str,
                            image2: bytes | str) -> dict[str, Any]:
        return self._call_fn("compare_face_base64",
                             [self._b64(image1), self._b64(image2)])

    def id_liveness_base64(self, image: bytes | str) -> dict[str, Any]:
        return self._call_fn("id_liveness_base64", [self._b64(image)])


# ---------------------------------------------------------------------------
# Env-based selection (read at call time so tests can set env per-case)
# ---------------------------------------------------------------------------

def get_ocr_adapter() -> PaddleOCRAdapter:
    return PaddleOCRAdapter()


def get_vlm_adapter() -> VLMAdapter:
    return VLMAdapter()


def get_docling_adapter() -> DoclingAdapter:
    return DoclingAdapter()


def get_idv_adapter() -> OpenKYCCompatibleIDVAdapter:
    return OpenKYCCompatibleIDVAdapter()
