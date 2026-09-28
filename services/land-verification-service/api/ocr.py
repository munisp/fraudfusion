"""OCR adapter interface for the land-verification-service.

Adapters (selected by `get_ocr_adapter`):
  * HttpOcrAdapter   — when OCR_SERVICE_URL is configured; POSTs the document
                       to the OCR service. Fail-closed on any error.
  * TesseractAdapter — when the `tesseract` binary is on PATH; runs it on the
                       uploaded image and parses TSV confidence output.

When neither is available, `get_ocr_adapter()` returns None and callers must
report `ocr: unavailable` honestly — extracted text is NEVER fabricated.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

OCR_SERVICE_URL = os.getenv("OCR_SERVICE_URL", "").strip()
OCR_TIMEOUT = float(os.getenv("OCR_TIMEOUT_SECONDS", "30"))
TESSERACT_BIN = os.getenv("TESSERACT_BIN", "tesseract")


class OcrResult(dict):
    """{'status': 'ok'|'unavailable', 'text': str, 'confidence': float|None,
    'engine': str, 'reason': str|None}"""


class OcrAdapter:
    name = "abstract"

    def extract_text(self, data: bytes, content_type: str | None = None) -> OcrResult:
        raise NotImplementedError


class TesseractAdapter(OcrAdapter):
    """Local OCR via the tesseract binary (image bytes -> text + mean conf)."""

    name = "tesseract"

    def __init__(self, binary: str | None = None):
        self.binary = binary or shutil.which(TESSERACT_BIN)
        if not self.binary:
            raise RuntimeError("tesseract binary not found on PATH")

    @classmethod
    def available(cls) -> bool:
        return shutil.which(TESSERACT_BIN) is not None

    def extract_text(self, data: bytes, content_type: str | None = None) -> OcrResult:
        suffix = ".png" if (content_type or "").endswith("png") else ".img"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            proc = subprocess.run(
                [self.binary, tmp_path, "stdout", "tsv"],
                capture_output=True, timeout=OCR_TIMEOUT, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.error("tesseract failed: %s", exc)
            return OcrResult(status="unavailable", text="", confidence=None,
                             engine=self.name, reason=f"tesseract error: {exc.__class__.__name__}")
        finally:
            os.unlink(tmp_path)
        if proc.returncode != 0:
            return OcrResult(status="unavailable", text="", confidence=None, engine=self.name,
                             reason=f"tesseract exited {proc.returncode}: "
                                    f"{proc.stderr.decode(errors='replace')[:200]}")
        text_words: list[str] = []
        confidences: list[float] = []
        for line in proc.stdout.decode("utf-8", errors="replace").splitlines()[1:]:
            cols = line.split("\t")
            if len(cols) >= 12 and cols[11].strip():
                text_words.append(cols[11].strip())
                try:
                    conf = float(cols[10])
                    if conf >= 0:
                        confidences.append(conf)
                except ValueError:
                    pass
        mean_conf = round(sum(confidences) / len(confidences) / 100.0, 3) if confidences else None
        return OcrResult(status="ok", text=" ".join(text_words), confidence=mean_conf,
                         engine=self.name, reason=None)


class HttpOcrAdapter(OcrAdapter):
    """Remote OCR service (OCR_SERVICE_URL). Fails closed."""

    name = "http-ocr-service"

    def __init__(self, base_url: str | None = None, timeout: float = OCR_TIMEOUT,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = (base_url or OCR_SERVICE_URL).rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def extract_text(self, data: bytes, content_type: str | None = None) -> OcrResult:
        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
                resp = client.post(
                    f"{self.base_url}/extract",
                    files={"document": ("document", data, content_type or "application/octet-stream")},
                )
        except httpx.HTTPError as exc:
            logger.error("OCR service unreachable: %s", exc)
            return OcrResult(status="unavailable", text="", confidence=None,
                             engine=self.name, reason=f"OCR service unreachable ({exc.__class__.__name__})")
        if resp.status_code != 200:
            return OcrResult(status="unavailable", text="", confidence=None, engine=self.name,
                             reason=f"OCR service returned HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError:
            return OcrResult(status="unavailable", text="", confidence=None,
                             engine=self.name, reason="OCR service returned non-JSON body")
        return OcrResult(status="ok", text=body.get("text", ""),
                         confidence=body.get("confidence"), engine=self.name, reason=None)


def get_ocr_adapter() -> Optional[OcrAdapter]:
    """Adapter selection; None means OCR is honestly unavailable."""
    if OCR_SERVICE_URL:
        return HttpOcrAdapter()
    if TesseractAdapter.available():
        try:
            return TesseractAdapter()
        except RuntimeError:
            return None
    return None


def ocr_health() -> dict[str, Any]:
    """Honest OCR capability report for /health."""
    if OCR_SERVICE_URL:
        return {"backend": "http", "url": OCR_SERVICE_URL}
    if TesseractAdapter.available():
        return {"backend": "tesseract", "binary": shutil.which(TESSERACT_BIN)}
    return {"backend": "unavailable", "detail": "ocr: unavailable (no OCR_SERVICE_URL, no tesseract binary)"}
