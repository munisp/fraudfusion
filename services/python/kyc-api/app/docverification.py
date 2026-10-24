"""Bootstrap for the shared doc-verification engine.

kyc-api has no build-time dependency on the shared package: the
services/python/doc-verification directory is appended to sys.path here, from
DOCVERIFICATION_PATH when set, otherwise the repo-relative default
(services/python/doc-verification). If the package or its core deps
(cv2/numpy) are absent, DOCVERIFICATION_AVAILABLE is False and every document
/ biometric endpoint falls back to the honest "not performed / unavailable"
responses — nothing is fabricated either way.

Exposes the pieces app/main.py uses:
  local_cv, pipeline, adapters modules and build_backends(), plus the
  Round-14 document intelligence engine (doc_intelligence) via run_engine().
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "doc-verification"
_path = os.environ.get("DOCVERIFICATION_PATH", str(_DEFAULT_PATH)).strip()

try:
    if _path and os.path.isdir(_path) and _path not in sys.path:
        sys.path.append(_path)
    import adapters as _adapters  # noqa: E402
    import liveness as _liveness  # noqa: E402
    import local_cv as _local_cv  # noqa: E402
    import pipeline as _pipeline  # noqa: E402

    local_cv = _local_cv
    pipeline = _pipeline
    adapters = _adapters
    liveness = _liveness
    DOCVERIFICATION_AVAILABLE = True
    DOCVERIFICATION_UNAVAILABLE_REASON = None
except ImportError as exc:  # pragma: no cover - exercised where cv2 missing
    local_cv = pipeline = adapters = liveness = None
    DOCVERIFICATION_AVAILABLE = False
    DOCVERIFICATION_UNAVAILABLE_REASON = (
        f"doc-verification package not importable ({exc}); expected at {_path} "
        "or DOCVERIFICATION_PATH")


def build_backends():
    """Construct a pipeline.Backends from current env (per-request, so env
    changes and tests take effect without a reload)."""
    return pipeline.Backends(
        ocr=adapters.PaddleOCRAdapter(),
        vlm=adapters.VLMAdapter(),
        docling=adapters.DoclingAdapter(),
    )


def get_idv_adapter():
    """OpenKYC-compatible remote IDV adapter from current env."""
    return adapters.OpenKYCCompatibleIDVAdapter()


# ---------------------------------------------------------------------------
# Round-14 document intelligence engine (in-process)
# ---------------------------------------------------------------------------

_engine_store = None


def run_engine(data: bytes, kind: str, document_type: str) -> dict | None:
    """Run the full document intelligence engine (pixel forensics, metadata,
    checksums, fingerprint registry, composite authenticity score) on a
    document payload. Returns None when the engine is unavailable — callers
    keep their honest degraded responses."""
    global _engine_store
    if not DOCVERIFICATION_AVAILABLE:
        return None
    try:
        import base64
        import doc_intelligence  # noqa: E402 — path appended above
        if _engine_store is None:
            _engine_store = doc_intelligence.DocIntelStore()
        encoded = base64.b64encode(data).decode()
        payload = doc_intelligence.IntelligenceInput(
            image_base64=encoded if kind != "pdf" else None,
            pdf_base64=encoded if kind == "pdf" else None,
            doc_type=document_type)
        result = doc_intelligence.run_intelligence(_engine_store, payload)
        return {"authenticity_score": result["authenticity_score"],
                "band": result["band"], "verdict": result["verdict"],
                "factors": result["factors"],
                "registry_matches": result["registry_matches"],
                "certificate": result["verification_certificate"]}
    except Exception:  # engine must never break the KYC path
        return None
