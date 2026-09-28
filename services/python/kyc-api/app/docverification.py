"""Bootstrap for the shared doc-verification engine.

kyc-api has no build-time dependency on the shared package: the
services/python/doc-verification directory is appended to sys.path here, from
DOCVERIFICATION_PATH when set, otherwise the repo-relative default
(services/python/doc-verification). If the package or its core deps
(cv2/numpy) are absent, DOCVERIFICATION_AVAILABLE is False and every document
/ biometric endpoint falls back to the honest "not performed / unavailable"
responses — nothing is fabricated either way.

Exposes the pieces app/main.py uses:
  local_cv, pipeline, adapters modules and build_backends().
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
    import local_cv as _local_cv  # noqa: E402
    import pipeline as _pipeline  # noqa: E402

    local_cv = _local_cv
    pipeline = _pipeline
    adapters = _adapters
    DOCVERIFICATION_AVAILABLE = True
    DOCVERIFICATION_UNAVAILABLE_REASON = None
except ImportError as exc:  # pragma: no cover - exercised where cv2 missing
    local_cv = pipeline = adapters = None
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
