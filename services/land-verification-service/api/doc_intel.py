"""Bootstrap for the shared document intelligence engine (Round 14).

The land module's deed/conformance checks are TEXT-based; a forged deed SCAN
passes them trivially. When a caller supplies a deed image/PDF, this module
runs the shared document intelligence engine (pixel forensics, metadata
forensics, checksums, fingerprint registry, composite authenticity score)
so the land module authenticates the DOCUMENT, not just its clauses.

No build-time dependency: the services/python/doc-verification directory is
appended to sys.path (DOCVERIFICATION_PATH overrides). Unavailable ->
engine_ok False and callers attach an honest 'not performed' note.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path
from typing import Any, Optional

_DEFAULT_PATH = (Path(__file__).resolve().parents[2]
                 / "python" / "doc-verification")
_path = os.environ.get("DOCVERIFICATION_PATH", str(_DEFAULT_PATH)).strip()

try:
    if _path and os.path.isdir(_path) and _path not in sys.path:
        sys.path.append(_path)
    import doc_intelligence as _engine  # noqa: E402

    ENGINE_OK = True
    ENGINE_UNAVAILABLE_REASON = None
except ImportError as exc:  # pragma: no cover
    _engine = None
    ENGINE_OK = False
    ENGINE_UNAVAILABLE_REASON = (
        f"document intelligence engine not importable ({exc}); "
        f"expected at {_path} or DOCVERIFICATION_PATH")

_store = None


def analyze_document(data: bytes, kind: str = "image",
                     doc_type: str = "deed_of_assignment",
                     reference: Optional[str] = None) -> dict[str, Any]:
    """Run the engine on a deed scan. Never raises; unavailable or error ->
    {'engine_performed': False, 'reason': ...}."""
    global _store
    if not ENGINE_OK:
        return {"engine_performed": False, "reason": ENGINE_UNAVAILABLE_REASON}
    try:
        if _store is None:
            _store = _engine.DocIntelStore()
        encoded = base64.b64encode(data).decode()
        payload = _engine.IntelligenceInput(
            image_base64=encoded if kind == "image" else None,
            pdf_base64=encoded if kind == "pdf" else None,
            doc_type=doc_type, reference=reference)
        result = _engine.run_intelligence(_store, payload)
        return {"engine_performed": True,
                "verdict": result["verdict"],
                "authenticity_score": result["authenticity_score"],
                "band": result["band"],
                "factors": result["factors"],
                "spec_conformance": result["spec_conformance"],
                "certificate": result["verification_certificate"]}
    except Exception as exc:  # engine must never break the land path
        return {"engine_performed": False,
                "reason": f"engine error ({type(exc).__name__})"}
