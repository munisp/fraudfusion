"""Document verification pipeline orchestration.

verify_document(image_bytes, doc_type, backends) layers:
  1. local_cv (ALWAYS runs — no dependencies, real cv2 forensics)
  2. OCR adapter (PaddleOCR) when available
  3. VLM adapter (ollama vision) when available — structured Nigerian doc-type
     extraction, fields validated against nigerian_docs regexes
  4. Docling adapter when the payload is a PDF and docling is installed

NEVER fabricates: every layer reports in `provenance` whether it `ran` or was
`unavailable` (with the reason). A layer that did not run contributes nothing.

Verdict statuses:
  * verified      — image readable, quality acceptable+, no replay sign, and a
                    structured extraction layer ran with all required fields
                    present AND regex-valid
  * manual_review — image readable but no extraction layer could confirm the
                    fields (only local_cv ran), or required fields missing /
                    invalid, or integrity signals ambiguous
  * rejected      — unreadable-quality capture (quality=poor) or screen-replay
                    moire detected
  * unavailable   — the image bytes could not be decoded at all
"""

from __future__ import annotations

from typing import Any, Optional

import adapters
import local_cv
import nigerian_docs

# Screen-replay integrity below this is treated as a detected replay attack.
SCREEN_REPLAY_REJECT_THRESHOLD = 0.35
# Printed-cutout integrity below this adds a manual-review reason.
PRINTED_CUTOUT_REVIEW_THRESHOLD = 0.25


class Backends:
    """Backend bundle; defaults are constructed from env at call time."""

    def __init__(self, ocr=None, vlm=None, docling=None):
        self.ocr = ocr if ocr is not None else adapters.get_ocr_adapter()
        self.vlm = vlm if vlm is not None else adapters.get_vlm_adapter()
        self.docling = (docling if docling is not None
                        else adapters.get_docling_adapter())


def _layer(layer: str, status: str, detail: Optional[str] = None,
           adapter: Optional[str] = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"layer": layer, "status": status}
    if adapter:
        entry["adapter"] = adapter
    if detail:
        entry["detail"] = detail
    return entry


def verify_document(image_bytes: bytes, doc_type: str,
                    backends: Optional[Backends] = None) -> dict[str, Any]:
    backends = backends or Backends()
    canonical = nigerian_docs.canonical_doc_type(doc_type)
    provenance: list[dict[str, Any]] = []
    reasons: list[str] = []

    # --- layer 1: local cv (always) -----------------------------------------
    local = local_cv.analyze_document_image(image_bytes)
    if not local["decode_ok"]:
        provenance.append(_layer("local_cv", "ran", "image undecodable"))
        for name, adapter in (("ocr", backends.ocr), ("vlm", backends.vlm)):
            provenance.append(_layer(name, "skipped",
                                     "image undecodable", adapter.name))
        return {
            "status": "unavailable",
            "document_type": doc_type,
            "document_type_canonical": canonical,
            "provenance": provenance,
            "extracted_fields": {},
            "field_validation": {},
            "authenticity": {"screen_replay_integrity": None,
                             "printed_cutout_integrity": None},
            "quality": "poor",
            "quality_scores": {},
            "reasons": ["image bytes could not be decoded as a supported "
                        "image format"],
        }
    provenance.append(_layer(
        "local_cv", "ran",
        f"quality={local['quality']} blur={local['quality_scores']['blur']} "
        f"replay_integrity={local['screen_replay_integrity']}"))
    reasons.extend(local["verdict_reasons"])

    # --- layer 2: OCR --------------------------------------------------------
    ocr_lines: list[dict[str, Any]] = []
    ocr_adapter = backends.ocr
    if ocr_adapter.availability()["available"]:
        ocr_result = ocr_adapter.ocr(image_bytes)
        if ocr_result["status"] == "ok":
            ocr_lines = ocr_result["lines"]
            provenance.append(_layer("ocr", "ran",
                                     f"{len(ocr_lines)} text lines",
                                     ocr_adapter.name))
        else:
            provenance.append(_layer("ocr", "unavailable",
                                     ocr_result.get("reason"), ocr_adapter.name))
    else:
        provenance.append(_layer("ocr", "unavailable",
                                 ocr_adapter.unavailable_reason,
                                 ocr_adapter.name))

    # --- layer 3: VLM structured extraction ----------------------------------
    extracted: dict[str, str] = {}
    vlm_adapter = backends.vlm
    vlm_ran = False
    if vlm_adapter.availability()["available"]:
        vlm_result = vlm_adapter.extract(image_bytes, doc_type)
        if vlm_result["status"] == "ok":
            extracted = vlm_result["fields"]
            vlm_ran = True
            provenance.append(_layer("vlm", "ran",
                                     f"model={vlm_result.get('model')} "
                                     f"fields={len(extracted)}",
                                     vlm_adapter.name))
        else:
            provenance.append(_layer("vlm", "unavailable",
                                     vlm_result.get("reason"),
                                     vlm_adapter.name))
    else:
        provenance.append(_layer("vlm", "unavailable",
                                 vlm_adapter.unavailable_reason,
                                 vlm_adapter.name))

    # --- field validation ----------------------------------------------------
    validation = nigerian_docs.validate_fields(doc_type, extracted)
    missing = nigerian_docs.missing_required(doc_type, extracted)
    invalid = [f for f, v in validation.items()
               if v["checked"] and v["valid"] is False]
    if vlm_ran and missing:
        reasons.append("required fields not extracted: " + ", ".join(missing))
    if invalid:
        reasons.append("fields failed format validation: " + ", ".join(invalid))

    # --- verdict -------------------------------------------------------------
    replay = local["screen_replay_integrity"]
    cutout = local["printed_cutout_integrity"]
    extraction_confirmed = (
        vlm_ran and not missing and not invalid and canonical is not None)
    if local["quality"] == "poor":
        status = "rejected"
        reasons.append("image quality insufficient for verification")
    elif replay is not None and replay < SCREEN_REPLAY_REJECT_THRESHOLD:
        status = "rejected"
    elif extraction_confirmed:
        status = "verified"
    else:
        status = "manual_review"
        if not vlm_ran:
            reasons.append("no structured extraction backend available — "
                           "fields could not be confirmed automatically")
        if cutout is not None and cutout < PRINTED_CUTOUT_REVIEW_THRESHOLD:
            reasons.append("weak physical-document signal (no border/texture) "
                           "— possible flat digital render")

    return {
        "status": status,
        "document_type": doc_type,
        "document_type_canonical": canonical,
        "provenance": provenance,
        "extracted_fields": extracted,
        "field_validation": validation,
        "ocr_lines": ocr_lines,
        "authenticity": {
            "screen_replay_integrity": replay,
            "printed_cutout_integrity": cutout,
        },
        "quality": local["quality"],
        "quality_scores": local["quality_scores"],
        "reasons": reasons,
    }


def verify_pdf(pdf_bytes: bytes, backends: Optional[Backends] = None) -> dict[str, Any]:
    """PDF path: docling layout parse when available; honest otherwise."""
    backends = backends or Backends()
    adapter = backends.docling
    if not adapter.availability()["available"]:
        return {"status": "unavailable", "reason": adapter.unavailable_reason,
                "provenance": [_layer("docling", "unavailable",
                                      adapter.unavailable_reason,
                                      adapter.name)]}
    result = adapter.parse_pdf(pdf_bytes)
    status = "ran" if result["status"] == "ok" else "unavailable"
    return {**result,
            "provenance": [_layer("docling", status, result.get("reason"),
                                  adapter.name)]}
