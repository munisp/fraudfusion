"""Pipeline orchestration tests: provenance, routing, no fabrication.

Run: python3 -m pytest tests/ -q   (from services/python/doc-verification)
"""

from __future__ import annotations

import adapters
import nigerian_docs
import pipeline
from conftest import to_png


def _offline_backends() -> pipeline.Backends:
    return pipeline.Backends(
        ocr=adapters.PaddleOCRAdapter(enabled=False),
        vlm=adapters.VLMAdapter(base_url=""),
        docling=adapters.DoclingAdapter(),
    )


class TestProvenance:
    def test_offline_layers_report_unavailable_honestly(self, clean_card):
        verdict = pipeline.verify_document(to_png(clean_card), "nin_slip",
                                           backends=_offline_backends())
        by_layer = {p["layer"]: p for p in verdict["provenance"]}
        assert by_layer["local_cv"]["status"] == "ran"
        assert by_layer["ocr"]["status"] == "unavailable"
        assert "paddleocr" in by_layer["ocr"]["detail"] or \
               "PADDLEOCR_ENABLED" in by_layer["ocr"]["detail"]
        assert by_layer["vlm"]["status"] == "unavailable"
        assert "OLLAMA_URL" in by_layer["vlm"]["detail"]
        # An unavailable layer contributes nothing.
        assert verdict["extracted_fields"] == {}

    def test_manual_review_when_only_local_layer_ran(self, clean_card):
        verdict = pipeline.verify_document(to_png(clean_card), "nin_slip",
                                           backends=_offline_backends())
        assert verdict["status"] == "manual_review"
        assert any("no structured extraction backend" in r
                   for r in verdict["reasons"])

    def test_unavailable_when_image_unreadable(self):
        verdict = pipeline.verify_document(b"\x00\xffgarbage", "nin_slip",
                                           backends=_offline_backends())
        assert verdict["status"] == "unavailable"
        assert verdict["extracted_fields"] == {}
        by_layer = {p["layer"]: p for p in verdict["provenance"]}
        assert by_layer["local_cv"]["status"] == "ran"
        assert by_layer["ocr"]["status"] == "skipped"

    def test_rejected_on_screen_replay(self, moire):
        verdict = pipeline.verify_document(to_png(moire), "drivers_license",
                                           backends=_offline_backends())
        assert verdict["status"] == "rejected"
        assert verdict["authenticity"]["screen_replay_integrity"] < 0.35

    def test_rejected_on_poor_quality(self, blurry):
        verdict = pipeline.verify_document(to_png(blurry), "voters_card",
                                           backends=_offline_backends())
        assert verdict["status"] == "rejected"
        assert verdict["quality"] == "poor"

    def test_flat_render_routes_to_manual_review(self, flat_render):
        verdict = pipeline.verify_document(to_png(flat_render), "national_id",
                                           backends=_offline_backends())
        assert verdict["status"] == "manual_review"
        assert any("flat digital render" in r for r in verdict["reasons"])


class _StubVLM(adapters.BackendAdapter):
    """Available VLM returning canned fields (simulates configured ollama)."""

    name = "stub_vlm"

    def __init__(self, fields):
        self.available = True
        self._fields = fields

    def extract(self, image_bytes, doc_type):
        return {"status": "ok", "fields": self._fields, "model": "stub",
                "adapter": self.name, "source": "stub"}


class TestVerdictWithExtraction:
    def test_verified_when_all_required_fields_valid(self, clean_card):
        vlm = _StubVLM({"name": "ADAEZE EZE", "nin": "12345678901",
                        "date_of_birth": "20/05/1990"})
        backends = pipeline.Backends(
            ocr=adapters.PaddleOCRAdapter(enabled=False), vlm=vlm,
            docling=adapters.DoclingAdapter())
        verdict = pipeline.verify_document(to_png(clean_card), "nin_slip",
                                           backends=backends)
        assert verdict["status"] == "verified"
        assert verdict["field_validation"]["nin"]["valid"] is True
        by_layer = {p["layer"]: p for p in verdict["provenance"]}
        assert by_layer["vlm"]["status"] == "ran"

    def test_manual_review_when_required_field_invalid(self, clean_card):
        vlm = _StubVLM({"name": "ADAEZE EZE", "nin": "12345",  # not 11 digits
                        "date_of_birth": "20/05/1990"})
        backends = pipeline.Backends(
            ocr=adapters.PaddleOCRAdapter(enabled=False), vlm=vlm,
            docling=adapters.DoclingAdapter())
        verdict = pipeline.verify_document(to_png(clean_card), "nin_slip",
                                           backends=backends)
        assert verdict["status"] == "manual_review"
        assert verdict["field_validation"]["nin"]["valid"] is False
        assert any("format validation" in r for r in verdict["reasons"])

    def test_manual_review_when_required_field_missing(self, clean_card):
        vlm = _StubVLM({"name": "ADAEZE EZE"})
        backends = pipeline.Backends(
            ocr=adapters.PaddleOCRAdapter(enabled=False), vlm=vlm,
            docling=adapters.DoclingAdapter())
        verdict = pipeline.verify_document(to_png(clean_card), "intl_passport",
                                           backends=backends)
        assert verdict["status"] == "manual_review"
        assert any("not extracted" in r for r in verdict["reasons"])


class TestNigerianDocs:
    def test_aliases(self):
        assert nigerian_docs.canonical_doc_type("international_passport") == \
            "intl_passport"
        assert nigerian_docs.canonical_doc_type("driver_license") == \
            "drivers_license"
        assert nigerian_docs.canonical_doc_type("unknown_doc") is None

    def test_validators(self):
        assert nigerian_docs.validate_fields(
            "nin_slip", {"nin": "12345678901"})["nin"]["valid"] is True
        assert nigerian_docs.validate_fields(
            "nin_slip", {"nin": "123"})["nin"]["valid"] is False
        assert nigerian_docs.validate_fields(
            "intl_passport", {"passport_number": "A12345678"}
        )["passport_number"]["valid"] is True
        assert nigerian_docs.validate_fields(
            "intl_passport", {"passport_number": "12345678"}
        )["passport_number"]["valid"] is False

    def test_pdf_parse_honest_when_docling_missing(self):
        out = pipeline.verify_pdf(b"%PDF-1.4 x\n%%EOF\n",
                                  backends=_offline_backends())
        assert out["status"] == "unavailable"
        assert out["provenance"][0]["layer"] == "docling"
