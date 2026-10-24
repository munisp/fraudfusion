"""Round 14 tests: document intelligence engine.

  forensics           — ELA splice, noise inconsistency, copy-move, JPEG ghost
  checksums           — ICAO 9303 MRZ check digits; date impossibility logic
  cross_field         — name seams, MRZ-vs-visual mismatch
  metadata_forensics  — EXIF editor tags; PDF producer/incremental updates
  fingerprint         — perceptual near-duplicate detection
  engine API          — composite score, registry, revocation, hash chain

Run: python3 -m pytest tests/test_doc_intelligence.py -q
     (from services/python/doc-verification)
"""

from __future__ import annotations

import base64
import io
import sys
from pathlib import Path

import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import checksums  # noqa: E402
import cross_field  # noqa: E402
import fingerprint  # noqa: E402
import forensics  # noqa: E402
import metadata_forensics  # noqa: E402
from doc_intelligence import (DocIntelStore, create_app,  # noqa: E402
                              reset_store_for_tests, score_factors)


def _b64(img: np.ndarray, quality: int = 95) -> str:
    ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, quality])
    assert ok
    return base64.b64encode(enc.tobytes()).decode()


def _doc_image(seed: int = 7, w: int = 512, h: int = 384) -> np.ndarray:
    """Textured document-like image (paper grain + text-ish blocks)."""
    rng = np.random.default_rng(seed)
    img = rng.normal(225, 6, (h, w, 3)).clip(0, 255).astype(np.uint8)
    cv2.rectangle(img, (10, 10), (w - 10, h - 10), (60, 60, 60), 2)
    # Non-periodic text bars: a regular grid of identical bars is itself
    # duplicated content and rightly trips copy-move detection.
    y = 40
    while y < h - 60:
        cv2.rectangle(img, (40 + int(rng.integers(0, 30)), y),
                      (40 + int(rng.integers(200, 420)), y + 14),
                      (40, 40, 40), -1)
        y += int(rng.integers(28, 55))
    return img


# --- forensics ---------------------------------------------------------------

class TestPixelForensics:
    def test_clean_document_no_signals(self):
        img = _doc_image()
        ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
        result = forensics.analyze(enc.tobytes())
        assert result["decode_ok"] is True
        assert result["signals"] == []

    def test_spliced_region_detected_by_ela(self):
        base = _doc_image()
        # Build the forgery at JPEG level: compress base, splice a patch from
        # a DIFFERENT image (different compression generation), save again.
        ok, enc1 = cv2.imencode(".jpg", base, [cv2.IMWRITE_JPEG_QUALITY, 70])
        host = cv2.imdecode(enc1, cv2.IMREAD_COLOR)
        donor = _doc_image(seed=99)
        patch = donor[100:228, 100:228]
        host[100:228, 100:228] = patch
        ok, enc2 = cv2.imencode(".jpg", host, [cv2.IMWRITE_JPEG_QUALITY, 95])
        result = forensics.analyze(enc2.tobytes())
        codes = {s["code"] for s in result["signals"]}
        assert "ela_splice" in codes

    def test_copy_move_detected(self):
        img = _doc_image()
        region = img[32:128, 32:128].copy()
        img[128:224, 128:224] = region  # clone a block-aligned region
        ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
        result = forensics.analyze(enc.tobytes())
        assert result["metrics"]["copy_move"]["copy_move_suspected"] is True
        assert any(s["code"] == "copy_move" for s in result["signals"])

    def test_double_compression_ghost(self):
        img = _doc_image()
        ok, enc1 = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 70])
        once = cv2.imdecode(enc1, cv2.IMREAD_COLOR)
        ok, enc2 = cv2.imencode(".jpg", once, [cv2.IMWRITE_JPEG_QUALITY, 95])
        ghost = forensics.jpeg_ghost(cv2.imdecode(enc2, cv2.IMREAD_COLOR))
        assert "resave_responses" in ghost  # metric always reported

    def test_undecodable_never_raises(self):
        assert forensics.analyze(b"not an image")["decode_ok"] is False


# --- checksums + cross-field --------------------------------------------------

class TestChecksums:
    # ICAO 9303 worked example: check digit of "520727" (DOB) with 7-3-1.
    def test_mrz_check_digit_known_vector(self):
        assert checksums.mrz_check_digit("520727") == (
            (5 * 7 + 2 * 3 + 0 * 1 + 7 * 7 + 2 * 3 + 7 * 1) % 10)

    def test_validate_field(self):
        data = "A12345678"
        assert checksums.validate_mrz_field(data, str(checksums.mrz_check_digit(data)))
        assert not checksums.validate_mrz_field(data, str((checksums.mrz_check_digit(data) + 1) % 10))

    def _mrz(self, doc="A1234567", dob="520727", exp="301231"):
        l1 = ("P<NGAOKAFOR<<ADEWALE<<CHUKWUDI" + "<" * 44)[:44].ljust(44, "<")
        d = checksums.mrz_check_digit
        l2 = (f"{doc}<{d(doc + '<')}"
              f"NGA{dob}{d(dob)}M{exp}{d(exp)}"
              f"{'<' * 14}<")
        composite = l2[0:10] + l2[13:20] + l2[21:43]
        l2 = l2[:43] + str(d(composite))
        assert len(l2) == 44
        return l1, l2

    def test_valid_mrz_passes(self):
        l1, l2 = self._mrz()
        assert checksums.validate_passport_mrz(l1, l2)["all_valid"] is True

    def test_single_digit_alteration_fails(self):
        l1, l2 = self._mrz(dob="520727")
        forged = l2[:15] + "9" + l2[16:]  # forger changes DOB year digit
        result = checksums.validate_passport_mrz(l1, forged)
        assert result["checks"]["date_of_birth"] is False
        assert result["all_valid"] is False

    def test_date_logic_impossibilities(self):
        issues = checksums.date_logic_issues(
            {"date_of_birth": "01/01/1990", "issue_date": "01/01/1985",
             "expiry_date": "01/01/1984"})
        codes = {i["code"] for i in issues}
        assert "issued_before_birth" in codes
        assert "expiry_before_issue" in codes
        assert checksums.date_logic_issues(
            {"date_of_birth": "01/01/1990", "issue_date": "01/01/2020",
             "expiry_date": "01/01/2030"}) == []

    def test_name_seam(self):
        bad = cross_field.run({"name": "Adewale Okafor", "surname": "Abubakar"})
        assert any(i["code"] == "name_inconsistency" for i in bad["issues"])
        good = cross_field.run({"name": "Adewale Okafor", "surname": "Okafor"})
        assert good["issues"] == []


# --- metadata -----------------------------------------------------------------

class TestMetadataForensics:
    def test_exif_editor_tag(self):
        from PIL import Image
        img = Image.fromarray(_doc_image())
        exif = Image.Exif()
        exif[0x0131] = "Adobe Photoshop 2024"   # Software
        buf = io.BytesIO()
        img.save(buf, format="JPEG", exif=exif)
        result = metadata_forensics.analyze_image_metadata(buf.getvalue())
        assert any(s["code"] == "metadata_editor" for s in result["signals"])

    def test_pdf_editor_and_incremental_update(self):
        pdf = (b"%PDF-1.4\n1 0 obj << /Producer (iLovePDF) /CreationDate (D:20240101120000) "
               b"/ModDate (D:20230101000000) >> endobj\n"
               b"startxref\n100\n%%EOF\n"
               b"3 0 obj << >> endobj\nstartxref\n200\n%%EOF\n")
        result = metadata_forensics.analyze_pdf_metadata(pdf)
        codes = {s["code"] for s in result["signals"]}
        assert "pdf_editor_producer" in codes
        assert "pdf_date_impossible" in codes
        assert "pdf_incremental_update" in codes

    def test_clean_pdf_no_signals(self):
        pdf = b"%PDF-1.4\n1 0 obj << /Producer (FraudFusion Print Service) >> endobj\nstartxref\n9\n%%EOF\n"
        assert metadata_forensics.analyze_pdf_metadata(pdf)["signals"] == []


# --- fingerprint ---------------------------------------------------------------

class TestFingerprint:
    def test_same_document_recaptured_matches(self):
        img = _doc_image()
        fp_a = fingerprint.fingerprint(_b64(img, 95).encode() and base64.b64decode(_b64(img, 95)))
        recaptured = base64.b64decode(_b64(img, 70))  # re-compressed
        fp_b = fingerprint.fingerprint(recaptured)
        dist = fingerprint.distance(fp_a, fp_b)
        assert dist is not None and dist <= fingerprint.SAME_DOCUMENT_THRESHOLD

    def test_different_document_far(self):
        fp_a = fingerprint.fingerprint(base64.b64decode(_b64(_doc_image(1))))
        fp_b = fingerprint.fingerprint(base64.b64decode(_b64(_doc_image(2))))
        assert fingerprint.distance(fp_a, fp_b) > fingerprint.SIMILAR_THRESHOLD


# --- scoring + engine API -----------------------------------------------------

class TestScoring:
    def test_bands(self):
        assert score_factors([])["band"] == "clean"
        assert score_factors([{"code": "double_compression"}])["band"] == "clean"
        assert score_factors([{"code": "ela_splice"}])["band"] == "manual_review"
        assert score_factors([{"code": "copy_move"}])["band"] == "manual_review"
        assert score_factors([{"code": "copy_move"},
                              {"code": "ela_splice"}])["band"] == "forgery_suspected"

    def test_capped_and_explained(self):
        s = score_factors([{"code": "revoked_document"}, {"code": "copy_move"}])
        assert s["authenticity_score"] == 100
        assert all("penalty" in f and "detail" in f for f in s["factors"])


@pytest.fixture()
def store(tmp_path):
    s = DocIntelStore(sqlite_path=str(tmp_path / "docintel_test.db"))
    reset_store_for_tests(s)
    yield s
    reset_store_for_tests(None)


@pytest.fixture()
def client(store):
    return TestClient(create_app())


class TestEngineAPI:
    def test_clean_document_verified(self, client):
        payload = {"image_base64": _b64(_doc_image()), "doc_type": "nin_slip"}
        r = client.post("/api/v1/documents/intelligence", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body["verdict"] in ("verified", "manual_review")  # no forgery factors
        assert body["authenticity_score"] < 50
        assert body["verification_certificate"]["document_sha256"] == body["document_sha256"]

    def test_spliced_document_flagged(self, client):
        ok, enc1 = cv2.imencode(".jpg", _doc_image(), [cv2.IMWRITE_JPEG_QUALITY, 70])
        host = cv2.imdecode(enc1, cv2.IMREAD_COLOR)
        host[100:228, 100:228] = _doc_image(seed=99)[100:228, 100:228]
        ok, enc2 = cv2.imencode(".jpg", host, [cv2.IMWRITE_JPEG_QUALITY, 95])
        r = client.post("/api/v1/documents/intelligence",
                        json={"image_base64": base64.b64encode(enc2.tobytes()).decode(),
                              "doc_type": "certificate_of_occupancy"})
        body = r.json()
        codes = {f["code"] for f in body["factors"]}
        assert "ela_splice" in codes
        assert body["authenticity_score"] >= 20

    def test_mrz_checksum_factor(self, client):
        # Valid MRZ with ONE altered DOB digit (check digit no longer matches).
        l1, l2 = TestChecksums()._mrz()
        forged = l2[:15] + "9" + l2[16:]
        fields = {"mrz_line1": l1, "mrz_line2": forged}
        r = client.post("/api/v1/documents/intelligence",
                        json={"image_base64": _b64(_doc_image()),
                              "doc_type": "passport", "fields": fields})
        codes = {f["code"] for f in r.json()["factors"]}
        assert "mrz_checksum_fail" in codes

    def test_date_impossibility_factor(self, client):
        r = client.post("/api/v1/documents/intelligence",
                        json={"image_base64": _b64(_doc_image()), "doc_type": "drivers_license",
                              "fields": {"date_of_birth": "01/01/1995",
                                         "issue_date": "01/01/1990"}})
        assert "date_impossible" in {f["code"] for f in r.json()["factors"]}

    def test_registry_and_resubmission(self, client):
        img = _b64(_doc_image())
        r1 = client.post("/api/v1/documents/intelligence",
                         json={"image_base64": img, "doc_type": "c_of_o", "register": True})
        doc_hash = r1.json()["document_sha256"]
        entry = client.get(f"/api/v1/documents/{doc_hash}").json()
        assert entry["registry"]["status"] == "active"
        # Byte-identical resubmission to a second "lender" is caught:
        r2 = client.post("/api/v1/documents/intelligence",
                         json={"image_base64": img, "doc_type": "c_of_o"})
        assert "same_document_resubmitted" in {f["code"] for f in r2.json()["factors"]}
        # Re-compressed (re-photographed) resubmission is ALSO caught:
        recaptured = _b64(cv2.imdecode(np.frombuffer(base64.b64decode(img), np.uint8),
                                       cv2.IMREAD_COLOR), 70)
        r3 = client.post("/api/v1/documents/intelligence",
                         json={"image_base64": recaptured, "doc_type": "c_of_o"})
        codes = {f["code"] for f in r3.json()["factors"]}
        assert "same_document_resubmitted" in codes or "near_duplicate_known" in codes

    def test_revocation_forces_forgery_verdict(self, client):
        img = _b64(_doc_image())
        r1 = client.post("/api/v1/documents/register",
                         json={"image_base64": img, "doc_type": "c_of_o"})
        doc_hash = r1.json()["doc_hash"]
        client.post(f"/api/v1/documents/{doc_hash}/revoke",
                    params={"reason": "confirmed forgery — Lagos Lands Bureau"})
        r2 = client.post("/api/v1/documents/intelligence",
                         json={"image_base64": img, "doc_type": "c_of_o"})
        body = r2.json()
        assert body["verdict"] == "rejected"
        assert body["authenticity_score"] == 100
        assert "revoked_document" in {f["code"] for f in body["factors"]}

    def test_similar_endpoint(self, client):
        img = _b64(_doc_image())
        r1 = client.post("/api/v1/documents/register",
                         json={"image_base64": img, "doc_type": "c_of_o"})
        doc_hash = r1.json()["doc_hash"]
        recaptured = _b64(cv2.imdecode(np.frombuffer(base64.b64decode(img), np.uint8),
                                       cv2.IMREAD_COLOR), 70)
        client.post("/api/v1/documents/register",
                    json={"image_base64": recaptured, "doc_type": "c_of_o"})
        sim = client.get(f"/api/v1/documents/{doc_hash}/similar").json()
        assert len(sim["similar"]) == 1

    def test_verification_chain_tamper_evident(self, client, store):
        img = _b64(_doc_image())
        r = client.post("/api/v1/documents/intelligence",
                        json={"image_base64": img, "doc_type": "c_of_o"})
        doc_hash = r.json()["document_sha256"]
        chain = client.get(f"/api/v1/documents/{doc_hash}/chain").json()
        assert chain["chain_valid"] is True and chain["entry_count"] >= 1
        # Tamper with a stored entry -> verification fails.
        store.execute("UPDATE doc_verification_chain SET event_type = 'x'"
                      " WHERE doc_hash = :d", {"d": doc_hash})
        chain2 = client.get(f"/api/v1/documents/{doc_hash}/chain").json()
        assert chain2["chain_valid"] is False

    def test_pdf_path_editor_detected(self, client):
        pdf = (b"%PDF-1.4\n1 0 obj << /Producer (smallpdf.com) >> endobj\n"
               b"startxref\n9\n%%EOF\n3 0 obj << >> endobj\nstartxref\n50\n%%EOF\n")
        r = client.post("/api/v1/documents/intelligence",
                        json={"pdf_base64": base64.b64encode(pdf).decode(),
                              "doc_type": "deed_of_assignment"})
        codes = {f["code"] for f in r.json()["factors"]}
        assert "pdf_editor_producer" in codes and "pdf_incremental_update" in codes

    def test_missing_payload_422(self, client):
        assert client.post("/api/v1/documents/intelligence",
                           json={"doc_type": "c_of_o"}).status_code == 422
