"""KYB document-content verification tests.

Synthetic documents are built at test time: text PDFs via fpdf (extractable
by pypdf), an empty-page PDF for the no-text-layer path, and a PIL-generated
PNG for the image path. The doc-verification package (Lane D) and docling
are NOT required — degradation paths are forced deterministically with
monkeypatching so the suite is independent of optional backends.
"""

from __future__ import annotations

import base64
import io
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import kyb_verification
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

TENANT = Principal(sub="user-tenant-1", username="ada", roles=set())
TENANT2 = Principal(sub="user-tenant-2", username="bola", roles=set())
ADMIN_A = Principal(sub="staff-a", username="staffa", roles={"onboarding_admin"})
ADMIN_B = Principal(sub="staff-b", username="staffb", roles={"admin"})

BUSINESS = "Acme Logistics Ltd"
CAC = "RC1234567"


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "onboarding.db"))
    yield database
    reset_db_for_tests(None)


@pytest.fixture(autouse=True)
def _no_optional_backends(monkeypatch):
    """Force the doc-verification/docling-absent degradation paths so tests
    are deterministic regardless of what parallel lanes have landed."""
    monkeypatch.setattr(kyb_verification, "_load_docling_adapter",
                        lambda: (None, None))
    monkeypatch.setattr(kyb_verification, "_load_local_cv", lambda: None)


def make_client(db, principal):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def pdf_b64(lines: list[str]) -> str:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in lines:
        pdf.cell(200, 10, txt=line, ln=1)
    return base64.b64encode(pdf.output(dest="S").encode("latin-1")).decode()


def empty_pdf_b64() -> str:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    return base64.b64encode(pdf.output(dest="S").encode("latin-1")).decode()


def png_b64() -> str:
    from PIL import Image

    img = Image.new("RGB", (64, 64), (200, 30, 30))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def cac_cert(rc: str = CAC, name: str = "ACME LOGISTICS LTD") -> dict:
    return {
        "type": "cac_certificate",
        "reference": "s3://kyb/acme/cac.pdf",
        "content": pdf_b64([
            "CORPORATE AFFAIRS COMMISSION",
            "Certificate of Incorporation",
            f"This is to certify that {name}",
            f"RC Number: {rc}",
            "Date of Registration: 2021-03-15",
        ]),
    }


def memart(name: str = "ACME LOGISTICS LTD") -> dict:
    return {
        "type": "memart",
        "reference": "s3://kyb/acme/memart.pdf",
        "content": pdf_b64([
            "MEMORANDUM AND ARTICLES OF ASSOCIATION",
            f"Company Name: {name}",
            "The objects of the company are logistics and haulage.",
        ]),
    }


def utility_bill(days_old: int = 5) -> dict:
    bill_date = (datetime.now(timezone.utc) - timedelta(days=days_old)).date().isoformat()
    return {
        "type": "utility_bill",
        "reference": "s3://kyb/acme/bill.pdf",
        "content": pdf_b64([
            "EKEDC ELECTRICITY BILL",
            "Service Address: 12 Adeola Odeku Street, Victoria Island, Lagos",
            f"Bill Date: {bill_date}",
        ]),
    }


def board_resolution(with_signatories: bool = True) -> dict:
    lines = [
        "BOARD RESOLUTION OF ACME LOGISTICS LTD",
        "Resolved that the company shall open a settlement account.",
        "Date: 2026-08-01",
        "Signed:",
    ]
    if with_signatories:
        lines += ["Chidi Okafor", "Ngozi Eze"]
    return {
        "type": "board_resolution",
        "reference": "s3://kyb/acme/board.pdf",
        "content": pdf_b64(lines),
    }


def submit(client, documents, business=BUSINESS, cac=CAC):
    return client.post("/api/v1/onboarding/kyb", json={
        "businessName": business,
        "cacNumber": cac,
        "businessType": "limited_liability",
        "contactEmail": "compliance@acme.example",
        "documents": documents,
    })


def doc_verdict(verdict: dict, doc_type: str) -> dict:
    return next(d for d in verdict["documents"] if d["type"] == doc_type)


class TestContentIntake:
    def test_reference_only_submission_skips_verification(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [
            {"type": "cac_certificate", "reference": "s3://kyb/acme/cac.pdf"},
            {"type": "memart", "reference": "s3://kyb/acme/memart.pdf"},
        ])
        assert resp.status_code == 201, resp.text
        assert resp.json()["verification"] is None
        app_id = resp.json()["applicationId"]
        assert client.get(f"/api/v1/onboarding/kyb/{app_id}/verification").status_code == 404

    def test_content_hash_stored_not_content(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert()])
        assert resp.status_code == 201, resp.text
        row = db.query_one("SELECT documents FROM kyb_applications")
        import json as _json
        stored = _json.loads(row["documents"])
        assert stored[0]["content_sha256"]
        assert "content" not in stored[0]

    def test_invalid_base64_rejected_422(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [
            {"type": "cac_certificate", "reference": "r", "content": "!!!not-b64!!!"},
        ])
        assert resp.status_code == 422

    def test_oversize_content_rejected_413(self, db):
        client = make_client(db, TENANT)
        big = base64.b64encode(b"\x00" * (10 * 1024 * 1024 + 1)).decode()
        resp = submit(client, [
            {"type": "cac_certificate", "reference": "r", "content": big},
        ])
        assert resp.status_code == 413


class TestCacCertificate:
    def test_matching_rc_and_name_verified(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert()])
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["verification"]["verdict"] == "verified"
        assert "pypdf" in body["verification"]["engines"]
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{body['applicationId']}/verification").json()
        cac_doc = doc_verdict(verdict, "cac_certificate")
        assert cac_doc["verdict"] == "verified"
        assert cac_doc["extracted"]["rc_number"] == CAC
        assert cac_doc["extracted"]["company_name"] == "ACME LOGISTICS LTD"
        assert cac_doc["extracted"]["registration_date"] == "2021-03-15"
        assert verdict["consistency"]["cac_rc_matches_submission"] is True

    def test_mismatched_rc_rejected(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert(rc="RC7654321")])  # submitted RC1234567
        assert resp.status_code == 201, resp.text
        assert resp.json()["verification"]["verdict"] == "rejected"
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        cac_doc = doc_verdict(verdict, "cac_certificate")
        assert cac_doc["verdict"] == "rejected"
        assert verdict["consistency"]["cac_rc_matches_submission"] is False

    def test_mismatched_name_manual_review(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert(name="BETA INDUSTRIES LTD")])
        assert resp.status_code == 201
        # RC matches but the name doesn't -> not auto-verified, not a hard fail
        assert resp.json()["verification"]["verdict"] == "manual_review"

    def test_no_text_layer_manual_review(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [
            {"type": "cac_certificate", "reference": "scan.pdf",
             "content": empty_pdf_b64()},
        ])
        assert resp.status_code == 201
        assert resp.json()["verification"]["verdict"] == "manual_review"
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        cac_doc = doc_verdict(verdict, "cac_certificate")
        assert any("no_text_layer" in n for n in cac_doc["notes"])


class TestMemartConsistency:
    def test_consistent_memart_verified(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert(), memart()])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        assert verdict["verdict"] == "verified"
        assert verdict["consistency"]["memart_cac_name_consistent"] is True
        assert doc_verdict(verdict, "memart")["verdict"] == "verified"

    def test_conflicting_memart_name_rejected(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert(), memart(name="OMEGA PETROLEUM PLC")])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        assert verdict["verdict"] == "rejected"
        assert doc_verdict(verdict, "memart")["verdict"] == "rejected"
        assert verdict["consistency"]["memart_cac_name_consistent"] is False

    def test_memart_before_cac_in_payload_still_consistent(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [memart(), cac_cert()])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        assert verdict["consistency"]["memart_cac_name_consistent"] is True


class TestUtilityBill:
    def test_recent_bill_verified(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [utility_bill(days_old=5)])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        bill = doc_verdict(verdict, "utility_bill")
        assert bill["verdict"] == "verified"
        assert bill["extracted"]["bill_age_days"] <= 90
        assert "Lagos" in bill["extracted"]["address"]

    def test_stale_bill_flagged(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [utility_bill(days_old=120)])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        bill = doc_verdict(verdict, "utility_bill")
        assert bill["verdict"] == "manual_review"
        check = next(c for c in bill["checks"] if c["check"] == "bill_recent_90d")
        assert check["passed"] is False
        assert bill["extracted"]["bill_age_days"] == 120


class TestBoardResolution:
    def test_signatory_block_and_date_verified(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [board_resolution()])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        board = doc_verdict(verdict, "board_resolution")
        assert board["verdict"] == "verified"
        assert board["extracted"]["signatory_count"] >= 2
        assert board["extracted"]["date"] == "2026-08-01"

    def test_missing_signatories_manual_review(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [board_resolution(with_signatories=False)])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        board = doc_verdict(verdict, "board_resolution")
        assert board["verdict"] == "manual_review"
        check = next(c for c in board["checks"]
                     if c["check"] == "signatory_block_present")
        assert check["passed"] is False


class TestImageDocuments:
    def test_image_degrades_honestly_without_doc_verification(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [
            {"type": "cac_certificate", "reference": "cac.png",
             "content": png_b64()},
        ])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        doc = doc_verdict(verdict, "cac_certificate")
        assert doc["verdict"] == "manual_review"
        assert doc["extracted"]["format"] == "png"
        assert any("image_forensics_unavailable" in n for n in doc["notes"])
        checks = {c["check"]: c["passed"] for c in doc["checks"]}
        assert checks["non_empty"] and checks["recognized_format"]

    def test_image_routed_to_local_cv_when_importable(self, db, monkeypatch):
        """When Lane D's doc-verification package IS importable, image content
        is routed through local_cv forensics."""
        monkeypatch.setattr(kyb_verification, "_load_local_cv", lambda: None)
        import types
        fake = types.SimpleNamespace(
            analyze_image=lambda data: {"tamper_detected": False, "score": 0.1})
        monkeypatch.setattr(kyb_verification, "_load_local_cv", lambda: fake)
        client = make_client(db, TENANT)
        resp = submit(client, [
            {"type": "cac_certificate", "reference": "cac.png",
             "content": png_b64()},
        ])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        doc = doc_verdict(verdict, "cac_certificate")
        assert doc["forensics"]["tamper_detected"] is False
        assert "doc-verification:local_cv" in verdict["provenance"]["engines"]


class TestEngineUnavailable:
    def test_no_pdf_parser_engine_unavailable(self, db, monkeypatch):
        monkeypatch.setattr(kyb_verification, "_load_pypdf", lambda: None)
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert()])
        assert resp.status_code == 201
        body = resp.json()
        assert body["verification"]["verdict"] == "engine_unavailable"
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{body['applicationId']}/verification").json()
        doc = doc_verdict(verdict, "cac_certificate")
        assert doc["verdict"] == "engine_unavailable"
        assert any("no_pdf_parser" in n for n in doc["notes"])


class TestReviewApproveFlow:
    def _submit_verified(self, db):
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert(), memart(), utility_bill(),
                               board_resolution()])
        assert resp.status_code == 201
        assert resp.json()["verification"]["verdict"] == "verified"
        return resp.json()["applicationId"]

    def test_approve_response_includes_verdict(self, db):
        app_id = self._submit_verified(db)
        admin_a = make_client(db, ADMIN_A)
        admin_b = make_client(db, ADMIN_B)
        review = admin_a.post(f"/api/v1/onboarding/admin/kyb/{app_id}/review")
        assert review.status_code == 200
        assert review.json()["verification"]["verdict"] == "verified"
        approve = admin_b.post(f"/api/v1/onboarding/admin/kyb/{app_id}/approve")
        assert approve.status_code == 200, approve.text
        assert approve.json()["status"] == "approved"
        assert approve.json()["verification"]["verdict"] == "verified"

    def test_approve_not_blocked_by_manual_review(self, db):
        client = make_client(db, TENANT)
        app_id = submit(client, [utility_bill(days_old=120)]).json()["applicationId"]
        assert client.get(f"/api/v1/onboarding/kyb/{app_id}"
                          ).json()["verification"]["verdict"] == "manual_review"
        admin_a = make_client(db, ADMIN_A)
        admin_b = make_client(db, ADMIN_B)
        assert admin_a.post(f"/api/v1/onboarding/admin/kyb/{app_id}/review").status_code == 200
        approve = admin_b.post(f"/api/v1/onboarding/admin/kyb/{app_id}/approve")
        assert approve.status_code == 200, approve.text
        assert approve.json()["verification"]["verdict"] == "manual_review"

    def test_verification_endpoint_access_control(self, db):
        app_id = self._submit_verified(db)
        other = make_client(db, TENANT2)
        assert other.get(f"/api/v1/onboarding/kyb/{app_id}/verification").status_code == 403
        admin = make_client(db, ADMIN_A)
        assert admin.get(f"/api/v1/onboarding/kyb/{app_id}/verification").status_code == 200


class TestReverify:
    def test_reverify_with_resubmitted_documents(self, db):
        client = make_client(db, TENANT)
        # reference-only submission: verification skipped honestly
        app_id = submit(client, [
            {"type": "cac_certificate", "reference": "s3://kyb/acme/cac.pdf"},
        ]).json()["applicationId"]
        assert client.get(f"/api/v1/onboarding/kyb/{app_id}").json()["verification"] is None
        # resubmit with content and re-run
        resp = client.post(f"/api/v1/onboarding/kyb/{app_id}/reverify",
                           json={"documents": [cac_cert()]})
        assert resp.status_code == 200, resp.text
        assert resp.json()["verdict"] == "verified"
        view = client.get(f"/api/v1/onboarding/kyb/{app_id}").json()
        assert view["verification"]["verdict"] == "verified"

    def test_reverify_fixes_rejected_document(self, db):
        client = make_client(db, TENANT)
        app_id = submit(client, [cac_cert(rc="RC7654321")]).json()["applicationId"]
        assert client.get(f"/api/v1/onboarding/kyb/{app_id}"
                          ).json()["verification"]["verdict"] == "rejected"
        resp = client.post(f"/api/v1/onboarding/kyb/{app_id}/reverify",
                           json={"documents": [cac_cert(rc=CAC)]})
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "verified"

    def test_reverify_empty_body_returns_stored_verdict(self, db):
        client = make_client(db, TENANT)
        app_id = submit(client, [cac_cert()]).json()["applicationId"]
        resp = client.post(f"/api/v1/onboarding/kyb/{app_id}/reverify", json={})
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "verified"
        assert resp.json()["reused_stored_verdict"] is True

    def test_reverify_empty_body_without_prior_verdict_422(self, db):
        client = make_client(db, TENANT)
        app_id = submit(client, [
            {"type": "cac_certificate", "reference": "s3://kyb/acme/cac.pdf"},
        ]).json()["applicationId"]
        resp = client.post(f"/api/v1/onboarding/kyb/{app_id}/reverify", json={})
        assert resp.status_code == 422

    def test_reverify_other_tenant_forbidden(self, db):
        app_id = submit(make_client(db, TENANT), [cac_cert()]).json()["applicationId"]
        other = make_client(db, TENANT2)
        assert other.post(f"/api/v1/onboarding/kyb/{app_id}/reverify",
                          json={"documents": [cac_cert()]}).status_code == 403


class TestRealDocVerificationIntegration:
    """Integration with Lane D's real doc-verification package when it is
    present in the tree (services/python/doc-verification). Skipped honestly
    when it isn't — the unit paths above cover the degradation behavior."""

    @staticmethod
    def _dv_dir():
        from pathlib import Path
        return Path(kyb_verification.__file__).resolve().parents[2] / "doc-verification"

    def test_real_local_cv_routes_image_forensics(self, db, monkeypatch):
        import sys
        dv = self._dv_dir()
        if not (dv / "local_cv.py").exists():
            pytest.skip("doc-verification package not present")
        sys.path.insert(0, str(dv))
        import local_cv  # Lane D's module
        monkeypatch.setattr(kyb_verification, "_load_local_cv", lambda: local_cv)
        client = make_client(db, TENANT)
        resp = submit(client, [
            {"type": "cac_certificate", "reference": "cac.png",
             "content": png_b64()},
        ])
        assert resp.status_code == 201
        verdict = client.get(
            f"/api/v1/onboarding/kyb/{resp.json()['applicationId']}/verification").json()
        doc = doc_verdict(verdict, "cac_certificate")
        assert doc["forensics"]["decode_ok"] is True
        assert "quality" in doc["forensics"]
        assert "doc-verification:local_cv" in verdict["provenance"]["engines"]

    def test_real_docling_adapter_fails_closed_falls_back_to_pypdf(self, db, monkeypatch):
        """docling models can't download here (HF blocked), so the real
        DoclingAdapter reports unavailable and the pipeline must fall back to
        pypdf rather than fail."""
        import sys
        dv = self._dv_dir()
        if not (dv / "adapters.py").exists():
            pytest.skip("doc-verification package not present")
        sys.path.insert(0, str(dv))
        import adapters  # Lane D's module
        adapter = adapters.DoclingAdapter()
        monkeypatch.setattr(
            kyb_verification, "_load_docling_adapter",
            lambda: (adapter.parse_pdf, "doc-verification:adapters.DoclingAdapter"))
        client = make_client(db, TENANT)
        resp = submit(client, [cac_cert()])
        assert resp.status_code == 201
        body = resp.json()
        # docling unavailable (no models) -> pypdf fallback still verifies
        assert body["verification"]["verdict"] == "verified"
        assert "pypdf" in body["verification"]["engines"]


class TestNameSimilarity:
    def test_suffix_and_case_insensitive(self):
        assert kyb_verification.name_similarity(
            "ACME LOGISTICS LTD", "Acme Logistics Limited") == 1.0

    def test_typo_close_match(self):
        assert kyb_verification.name_similarity(
            "Acme Logistics Ltd", "Acme Logistic Ltd") >= 0.8

    def test_distinct_names_low(self):
        assert kyb_verification.name_similarity(
            "Acme Logistics Ltd", "Omega Petroleum Plc") < 0.5
