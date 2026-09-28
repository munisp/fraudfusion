"""KYB endpoint fixtures and shape conformance (onboarding-service shapes)."""

from __future__ import annotations

import base64

from tests.conftest import AUTH, PDF_BYTES

# KybApplicationView fields (onboarding-service app/schemas.py, by alias).
KYB_VIEW_KEYS = {
    "applicationId", "businessName", "cacNumber", "businessType", "status",
    "submittedBy", "reviewedBy", "approvedBy", "rejectionReason", "createdAt",
    "verification",
}

# verify_kyb_documents verdict envelope keys (onboarding-service
# app/kyb_verification.py).
VERDICT_KEYS = {
    "verdict", "reason", "documents", "documents_with_content",
    "documents_total", "consistency", "provenance", "verified_at",
}


def _submission(cac="RC000000", name="Sandbox Verified Ventures Ltd"):
    return {
        "businessName": name,
        "cacNumber": cac,
        "businessType": "limited_liability",
        "contactEmail": "dev@sandbox.example",
        "documents": [
            {"type": "cac_certificate", "reference": "s3://sandbox/cac.pdf",
             "content": base64.b64encode(PDF_BYTES).decode()},
            {"type": "utility_bill", "reference": "s3://sandbox/bill.pdf"},
        ],
    }


class TestKybFixtures:
    def test_rc000000_verified(self, client):
        r = client.post("/api/v1/onboarding/kyb", json=_submission(),
                        headers=AUTH)
        assert r.status_code == 201
        body = r.json()
        assert body["verification"]["verdict"] == "verified"
        assert body["status"] == "approved"

    def test_rc000001_manual_review(self, client):
        body = client.post("/api/v1/onboarding/kyb",
                           json=_submission("RC000001",
                                            "Sandbox Review Trading Co"),
                           headers=AUTH).json()
        assert body["verification"]["verdict"] == "manual_review"
        assert body["status"] == "under_review"

    def test_rc000002_rejected(self, client):
        body = client.post("/api/v1/onboarding/kyb",
                           json=_submission("RC000002",
                                            "Sandbox Rejected Enterprises"),
                           headers=AUTH).json()
        assert body["verification"]["verdict"] == "rejected"
        assert body["status"] == "rejected"
        assert body["rejectionReason"]

    def test_other_valid_cac_defaults_verified(self, client):
        body = client.post("/api/v1/onboarding/kyb",
                           json=_submission("RC7654321", "Other Co Ltd"),
                           headers=AUTH).json()
        assert body["verification"]["verdict"] == "verified"

    def test_invalid_cac_is_422_mirroring_real_schema(self, client):
        r = client.post("/api/v1/onboarding/kyb",
                        json=_submission("XX123456"), headers=AUTH)
        assert r.status_code == 422
        assert "CAC number must look like RC1234567" in str(r.json())

    def test_cac_normalized_uppercase(self, client):
        body = client.post("/api/v1/onboarding/kyb",
                           json=_submission("rc000000"), headers=AUTH).json()
        assert body["cacNumber"] == "RC000000"
        assert body["verification"]["verdict"] == "verified"

    def test_invalid_document_content_is_422(self, client):
        sub = _submission()
        sub["documents"][0]["content"] = "!!!not-base64!!!"
        r = client.post("/api/v1/onboarding/kyb", json=sub, headers=AUTH)
        assert r.status_code == 422


class TestKybShapes:
    def test_application_view_shape(self, client):
        body = client.post("/api/v1/onboarding/kyb", json=_submission(),
                           headers=AUTH).json()
        assert KYB_VIEW_KEYS <= set(body)
        assert body["environment"] == "sandbox" and body["synthetic"] is True
        summary = body["verification"]
        assert {"verdict", "verifiedAt", "engines",
                "documentsWithContent"} <= set(summary)
        assert summary["documentsWithContent"] == 1

    def test_verification_endpoint_shape(self, client):
        created = client.post("/api/v1/onboarding/kyb", json=_submission(),
                              headers=AUTH).json()
        app_id = created["applicationId"]
        r = client.get(f"/api/v1/onboarding/kyb/{app_id}/verification",
                       headers=AUTH)
        assert r.status_code == 200
        verdict = r.json()
        assert VERDICT_KEYS <= set(verdict)
        assert verdict["environment"] == "sandbox"
        assert verdict["synthetic"] is True
        assert verdict["verdict"] == "verified"
        assert verdict["documents_total"] == 2
        assert verdict["documents_with_content"] == 1
        assert {"cac_rc_matches_submission",
                "memart_cac_name_consistent"} <= set(verdict["consistency"])
        doc = verdict["documents"][0]
        assert {"type", "reference", "content_sha256", "verdict", "checks",
                "extracted", "notes"} <= set(doc)

    def test_application_id_is_deterministic(self, client):
        a = client.post("/api/v1/onboarding/kyb", json=_submission(),
                        headers=AUTH).json()["applicationId"]
        b = client.post("/api/v1/onboarding/kyb", json=_submission(),
                        headers=AUTH).json()["applicationId"]
        assert a == b and a.startswith("kyb_")

    def test_unknown_verification_id_404(self, client):
        r = client.get("/api/v1/onboarding/kyb/kyb_doesnotexist/verification",
                       headers=AUTH)
        assert r.status_code == 404
