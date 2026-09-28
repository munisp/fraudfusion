"""KYC + document endpoint fixtures and shape conformance."""

from __future__ import annotations

from tests.conftest import AUTH, PDF_BYTES, PNG_BYTES

# The KYCResponse fields of the real kyc-api (services/python/kyc-api
# app/schemas.py) — the sandbox response must be a superset of these.
KYC_RESPONSE_KEYS = {
    "request_id", "customer_id", "status", "verification_level", "risk_score",
    "risk_level", "decision", "verification_results", "timestamp",
    "processing_time_ms",
}

# The /api/v1/document/verify envelope keys of the real kyc-api
# (app/main.py _document_checks + handler additions).
DOCUMENT_RESPONSE_KEYS = {
    "document_type", "detected_format", "size_bytes", "checks", "forgery",
    "structurally_valid", "verification_id", "status", "timestamp",
}


def _payload(**over):
    base = {
        "customer_id": "cus_sandbox_t",
        "bvn": "22300000000",
        "nin": "70123456000",
        "phone": "+2348010000001",
        "email": "dev@sandbox.example",
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": "1990-01-01",
    }
    base.update(over)
    return base


def _verify(client, path="/api/v1/kyc/verify", **over):
    return client.post(path, json=_payload(**over), headers=AUTH)


class TestDeterministicFixtures:
    def test_bvn_000_approved(self, client):
        body = _verify(client, bvn="22300000000").json()
        assert body["decision"] == "approved"
        assert body["status"] == "completed"
        assert body["risk_level"] == "low"

    def test_bvn_001_manual_review(self, client):
        body = _verify(client, bvn="22300000001").json()
        assert body["decision"] == "manual_review"

    def test_bvn_002_rejected(self, client):
        body = _verify(client, bvn="22300000002").json()
        assert body["decision"] == "rejected"

    def test_bvn_003_sanctions_hit(self, client):
        body = _verify(client, "/api/v1/kyc/verify/enhanced",
                       bvn="22300000003").json()
        assert body["decision"] == "rejected"
        sanctions = body["verification_results"]["sanctions_screening"]
        assert sanctions["is_sanctioned"] is True

    def test_other_valid_bvn_defaults_approved(self, client):
        body = _verify(client, bvn="22300000099").json()
        assert body["decision"] == "approved"

    def test_determinism(self, client):
        a = _verify(client, bvn="22300000001").json()
        b = _verify(client, bvn="22300000001").json()
        assert a["decision"] == b["decision"]
        assert a["risk_score"] == b["risk_score"]


class TestValidationMirrorsRealBehaviour:
    def test_bad_nin_format_rejected_with_reason(self, client):
        r = _verify(client, bvn=None, nin="12345")
        assert r.status_code == 200  # real service rejects via decision, not 4xx
        body = r.json()
        assert body["decision"] == "rejected"
        nin = body["verification_results"]["nin"]
        assert nin["provided"] is True and nin["format_valid"] is False
        assert nin["reason"] == "NIN must be exactly 11 digits"

    def test_repeated_digit_nin_rejected(self, client):
        body = _verify(client, bvn=None, nin="11111111111").json()
        nin = body["verification_results"]["nin"]
        assert nin["format_valid"] is False
        assert nin["reason"] == "NIN cannot be a repeated digit"

    def test_bad_bvn_format_rejected_with_reason(self, client):
        body = _verify(client, bvn="abc").json()
        bvn = body["verification_results"]["bvn"]
        assert bvn["format_valid"] is False
        assert bvn["reason"] == "BVN must be exactly 11 digits"
        assert body["decision"] == "rejected"

    def test_no_ids_still_processed(self, client):
        body = _verify(client, bvn=None, nin=None).json()
        assert body["verification_results"]["bvn"]["registry_status"] == "not_provided"
        assert body["decision"] == "approved"


class TestShapes:
    def test_kyc_response_shape(self, client):
        body = _verify(client).json()
        assert KYC_RESPONSE_KEYS <= set(body)
        assert body["environment"] == "sandbox"
        assert body["synthetic"] is True
        results = body["verification_results"]
        for key in ("level", "bvn", "nin", "phone_tenure", "tier",
                    "tier_limits_ngn", "address_verification"):
            assert key in results, key
        limits = results["tier_limits_ngn"]
        assert {"single_transaction", "daily", "requirements"} <= set(limits)

    def test_enhanced_adds_screening_keys(self, client):
        body = _verify(client, "/api/v1/kyc/verify/enhanced").json()
        results = body["verification_results"]
        assert "pep_screening" in results
        assert "sanctions_screening" in results

    def test_premium_adds_credit_bureau(self, client):
        body = _verify(client, "/api/v1/kyc/verify/premium").json()
        assert body["verification_results"]["credit_bureau"]["status"] == "ok"

    def test_levels_reflected(self, client):
        for level in ("basic", "enhanced", "premium"):
            body = _verify(client, f"/api/v1/kyc/verify/{level}").json()
            assert body["verification_level"] == level

    def test_document_response_shape(self, client):
        r = client.post(
            "/api/v1/document/verify",
            files={"document": ("id_card.png", PNG_BYTES, "image/png")},
            data={"document_type": "national_id", "check_forgery": "true"},
            headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert DOCUMENT_RESPONSE_KEYS <= set(body)
        assert body["environment"] == "sandbox" and body["synthetic"] is True
        assert body["detected_format"] == "png"
        assert body["structurally_valid"] is True
        assert body["status"] == "verified"
        assert {c["check"] for c in body["checks"]} == {
            "non_empty", "size_within_limit", "recognized_format"}

    def test_document_magic_filename_reject(self, client):
        r = client.post(
            "/api/v1/document/verify",
            files={"document": ("reject_me.png", PNG_BYTES, "image/png")},
            data={"document_type": "national_id"},
            headers=AUTH)
        assert r.json()["status"] == "rejected"

    def test_document_magic_filename_review(self, client):
        r = client.post(
            "/api/v1/document/verify",
            files={"document": ("needs_review.pdf", PDF_BYTES,
                                "application/pdf")},
            data={"document_type": "drivers_license"},
            headers=AUTH)
        body = r.json()
        assert body["status"] == "manual_review"
        assert body["detected_format"] == "pdf"

    def test_document_unknown_format_rejected(self, client):
        r = client.post(
            "/api/v1/document/verify",
            files={"document": ("notes.txt", b"plain text", "text/plain")},
            data={"document_type": "national_id"},
            headers=AUTH)
        body = r.json()
        assert body["detected_format"] == "unknown"
        assert body["structurally_valid"] is False
        assert body["status"] == "rejected"

    def test_document_empty_upload_422(self, client):
        r = client.post(
            "/api/v1/document/verify",
            files={"document": ("empty.png", b"", "image/png")},
            data={"document_type": "national_id"},
            headers=AUTH)
        assert r.status_code == 422

    def test_document_check_forgery_false(self, client):
        r = client.post(
            "/api/v1/document/verify",
            files={"document": ("id.png", PNG_BYTES, "image/png")},
            data={"document_type": "passport", "check_forgery": "false"},
            headers=AUTH)
        assert r.json()["forgery"] == {
            "performed": False, "reason": "check_forgery=false"}
