"""Tests for the KYC API (SQLite backend, auth stubbed via overrides).

The fail-closed Keycloak path is tested separately in TestAuthFailClosed.

Run: python3 -m pytest tests/ -q   (from services/python/kyc-api)
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.identity import luhn_checksum_ok
from app.main import create_app
from app.tiers import assign_tier, check_transaction, TierAssignmentError

CALLER = Principal(sub="kyc-ops-1", username="ops", roles={"kyc_operator"})

# 1x1 PNG (valid magic bytes, tiny).
PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)
PDF_BYTES = b"%PDF-1.4 fake-but-structurally-pdf\n%%EOF\n" + b"0" * 2048


def valid_bvn() -> str:
    base = "2234567890"
    for d in range(10):
        candidate = base + str(d)
        if luhn_checksum_ok(candidate):
            return candidate
    raise AssertionError("no luhn-valid suffix found")


BVN = valid_bvn()


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "kyc.db"))
    yield database
    reset_db_for_tests(None)


def make_client(db, principal=CALLER):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def basic_payload(**overrides):
    payload = {
        "customer_id": "cust-1",
        "bvn": BVN,
        "first_name": "Adaeze",
        "last_name": "Eze",
        "date_of_birth": "1990-05-20",
        "phone": "+2348012345678",
    }
    payload.update(overrides)
    return payload


class TestTierStateMachine:
    def test_tier_limits_encoded(self):
        assert check_transaction("tier_1", 50_000)["allowed"] is True
        assert check_transaction("tier_1", 50_001)["allowed"] is False
        assert check_transaction("tier_1", 100_000, daily_total_ngn=250_000)["allowed"] is False
        assert check_transaction("tier_2", 200_000)["allowed"] is True
        assert check_transaction("tier_2", 200_001)["allowed"] is False
        assert check_transaction("tier_2", 300_000, daily_total_ngn=300_000)["allowed"] is False
        assert check_transaction("tier_3", 5_000_000)["allowed"] is True
        assert check_transaction("tier_3", 5_000_001)["allowed"] is False
        # tier 3 has no daily cap
        assert check_transaction("tier_3", 5_000_000, daily_total_ngn=900_000_000)["allowed"] is True

    def test_tier_assignment_requires_evidence(self):
        with pytest.raises(TierAssignmentError):
            assign_tier("basic", {"bvn_or_nin": False})
        with pytest.raises(TierAssignmentError) as exc:
            assign_tier("premium", {"bvn_or_nin": True, "id_document": True,
                                    "enhanced_due_diligence": False})
        assert "enhanced_due_diligence" in str(exc.value)
        limits = assign_tier("premium", {"bvn_or_nin": True, "id_document": True,
                                         "enhanced_due_diligence": True})
        assert limits.tier == "tier_3"


class TestKycVerification:
    def test_basic_verify_approved_tier1_with_limits(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["decision"] == "approved"
        assert body["verification_level"] == "basic"
        assert body["verification_results"]["tier"] == "tier_1"
        limits = body["verification_results"]["tier_limits_ngn"]
        assert limits["single_transaction"] == 50_000
        assert limits["daily"] == 300_000
        assert body["verification_results"]["bvn"]["registry_status"] == "unavailable"

    def test_basic_verify_without_bvn_or_nin_rejected_422(self, db):
        client = make_client(db)
        payload = basic_payload()
        del payload["bvn"]
        resp = client.post("/api/v1/kyc/verify/basic", json=payload)
        assert resp.status_code == 422
        assert "bvn_or_nin" in resp.json()["detail"]

    def test_invalid_bvn_checksum_rejects(self, db):
        client = make_client(db)
        bad = "12345678901"
        assert not luhn_checksum_ok(bad)
        # Valid NIN satisfies the tier-1 evidence requirement; the bad BVN
        # must then drive the decision to rejected (not an evidence 422).
        resp = client.post("/api/v1/kyc/verify/basic",
                           json=basic_payload(bvn=bad, nin="12345678901"))
        assert resp.status_code == 200, resp.text
        assert resp.json()["decision"] == "rejected"
        assert resp.json()["risk_level"] in ("high", "critical")

    def test_enhanced_verify_pep_fuzzy_match_manual_review(self, db):
        client = make_client(db)
        # Fuzzy variant of the seeded PEP "Ngozi Okonjo-Iweala".
        resp = client.post(
            "/api/v1/kyc/verify/enhanced",
            json=basic_payload(first_name="Ngozi", last_name="Okonjo Iweala",
                               nationality="NG"),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["verification_results"]["tier"] == "tier_2"
        pep = body["verification_results"]["pep_screening"]
        assert pep["is_pep"] is True
        assert pep["matches"][0]["score"] >= 0.85
        assert body["decision"] == "manual_review"

    def test_premium_verify_reports_credit_bureau_unavailable(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/kyc/verify/premium",
            json=basic_payload(nationality="NG", check_credit_bureau=True,
                               credit_bureau_provider="crc"),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["verification_results"]["tier"] == "tier_3"
        assert body["verification_results"]["tier_limits_ngn"]["single_transaction"] == 5_000_000
        assert body["verification_results"]["tier_limits_ngn"]["daily"] is None
        bureau = body["verification_results"]["credit_bureau"]
        assert bureau["status"] == "unavailable"
        assert bureau["score"] is None
        assert body["decision"] == "approved"

    def test_premium_requires_enhanced_due_diligence(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/kyc/verify/premium",
            json=basic_payload(nationality="NG", check_pep=False),
        )
        assert resp.status_code == 422
        assert "enhanced_due_diligence" in resp.json()["detail"]

    def test_status_roundtrip_and_404(self, db):
        client = make_client(db)
        created = client.post("/api/v1/kyc/verify/basic", json=basic_payload()).json()
        status = client.get(f"/api/v1/kyc/status/{created['request_id']}")
        assert status.status_code == 200
        assert status.json()["decision"] == "approved"
        assert status.json()["tier"] == "tier_1"
        assert client.get("/api/v1/kyc/status/does-not-exist").status_code == 404


class TestScreening:
    def test_pep_screening_endpoint(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/screening/pep", json={"full_name": "Ngozi Okonjo-Iweala"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_pep"] is True
        assert body["entries_screened"] >= 1

    def test_sanctions_screening_local_watchlist(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/screening/sanctions",
                           json={"full_name": "Sani Example Danladi"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["is_sanctioned"] is True
        assert body["live_feeds"] == "not_configured"

    def test_sanctions_clean_name_and_comprehensive(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/screening/comprehensive",
                           json={"full_name": "Adaeze Eze"})
        body = resp.json()
        assert body["sanctions"]["is_sanctioned"] is False
        assert body["pep"]["is_pep"] is False
        assert body["recommendation"] == "proceed"

    def test_watchlist_db_table_takes_precedence(self, db):
        db.execute(
            "INSERT INTO watchlist (id, full_name, program, source)"
            " VALUES ('w1', 'Database Listed Person', 'TEST-PROGRAM', 'test')"
        )
        client = make_client(db)
        body = client.post("/api/v1/screening/sanctions",
                           json={"full_name": "Database Listed Person"}).json()
        assert body["is_sanctioned"] is True
        assert body["list"] == "watchlist (database table)"


class TestBiometric:
    def test_verify_json_honest_unavailable(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/biometric/verify", json={
            "selfie_image_base64": base64.b64encode(PNG_BYTES).decode(),
            "check_liveness": True,
        })
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["face_match"]["performed"] is False
        assert body["face_match"]["score"] is None
        assert body["liveness"]["result"] == "not_evaluated"
        assert body["status"] == "manual_review"

    def test_verify_rejects_invalid_base64_and_unknown_format(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/biometric/verify",
                           json={"selfie_image_base64": "!!!not-base64!!!"})
        assert resp.status_code == 422
        resp = client.post("/api/v1/biometric/verify", json={
            "selfie_image_base64": base64.b64encode(b"\x00\x01\x02garbage").decode(),
        })
        assert resp.json()["status"] == "rejected"

    def test_face_match_upload_honest(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/biometric/face-match",
            files={"image1": ("a.png", PNG_BYTES, "image/png"),
                   "image2": ("b.png", PNG_BYTES, "image/png")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["performed"] is False
        assert body["match"] is None


class TestDocument:
    def test_document_verify_structural_checks(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/verify",
            files={"document": ("id.pdf", PDF_BYTES, "application/pdf")},
            data={"document_type": "international_passport", "check_forgery": "true"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["detected_format"] == "pdf"
        assert body["structurally_valid"] is True
        assert body["forgery"]["performed"] is True
        # Honest: no forgery model => no confidence score fabricated.
        assert body["forgery"]["confidence"] is None
        assert body["status"] == "manual_review"

    def test_document_verify_rejects_garbage(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/verify",
            files={"document": ("id.bin", b"\x00\xffgarbage", "application/octet-stream")},
            data={"document_type": "drivers_license"},
        )
        assert resp.json()["status"] == "rejected"

    def test_ocr_reports_unavailable(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/ocr",
            files={"document": ("id.pdf", PDF_BYTES, "application/pdf")},
            data={"document_type": "national_id"},
        )
        body = resp.json()
        assert body["status"] == "unavailable"
        assert body["extracted_fields"] == {}

    def test_quality_check_flags_tiny_file(self, db):
        client = make_client(db)
        resp = client.post(
            "/api/v1/document/quality-check",
            files={"document": ("id.png", PNG_BYTES, "image/png")},
        )
        assert resp.json()["quality"] == "poor"  # <1KB


class TestCreditBureau:
    def test_check_reports_unavailable_honestly(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/credit-bureau/check", json={
            "bvn": BVN, "first_name": "Adaeze", "last_name": "Eze", "provider": "crc",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "unavailable"
        assert body["score"] is None

    def test_unknown_provider_422_and_bad_bvn_422(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/credit-bureau/check", json={
            "bvn": BVN, "first_name": "A", "last_name": "B", "provider": "experian",
        })
        assert resp.status_code == 422
        resp = client.post("/api/v1/credit-bureau/score-only", json={
            "bvn": "12345678901", "first_name": "A", "last_name": "B",
        })
        assert resp.status_code == 422


class TestRisk:
    def test_assess_large_amount_elevates(self, db):
        client = make_client(db)
        body = client.post("/api/v1/risk/assess",
                           json={"amount_ngn": 6_000_000, "country": "NG"}).json()
        assert body["risk_score"] >= 0.4
        assert body["model"] == "rules"

    def test_fraud_check_velocity_and_amount_ratio(self, db):
        client = make_client(db)
        history = [{"amount_ngn": 10_000} for _ in range(25)]
        body = client.post("/api/v1/risk/fraud-check", json={
            "customer_id": "cust-1",
            "transaction_data": {"amount_ngn": 500_000, "channel": "card_not_present"},
            "historical_data": history,
        }).json()
        assert body["is_fraud_suspected"] is True
        assert len(body["factors"]) >= 3

    def test_behavioral_analysis_flags_failed_logins(self, db):
        client = make_client(db)
        body = client.post("/api/v1/risk/behavioral-analysis", json={
            "customer_id": "cust-1",
            "behavioral_data": {"failed_logins_24h": 7, "new_device": True, "login_hour": 3},
        }).json()
        assert body["anomalous"] is True


class TestAuthFailClosed:
    def test_missing_bearer_is_401(self, db, monkeypatch):
        import app.auth as auth_mod
        monkeypatch.setattr(auth_mod, "KEYCLOAK_URL", "https://keycloak.example")
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db  # auth NOT overridden
        client = TestClient(app)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 401

    def test_no_keycloak_configured_is_503(self, db, monkeypatch):
        import app.auth as auth_mod
        monkeypatch.setattr(auth_mod, "KEYCLOAK_URL", "")
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        client = TestClient(app, headers={"Authorization": "Bearer x"})
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 503

    def test_insecure_http_keycloak_rejected(self, db, monkeypatch):
        import app.auth as auth_mod
        monkeypatch.setattr(auth_mod, "KEYCLOAK_URL", "http://keycloak:8080")
        monkeypatch.delenv("KEYCLOAK_INSECURE_HTTP", raising=False)
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        client = TestClient(app, headers={"Authorization": "Bearer x"})
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 503
