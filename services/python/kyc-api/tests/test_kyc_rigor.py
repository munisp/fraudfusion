"""Tests for Round 7 Lane I2 KYC rigor additions:

  * Task 1 — recycled phone-number risk (PhoneTenureAdapter, fail-closed).
  * Task 2 — address-verification method/recency tracking + triggered reviews.
  * Task 4 — counterparty verification-rigor registry + risk-gap flag wiring.

Run: python3 -m pytest tests/test_kyc_rigor.py -q
"""

from __future__ import annotations

import pytest
import httpx
from fastapi.testclient import TestClient

from app import phone_tenure
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.identity import luhn_checksum_ok
from app.main import create_app
from app.phone_tenure import (
    HTTPTenureAdapter,
    UnavailablePhoneTenureAdapter,
    assess_recycled_number,
)
from app.tiers import address_review_required, validate_address_evidence

OPERATOR = Principal(sub="kyc-ops-1", username="ops", roles={"kyc_operator"})
ADMIN = Principal(sub="kyc-admin-1", username="adm", roles={"kyc_operator", "kyc_admin"})


def valid_bvn() -> str:
    base = "2234567890"
    for d in range(10):
        candidate = base + str(d)
        if luhn_checksum_ok(candidate):
            return candidate
    raise AssertionError("no luhn-valid suffix found")


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "kyc.db"))
    yield database
    reset_db_for_tests(None)


def make_client(db, principal=OPERATOR):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def basic_payload(**overrides):
    payload = {
        "customer_id": "cust-1",
        "bvn": valid_bvn(),
        "first_name": "Adaeze",
        "last_name": "Eze",
        "date_of_birth": "1990-05-20",
        "phone": "+2348012345678",
    }
    payload.update(overrides)
    return payload


def feed_adapter(body: dict | None = None, status_code: int = 200,
                 raise_error: bool = False) -> HTTPTenureAdapter:
    """HTTPTenureAdapter backed by an httpx MockTransport feed."""

    def handler(request: httpx.Request) -> httpx.Response:
        if raise_error:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(status_code, json=body or {})

    return HTTPTenureAdapter("http://telco-feed.test",
                             transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# Task 1 — recycled-number risk
# ---------------------------------------------------------------------------

class TestPhoneTenureAdapter:
    def test_unconfigured_adapter_fails_closed(self, monkeypatch):
        monkeypatch.delenv("TELCO_TENURE_URL", raising=False)
        adapter = phone_tenure.get_phone_tenure_adapter()
        assert isinstance(adapter, UnavailablePhoneTenureAdapter)
        result = adapter.lookup("+2348012345678")
        assert result["status"] == "unavailable"
        assert result["phone_checked"] is False

    def test_http_error_fails_closed(self):
        adapter = feed_adapter(raise_error=True)
        result = adapter.lookup("+2348012345678")
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]

    def test_http_non_200_fails_closed(self):
        adapter = feed_adapter(status_code=500)
        assert adapter.lookup("+2348012345678")["status"] == "unavailable"

    def test_feed_positive_recycled(self):
        adapter = feed_adapter({"number_age_days": 30, "reassigned_recently": True,
                                "prior_owner_linked_accounts": 2})
        result = adapter.lookup("+2348012345678")
        assert result["status"] == "ok"
        assert result["number_age_days"] == 30
        assert result["prior_owner_linked_accounts"] == 2

    def test_assessment_window_boundary(self):
        # Boundary is inclusive: age == window (default 180d) still counts as
        # recently reassigned; one day beyond does not.
        recycled = assess_recycled_number(
            "+2348012345678", adapter=feed_adapter({"number_age_days": 180}))
        assert recycled["state"] == "recycled"
        assert recycled["recycled_number_risk"] is True
        assert recycled["risk_contribution"] == pytest.approx(0.15)

        clean = assess_recycled_number(
            "+2348012345678", adapter=feed_adapter({"number_age_days": 181}))
        assert clean["state"] == "verified_clean"
        assert clean["recycled_number_risk"] is False
        assert clean["risk_contribution"] == 0.0

    def test_assessment_prior_owner_links_add_contribution(self):
        result = assess_recycled_number(
            "+2348012345678",
            adapter=feed_adapter({"number_age_days": 400, "reassigned_recently": False,
                                  "prior_owner_linked_accounts": 3}))
        # old number (not recycled) but prior owner's accounts still linked
        assert result["recycled_number_risk"] is False
        assert result["risk_contribution"] == pytest.approx(0.10)

    def test_assessment_unavailable_feed_is_unverified_not_clean(self):
        result = assess_recycled_number("+2348012345678",
                                        adapter=UnavailablePhoneTenureAdapter())
        assert result["state"] == "unverified"
        assert result["recycled_number_risk"] is False
        assert result["risk_contribution"] == pytest.approx(0.05)

    def test_assessment_no_phone(self):
        assert assess_recycled_number(None)["state"] == "not_provided"

    def test_onboarding_flow_marks_recycled_number(self, db, monkeypatch):
        monkeypatch.setattr(
            phone_tenure, "get_phone_tenure_adapter",
            lambda: feed_adapter({"number_age_days": 10, "reassigned_recently": True,
                                  "prior_owner_linked_accounts": 0}))
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 200, resp.text
        tenure = resp.json()["verification_results"]["phone_tenure"]
        assert tenure["state"] == "recycled"
        assert tenure["recycled_number_risk"] is True

    def test_onboarding_flow_unverified_when_feed_absent(self, db, monkeypatch):
        monkeypatch.delenv("TELCO_TENURE_URL", raising=False)
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 200, resp.text
        tenure = resp.json()["verification_results"]["phone_tenure"]
        assert tenure["state"] == "unverified"
        # risk went up by exactly the honest-degradation contribution
        assert resp.json()["risk_score"] == pytest.approx(0.15)


# ---------------------------------------------------------------------------
# Task 2 — address-verification tracking
# ---------------------------------------------------------------------------

class TestAddressEvidenceModel:
    def test_validate_method_and_date(self):
        rec = validate_address_evidence("physical_visit", "2026-08-01")
        assert rec["method"] == "physical_visit"
        assert rec["verified_at"].startswith("2026-08-01")
        with pytest.raises(ValueError):
            validate_address_evidence("ouija_board", "2026-08-01")
        with pytest.raises(ValueError):
            validate_address_evidence("physical_visit", "not-a-date")

    def test_stale_evidence_requires_review(self):
        review = address_review_required("tier_1", "physical_visit", "2000-01-01")
        assert review["required"] is True
        assert any("stale" in r for r in review["reasons"])

    def test_electronic_only_weak_at_tier_2(self):
        review = address_review_required("tier_2", "electronic", "2999-01-01")
        assert review["required"] is True
        assert any("electronic_only" in r for r in review["reasons"])
        # tier_1 with fresh electronic evidence is acceptable
        assert address_review_required("tier_1", "electronic", "2999-01-01")["required"] is False

    def test_tier_2_without_evidence_requires_review(self):
        review = address_review_required("tier_2", None, None)
        assert review["required"] is True
        assert "no_address_evidence" in review["reasons"]

    def test_fresh_physical_visit_ok(self):
        review = address_review_required("tier_3", "physical_visit", "2999-01-01")
        assert review["required"] is False


class TestAddressVerificationFlow:
    def test_stale_address_schedules_triggered_review(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/enhanced", json=basic_payload(
            customer_id="cust-addr",
            address_evidence={"method": "physical_visit", "verified_at": "2020-01-01"},
        ))
        assert resp.status_code == 200, resp.text
        addr = resp.json()["verification_results"]["address_verification"]
        assert addr["required"] is True
        assert addr["method"] == "physical_visit"
        row = db.query_one(
            "SELECT * FROM kyc_review_schedule WHERE customer_id = 'cust-addr'"
            " AND review_type = 'triggered'")
        assert row is not None
        assert "address_reverification" in row["reason"]

    def test_fresh_physical_visit_no_review(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/enhanced", json=basic_payload(
            customer_id="cust-fresh",
            address_evidence={"method": "physical_visit", "verified_at": "2999-01-01"},
        ))
        assert resp.status_code == 200, resp.text
        addr = resp.json()["verification_results"]["address_verification"]
        assert addr["required"] is False
        assert db.query_one(
            "SELECT * FROM kyc_review_schedule WHERE customer_id = 'cust-fresh'"
            " AND review_type = 'triggered'") is None

    def test_tier_2_no_evidence_schedules_review(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/enhanced",
                           json=basic_payload(customer_id="cust-noaddr"))
        assert resp.status_code == 200, resp.text
        addr = resp.json()["verification_results"]["address_verification"]
        assert addr["required"] is True
        assert "no_address_evidence" in addr["reasons"]

    def test_status_response_exposes_address_recency(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/enhanced", json=basic_payload(
            customer_id="cust-status",
            address_evidence={"method": "utility_bill", "verified_at": "2026-01-01"},
        ))
        rid = resp.json()["request_id"]
        status = client.get(f"/api/v1/kyc/status/{rid}")
        assert status.status_code == 200, status.text
        addr = status.json()["address_verification"]
        assert addr["method"] == "utility_bill"
        assert addr["verified_at"].startswith("2026-01-01")
        assert addr["age_days"] is not None and addr["age_days"] > 90
        assert addr["required"] is True


# ---------------------------------------------------------------------------
# Task 4 — counterparty verification-rigor registry
# ---------------------------------------------------------------------------

class TestCounterpartyRigor:
    def test_upsert_requires_admin_role(self, db):
        client = make_client(db, OPERATOR)
        resp = client.post("/api/v1/kyc/admin/counterparty-rigor", json={
            "institution_code": "058", "institution_name": "GTBank",
            "rigor_level": "cbn_full_biometric", "source_note": "CBN audit 2026-Q2",
        })
        assert resp.status_code == 403

    def test_upsert_and_lookup(self, db):
        admin = make_client(db, ADMIN)
        resp = admin.post("/api/v1/kyc/admin/counterparty-rigor", json={
            "institution_code": "999", "institution_name": "Skipsure MFB",
            "rigor_level": "unverified",
            "source_note": "field audit: no biometric BVN check at account opening",
        })
        assert resp.status_code == 201, resp.text
        assert resp.json()["rigor_level"] == "unverified"
        look = make_client(db).get("/api/v1/kyc/counterparty-rigor/999")
        assert look.status_code == 200
        assert look.json()["source"] == "registry"
        # upsert is idempotent on institution_code
        admin.post("/api/v1/kyc/admin/counterparty-rigor", json={
            "institution_code": "999", "institution_name": "Skipsure MFB",
            "rigor_level": "cbn_basic", "source_note": "remediated partially",
        })
        assert make_client(db).get("/api/v1/kyc/counterparty-rigor/999").json()[
            "rigor_level"] == "cbn_basic"

    def test_unknown_institution_fails_closed(self, db):
        look = make_client(db).get("/api/v1/kyc/counterparty-rigor/NOPE")
        assert look.status_code == 200
        body = look.json()
        assert body["rigor_level"] == "unknown"
        assert body["source"] == "default_unknown"
        assert "failing closed" in body["reason"]

    def test_risk_assess_flags_unverified_counterparty(self, db):
        admin = make_client(db, ADMIN)
        admin.post("/api/v1/kyc/admin/counterparty-rigor", json={
            "institution_code": "777", "institution_name": "Weakbank",
            "rigor_level": "unverified", "source_note": "skips CBN biometric BVN",
        })
        client = make_client(db)
        resp = client.post("/api/v1/risk/assess",
                           json={"amount_ngn": 1000, "counterparty_institution": "777"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["counterparty_verification_gap"] is True
        assert body["counterparty_rigor"]["rigor_level"] == "unverified"
        assert body["risk_score"] == pytest.approx(0.10 + 0.15)
        assert any("counterparty_verification_gap" in f for f in body["factors"])

    def test_risk_assess_unknown_counterparty_contributes(self, db):
        client = make_client(db)
        body = client.post("/api/v1/risk/assess", json={
            "amount_ngn": 1000, "counterparty_institution": "UNLISTED"}).json()
        assert body["counterparty_verification_gap"] is True
        assert body["counterparty_rigor"]["rigor_level"] == "unknown"
        assert body["risk_score"] == pytest.approx(0.10 + 0.10)

    def test_risk_assess_strong_counterparty_no_flag(self, db):
        admin = make_client(db, ADMIN)
        admin.post("/api/v1/kyc/admin/counterparty-rigor", json={
            "institution_code": "058", "institution_name": "GTBank",
            "rigor_level": "cbn_full_biometric", "source_note": "CBN audit",
        })
        body = make_client(db).post("/api/v1/risk/assess", json={
            "amount_ngn": 1000, "counterparty_institution": "058"}).json()
        assert body["counterparty_verification_gap"] is False
        assert body["risk_score"] == pytest.approx(0.10)

    def test_fraud_check_flags_unverified_counterparty(self, db):
        admin = make_client(db, ADMIN)
        admin.post("/api/v1/kyc/admin/counterparty-rigor", json={
            "institution_code": "777", "institution_name": "Weakbank",
            "rigor_level": "unverified", "source_note": "skips biometric BVN",
        })
        body = make_client(db).post("/api/v1/risk/fraud-check", json={
            "customer_id": "cust-1",
            "transaction_data": {"amount_ngn": 5000, "counterparty_institution": "777"},
        }).json()
        assert body["counterparty_verification_gap"] is True
        assert body["fraud_score"] == pytest.approx(0.10 + 0.15)
