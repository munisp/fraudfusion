"""Tests for kyc-api additions: re-KYC flow, periodic review scheduler, and
the appeal flow with the independent-reviewer rule.

Run: python3 -m pytest tests/test_kyc_rekyc_appeals.py -q
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.identity import luhn_checksum_ok
from app.main import create_app

SUBMITTER = Principal(sub="reviewer-1", username="r1", roles={"kyc_operator"})
OTHER = Principal(sub="reviewer-2", username="r2", roles={"kyc_operator"})

PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


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


def make_client(db, principal=SUBMITTER):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def seed_request(db, customer_id="cust-1", decision="rejected", actor="reviewer-1"):
    """Directly seed a completed kyc request (verified requests are expensive
    to drive through the full pipeline in unit tests)."""
    import uuid

    rid = uuid.uuid4().hex
    db.execute(
        "INSERT INTO kyc_requests (id, customer_id, level, tier, status, decision,"
        " risk_score, risk_level, results_json, actor_sub, created_at, updated_at)"
        " VALUES (:id, :cid, 'basic', 'tier_1', 'completed', :dec, 0.9, 'high', '{}',"
        " :actor, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        {"id": rid, "cid": customer_id, "dec": decision, "actor": actor},
    )
    return rid


class TestRekyc:
    def test_rekyc_creates_pending_request_with_deadline(self, db):
        rid = seed_request(db, decision="approved")
        client = make_client(db)
        resp = client.post("/api/v1/kyc/cust-1/rekyc",
                           json={"reason": "expired CAC documents", "deadline_days": 14})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "pending"
        assert body["tier"] == "tier_1"
        assert body["supersedes"] == rid
        assert body["deadline"]
        row = db.query_one("SELECT * FROM kyc_requests WHERE id = :id",
                           {"id": body["rekyc_id"]})
        assert row["decision"] == "pending" and row["status"] == "received"
        assert row["rekyc_of"] == rid
        assert row["rekyc_reason"] == "expired CAC documents"
        assert row["rekyc_deadline"] == body["deadline"]
        # and a rekyc review is scheduled at the deadline
        sched = db.query_one(
            "SELECT * FROM kyc_review_schedule WHERE customer_id = 'cust-1' AND review_type = 'rekyc'")
        assert sched["due_at"] == body["deadline"]

    def test_rekyc_unknown_customer_404(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/nobody/rekyc", json={"reason": "periodic check"})
        assert resp.status_code == 404


class TestReviewScheduler:
    def test_due_reviews_listed_and_marked_overdue(self, db):
        db.execute(
            "INSERT INTO kyc_review_schedule (customer_id, review_type, tier, due_at)"
            " VALUES ('cust-1', 'periodic', 'tier_1', '2000-01-01T00:00:00')")
        db.execute(
            "INSERT INTO kyc_review_schedule (customer_id, review_type, tier, due_at)"
            " VALUES ('cust-2', 'periodic', 'tier_2', '2999-01-01T00:00:00')")
        client = make_client(db)
        resp = client.get("/api/v1/kyc/reviews/due")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["count"] == 1
        assert body["due"][0]["customer_id"] == "cust-1"
        # the overdue row is loudly marked, not silently pending
        row = db.query_one(
            "SELECT status FROM kyc_review_schedule WHERE customer_id = 'cust-1'")
        assert row["status"] == "overdue"

    def test_periodic_review_scheduled_on_verification(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json={
            "customer_id": "cust-sched",
            "bvn": valid_bvn(),
            "first_name": "Adaeze",
            "last_name": "Eze",
            "date_of_birth": "1990-05-20",
            "phone_number": "08012345678",
            "document_type": "nin",
            "document_file": base64.b64encode(PNG_BYTES).decode(),
        })
        assert resp.status_code == 200, resp.text
        row = db.query_one(
            "SELECT * FROM kyc_review_schedule WHERE customer_id = 'cust-sched'"
            " AND review_type = 'periodic'")
        assert row is not None
        assert row["tier"] in ("tier_1", "tier_2", "tier_3")
        assert row["status"] == "pending"


class TestAppeals:
    def test_appeal_lifecycle(self, db):
        rid = seed_request(db, decision="rejected", actor="reviewer-1")
        client = make_client(db, SUBMITTER)
        resp = client.post("/api/v1/kyc/cust-1/appeals",
                           json={"grounds": "valid international passport was provided"})
        assert resp.status_code == 201, resp.text
        appeal = resp.json()
        assert appeal["status"] == "pending"
        assert appeal["original_reviewer"] == "reviewer-1"

        status = client.get(f"/api/v1/kyc/appeals/{appeal['appeal_id']}")
        assert status.status_code == 200 and status.json()["status"] == "pending"

        # independent reviewer overturns
        decider = make_client(db, OTHER)
        dec = decider.post(f"/api/v1/kyc/appeals/{appeal['appeal_id']}/decision",
                           json={"decision": "overturned",
                                 "reason": "document verified on manual inspection"})
        assert dec.status_code == 200, dec.text
        assert dec.json()["status"] == "overturned"
        assert dec.json()["decided_by"] == "reviewer-2"
        # overturned routes the request back to manual review
        req = db.query_one("SELECT decision FROM kyc_requests WHERE id = :id", {"id": rid})
        assert req["decision"] == "manual_review"

    def test_original_reviewer_cannot_decide(self, db):
        rid = seed_request(db, decision="rejected", actor="reviewer-1")
        client = make_client(db, SUBMITTER)
        appeal = client.post("/api/v1/kyc/cust-1/appeals",
                             json={"grounds": "the address verification was wrong"}).json()
        # SUBMITTER == original reviewer here
        resp = client.post(f"/api/v1/kyc/appeals/{appeal['appeal_id']}/decision",
                           json={"decision": "overturned", "reason": "i disagree with myself"})
        assert resp.status_code == 409
        assert "independence" in resp.json()["detail"]
        # appeal remains pending
        assert db.query_one("SELECT status FROM kyc_appeals WHERE id = :id",
                            {"id": appeal["appeal_id"]})["status"] == "pending"

    def test_appeal_only_for_adverse_decisions(self, db):
        seed_request(db, decision="approved")
        client = make_client(db)
        resp = client.post("/api/v1/kyc/cust-1/appeals",
                           json={"grounds": "i want a better score anyway"})
        assert resp.status_code == 409

    def test_appeal_unknown_customer_404(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/kyc/nobody/appeals",
                           json={"grounds": "nothing exists here"})
        assert resp.status_code == 404
