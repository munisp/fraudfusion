"""Tests for agent-banking onboarding: BVN reference-only capture, screening
hook fail-closed behavior, dual-control approval, status transitions.

Run: python3 -m pytest tests/test_agents.py -q
"""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

SUBMITTER = Principal(sub="ops-1", username="o1", roles=set())
REVIEWER = Principal(sub="admin-reviewer", username="ar", roles={"onboarding_admin"})
APPROVER = Principal(sub="admin-approver", username="aa", roles={"onboarding_admin"})

AGENT = {
    "agent_code": "AGT-0001",
    "full_name": "Kemi Agent",
    "principal_fintech": "FraudFusion MFB",
    "principal_reference": "PF-REF-12345",
    "bvn": "22345678901",
    "float_account_number": "0123456789",
    "float_account_bank": "058",
    "latitude": 6.5244,
    "longitude": 3.3792,
    "cbn_tier": "tier_2",
}


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "onb.db"))
    yield database
    reset_db_for_tests(None)


def make_client(db, principal):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def submit(db, principal=SUBMITTER, screening="unavailable"):
    """Submit an agent and force a screening outcome (the kyc-api hook is
    unavailable in unit tests; screening transitions are exercised via the
    rescreen path and direct updates)."""
    client = make_client(db, principal)
    resp = client.post("/api/v1/onboarding/agents", json=AGENT)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["screeningStatus"] == "unavailable"  # KYC_API_URL unset in tests
    db.execute(
        "UPDATE agent_applications SET screening_status = :st WHERE id = :id",
        {"st": screening, "id": body["id"]},
    )
    return body


class TestAgentSubmission:
    def test_bvn_stored_as_salted_hash_only(self, db):
        body = submit(db)
        row = db.query_one("SELECT * FROM agent_applications WHERE id = :id", {"id": body["id"]})
        assert AGENT["bvn"] not in str(row.values())
        assert row["bvn_hash"] == hashlib.sha256((row["bvn_salt"] + AGENT["bvn"]).encode()).hexdigest()
        assert row["bvn_hash"] != hashlib.sha256(AGENT["bvn"].encode()).hexdigest()  # salted

    def test_duplicate_agent_code_409(self, db):
        submit(db)
        client = make_client(db, SUBMITTER)
        resp = client.post("/api/v1/onboarding/agents", json=AGENT)
        assert resp.status_code == 409

    def test_validation_rejects_bad_bvn_and_geo(self, db):
        client = make_client(db, SUBMITTER)
        bad = dict(AGENT, bvn="123")
        assert client.post("/api/v1/onboarding/agents", json=bad).status_code == 422
        bad = dict(AGENT, latitude=91.0)
        assert client.post("/api/v1/onboarding/agents", json=bad).status_code == 422
        bad = dict(AGENT, cbn_tier="tier_9")
        assert client.post("/api/v1/onboarding/agents", json=bad).status_code == 422


class TestDualControl:
    def test_full_dual_control_lifecycle(self, db):
        body = submit(db, screening="clear")
        agent_id = body["id"]
        assert body["status"] == "screening"

        reviewer = make_client(db, REVIEWER)
        reviewed = reviewer.post(f"/api/v1/onboarding/admin/agents/{agent_id}/review")
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["status"] == "pending_approval"
        assert reviewed.json()["reviewedBy"] == "admin-reviewer"

        approver = make_client(db, APPROVER)
        approved = approver.post(f"/api/v1/onboarding/admin/agents/{agent_id}/approve")
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["approvedBy"] == "admin-approver"

    def test_submitter_cannot_approve(self, db):
        body = submit(db, screening="clear")
        agent_id = body["id"]
        submitter_admin = make_client(db, Principal(sub="ops-1", username="o1",
                                                    roles={"onboarding_admin"}))
        resp = submitter_admin.post(f"/api/v1/onboarding/admin/agents/{agent_id}/approve")
        assert resp.status_code == 409
        assert "dual control" in resp.json()["detail"]

    def test_reviewer_cannot_approve(self, db):
        body = submit(db, screening="clear")
        agent_id = body["id"]
        reviewer = make_client(db, REVIEWER)
        reviewer.post(f"/api/v1/onboarding/admin/agents/{agent_id}/review")
        resp = reviewer.post(f"/api/v1/onboarding/admin/agents/{agent_id}/approve")
        assert resp.status_code == 409
        assert "dual control" in resp.json()["detail"]

    def test_approval_blocked_until_screening_clear(self, db):
        body = submit(db, screening="unavailable")
        agent_id = body["id"]
        reviewer = make_client(db, REVIEWER)
        reviewer.post(f"/api/v1/onboarding/admin/agents/{agent_id}/review")
        approver = make_client(db, APPROVER)
        resp = approver.post(f"/api/v1/onboarding/admin/agents/{agent_id}/approve")
        assert resp.status_code == 409
        assert "screening" in resp.json()["detail"]

    def test_approval_requires_admin(self, db):
        body = submit(db, screening="clear")
        other = make_client(db, Principal(sub="rando", username="r", roles=set()))
        resp = other.post(f"/api/v1/onboarding/admin/agents/{body['id']}/approve")
        assert resp.status_code == 403


class TestTransitions:
    def test_terminal_rejected_cannot_transition(self, db):
        body = submit(db)
        reviewer = make_client(db, REVIEWER)
        rejected = reviewer.post(f"/api/v1/onboarding/admin/agents/{body['id']}/reject",
                                 json={"reason": "bad documents"})
        assert rejected.json()["status"] == "rejected"
        resp = reviewer.post(f"/api/v1/onboarding/admin/agents/{body['id']}/review")
        assert resp.status_code == 409

    def test_approve_from_screening_directly_is_illegal(self, db):
        body = submit(db, screening="clear")
        approver = make_client(db, APPROVER)
        resp = approver.post(f"/api/v1/onboarding/admin/agents/{body['id']}/approve")
        assert resp.status_code == 409  # must be reviewed first
