"""Tests for enrollment-agent integrity scoring (Round 7 Lane I2 Task 3):

  * Beta-Binomial smoothing sanity (1/1 fraud is NOT a 100% score; a new
    agent sits at the documented prior mean).
  * Alert threshold flag on sufficient data.
  * k-anonymity suppression ('insufficient_data') below the minimum
    enrollment count.

Run: python3 -m pytest tests/test_agent_integrity.py -q
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import agents
from app.agents import compute_integrity
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

SUBMITTER = Principal(sub="ops-1", username="o1", roles=set())

AGENT = {
    "agent_code": "AGT-9001",
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


def make_client(db, principal=SUBMITTER):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def submit_agent(db) -> str:
    client = make_client(db)
    resp = client.post("/api/v1/onboarding/agents", json=AGENT)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def record(client, agent_id, n_clean=0, n_flagged=0, n_fraud=0):
    ref = 0
    for outcome, n in (("clean", n_clean), ("flagged", n_flagged),
                       ("confirmed_fraud", n_fraud)):
        for _ in range(n):
            ref += 1
            resp = client.post(f"/api/v1/onboarding/agents/{agent_id}/outcomes",
                               json={"customer_ref": f"cust-{ref}", "outcome": outcome})
            assert resp.status_code == 201, resp.text


class TestOutcomeRecording:
    def test_record_outcome(self, db):
        agent_id = submit_agent(db)
        client = make_client(db)
        resp = client.post(f"/api/v1/onboarding/agents/{agent_id}/outcomes",
                           json={"customer_ref": "cust-1", "outcome": "clean"})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["agentId"] == agent_id
        assert body["outcome"] == "clean"
        row = db.query_one("SELECT * FROM agent_outcomes WHERE agent_id = :a",
                           {"a": agent_id})
        assert row["customer_ref"] == "cust-1"

    def test_outcome_unknown_agent_404(self, db):
        client = make_client(db)
        resp = client.post("/api/v1/onboarding/agents/nobody/outcomes",
                           json={"customer_ref": "cust-1", "outcome": "clean"})
        assert resp.status_code == 404

    def test_outcome_rejects_bad_value(self, db):
        agent_id = submit_agent(db)
        client = make_client(db)
        resp = client.post(f"/api/v1/onboarding/agents/{agent_id}/outcomes",
                           json={"customer_ref": "cust-1", "outcome": "meh"})
        assert resp.status_code == 422


class TestSmoothing:
    def test_new_agent_sits_at_prior(self):
        # With no data the posterior mean equals the prior mean 2/(2+18)=0.10
        # (min_enrollments=0 disables the k-anonymity guard for this check).
        result = compute_integrity(enrollments=0, fraud_weight=0.0, min_enrollments=0)
        assert result["fraud_rate"] == pytest.approx(0.10)

    def test_one_of_one_fraud_is_not_extreme(self):
        # 1 enrollment, 1 confirmed fraud -> (1+2)/(1+20) = 0.1429, NOT 100%.
        result = compute_integrity(enrollments=1, fraud_weight=1.0, min_enrollments=0)
        assert result["fraud_rate"] == pytest.approx(3 / 21, abs=1e-4)
        assert result["fraud_rate"] < 0.15
        assert result["alert"] is False

    def test_flagged_counts_half(self):
        # 10 flagged (weight 0.5 each) -> (5+2)/(10+20) = 0.2333
        result = compute_integrity(enrollments=10, fraud_weight=5.0)
        assert result["fraud_rate"] == pytest.approx(7 / 30, abs=1e-4)


class TestAlertAndSuppression:
    def test_alert_threshold_flag(self, db):
        agent_id = submit_agent(db)
        client = make_client(db)
        # 10 enrollments, 6 confirmed fraud -> (6+2)/30 = 0.2667 >= 0.25
        record(client, agent_id, n_clean=4, n_fraud=6)
        body = client.get(f"/api/v1/onboarding/agents/{agent_id}/integrity").json()
        assert body["status"] == "ok"
        assert body["alert"] is True
        assert body["fraudRate"] == pytest.approx(8 / 30, abs=1e-4)
        assert body["counts"]["confirmed_fraud"] == 6

    def test_below_threshold_no_alert(self, db):
        agent_id = submit_agent(db)
        client = make_client(db)
        # 10 enrollments, 5 confirmed fraud -> (5+2)/30 = 0.2333 < 0.25
        record(client, agent_id, n_clean=5, n_fraud=5)
        body = client.get(f"/api/v1/onboarding/agents/{agent_id}/integrity").json()
        assert body["status"] == "ok"
        assert body["alert"] is False

    def test_small_agent_suppressed(self, db):
        agent_id = submit_agent(db)
        client = make_client(db)
        record(client, agent_id, n_fraud=3)  # 3/3 fraud — still suppressed
        body = client.get(f"/api/v1/onboarding/agents/{agent_id}/integrity").json()
        assert body["status"] == "insufficient_data"
        assert body["fraudRate"] is None
        assert body["alert"] is False
        assert body["enrollments"] == 3
        # k-anonymity: counts breakdown is suppressed too (it would let a
        # caller derive the rate).
        assert body["counts"] == {}

    def test_min_enrollments_boundary(self, db):
        agent_id = submit_agent(db)
        client = make_client(db)
        record(client, agent_id, n_clean=agents.MIN_ENROLLMENTS_FOR_EXPOSURE)
        body = client.get(f"/api/v1/onboarding/agents/{agent_id}/integrity").json()
        assert body["status"] == "ok"
        # all clean: (0+2)/(10+20) = 0.0667 — below the prior mean, as expected
        assert body["fraudRate"] == pytest.approx(2 / 30, abs=1e-4)

    def test_integrity_unknown_agent_404(self, db):
        client = make_client(db)
        assert client.get("/api/v1/onboarding/agents/nobody/integrity").status_code == 404
