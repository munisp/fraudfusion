"""Tests for backoffice-api: fail-closed auth, dual-control KYC override,
fraud alert state machine, hash-chained audit ledger, journey admin,
session revocation.

Run: python3 -m pytest tests/ -q   (from services/python/backoffice-api)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, get_principal
from app.audit import append_event, verify_chain
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

OPS = Principal(sub="ops-1", email="ops@ff.io", name="Ops One",
                roles={"backoffice_ops"}, tenant_id="default", jti="jti-ops", iat=100)
ADMIN = Principal(sub="admin-1", email="admin@ff.io", name="Admin One",
                  roles={"admin", "backoffice_admin"}, tenant_id="default", jti="jti-adm", iat=100)


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "bo.db"))
    yield database
    reset_db_for_tests(None)


def make_client(db, principal=OPS):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_principal] = lambda: principal
    return TestClient(app, raise_server_exceptions=False)


def seed_alert(db, status="open", alert_id="al-1"):
    db.execute(
        "INSERT INTO fraud_alerts (id, alert_type, severity, status, customer_id,"
        " customer_name, description, amount, currency, risk_score, indicators)"
        " VALUES (:id, 'identity', 'high', :st, 'cust-1', 'Ada Eze', 'BVN mismatch',"
        " 50000, 'NGN', 0.82, '[\"bvn_mismatch\", \"velocity\"]')",
        {"id": alert_id, "st": status},
    )


def seed_review(db, status="pending", rid="rev-1"):
    db.execute(
        "INSERT INTO document_reviews (id, document_id, document_type, status, customer_id,"
        " customer_name, submitter_id, risk_score) VALUES (:id, 'doc-1', 'c_of_o', :st,"
        " 'cust-1', 'Ada Eze', 'ops-9', 0.4)",
        {"id": rid, "st": status},
    )


def seed_kyc(db, rid="kyc-1", actor="kyc-submitter", decision="manual_review"):
    db.execute(
        "INSERT INTO kyc_requests (id, customer_id, level, tier, status, decision,"
        " risk_score, risk_level, actor_sub) VALUES (:id, 'cust-1', 'enhanced', 'tier_2',"
        " 'completed', :dec, 0.6, 'medium', :actor)",
        {"id": rid, "dec": decision, "actor": actor},
    )


def seed_journey(db, eid="exec-1", status="failed"):
    db.execute(
        "INSERT INTO journey_executions (id, journey_id, journey_name, customer_id, status,"
        " current_step, total_steps) VALUES (:id, 34, 'Double Allocation', 'cust-1', :st,"
        " 2, 5)",
        {"id": eid, "st": status},
    )
    db.execute(
        "INSERT INTO journey_steps (execution_id, step_number, name, status, error)"
        " VALUES (:id, 1, 'document_analysis', 'completed', NULL)",
        {"id": eid},
    )
    db.execute(
        "INSERT INTO journey_steps (execution_id, step_number, name, status, error)"
        " VALUES (:id, 2, 'detect_claimants', 'failed', 'timeout')",
        {"id": eid},
    )


class TestAuth:
    def test_fail_closed_without_keycloak(self, db, monkeypatch):
        import app.auth as auth_mod

        monkeypatch.setattr(auth_mod, "KEYCLOAK_URL", "")
        client = TestClient(create_app(), raise_server_exceptions=False)
        resp = client.get("/api/v1/backoffice/dashboard/stats")
        assert resp.status_code == 503

    def test_login_fail_closed_without_keycloak(self, db, monkeypatch):
        import app.auth as auth_mod
        import app.main as main_mod

        monkeypatch.setattr(main_mod, "KEYCLOAK_URL", "")
        client = TestClient(create_app(), raise_server_exceptions=False)
        resp = client.post("/api/v1/auth/login",
                           json={"email": "a@b.c", "password": "x"})
        assert resp.status_code == 503


class TestKycOverrideDualControl:
    def test_override_by_independent_approver(self, db):
        seed_kyc(db)
        client = make_client(db, OPS)
        resp = client.post("/api/v1/backoffice/kyc/verifications/kyc-1/override",
                           json={"decision": "approve", "reason": "documents verified"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "approved"
        assert body["reviewed_by"] == "ops-1"
        row = db.query_one("SELECT * FROM kyc_requests WHERE id = 'kyc-1'")
        assert row["override_by"] == "ops-1"
        assert row["override_reason"] == "documents verified"
        # mutation is audit-logged in the hash chain
        logs = db.query("SELECT * FROM backoffice_audit_ledger")
        assert len(logs) == 1 and logs[0]["action"] == "override_approve"
        assert verify_chain(db)["intact"] is True

    def test_submitter_cannot_override(self, db):
        seed_kyc(db, actor="ops-1")  # OPS principal IS the submitter
        client = make_client(db, OPS)
        resp = client.post("/api/v1/backoffice/kyc/verifications/kyc-1/override",
                           json={"decision": "approve", "reason": "i approve myself"})
        assert resp.status_code == 409
        assert "dual control" in resp.json()["detail"]
        row = db.query_one("SELECT decision FROM kyc_requests WHERE id = 'kyc-1'")
        assert row["decision"] == "manual_review"

    def test_override_requires_ops_role(self, db):
        seed_kyc(db)
        viewer = Principal(sub="viewer", roles=set(), tenant_id="default", jti="j", iat=1)
        client = make_client(db, viewer)
        resp = client.post("/api/v1/backoffice/kyc/verifications/kyc-1/override",
                           json={"decision": "reject", "reason": "nope nope nope"})
        assert resp.status_code == 403

    def test_list_verifications_scoped_to_tenant(self, db):
        seed_kyc(db)
        db.execute(
            "INSERT INTO kyc_requests (id, tenant_id, customer_id, level, tier, status,"
            " decision, actor_sub) VALUES ('kyc-other', 'tenant-b', 'cust-9', 'basic',"
            " 'tier_1', 'completed', 'approved', 'x')")
        client = make_client(db)
        body = client.get("/api/v1/backoffice/kyc/verifications").json()
        assert body["total"] == 1
        assert body["verifications"][0]["id"] == "kyc-1"


class TestFraudAlerts:
    def test_alert_lifecycle_and_audit(self, db):
        seed_alert(db)
        client = make_client(db, ADMIN)
        resp = client.post("/api/v1/backoffice/fraud/alerts/al-1/status",
                           json={"status": "investigating"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "investigating"
        assert resp.json()["assigned_to"] == "admin-1"  # self-assign on investigate

        resp = client.post("/api/v1/backoffice/fraud/alerts/al-1/status",
                           json={"status": "false_positive", "note": "legitimate customer"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "false_positive"

        # terminal state: no further transitions
        resp = client.post("/api/v1/backoffice/fraud/alerts/al-1/status",
                           json={"status": "investigating"})
        assert resp.status_code == 409

        logs = db.query("SELECT action FROM backoffice_audit_ledger ORDER BY id")
        assert [l["action"] for l in logs] == ["investigating", "false_positive"]

    def test_illegal_open_to_resolved(self, db):
        seed_alert(db)
        client = make_client(db)
        resp = client.post("/api/v1/backoffice/fraud/alerts/al-1/status",
                           json={"status": "resolved"})
        assert resp.status_code == 409

    def test_list_filters_and_shape(self, db):
        seed_alert(db, alert_id="al-1")
        seed_alert(db, alert_id="al-2")
        db.execute("UPDATE fraud_alerts SET severity = 'critical' WHERE id = 'al-2'")
        client = make_client(db)
        body = client.get("/api/v1/backoffice/fraud/alerts", params={"severity": "critical"}).json()
        assert body["total"] == 1 and body["alerts"][0]["id"] == "al-2"
        alert = body["alerts"][0]
        # UI contract fields (backoffice-ui types/index.ts FraudAlertView)
        assert set(alert) >= {"id", "type", "severity", "status", "customer_id",
                              "risk_score", "indicators", "created_at"}
        assert alert["indicators"] == ["bvn_mismatch", "velocity"]


class TestDocumentReviews:
    def test_decision_state_machine(self, db):
        seed_review(db)
        client = make_client(db)
        # assign moves pending -> in_review
        resp = client.post("/api/v1/backoffice/documents/reviews/rev-1/assign",
                           json={"reviewer_id": "ops-1"})
        assert resp.status_code == 200 and resp.json()["status"] == "in_review"
        resp = client.post("/api/v1/backoffice/documents/reviews/decision",
                           json={"review_id": "rev-1", "decision": "rejected",
                                 "reason": "forged survey plan"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "rejected"
        # terminal
        resp = client.post("/api/v1/backoffice/documents/reviews/decision",
                           json={"review_id": "rev-1", "decision": "approved",
                                 "reason": "changed my mind"})
        assert resp.status_code == 409

    def test_image_404_when_absent_and_served_when_present(self, db):
        seed_review(db)
        client = make_client(db)
        assert client.get("/api/v1/backoffice/documents/doc-1/image").status_code == 404
        db.execute(
            "INSERT INTO document_store (document_id, content_type, content)"
            " VALUES ('doc-1', 'image/png', X'89504E47')")
        resp = client.get("/api/v1/backoffice/documents/doc-1/image")
        assert resp.status_code == 200
        assert resp.content == b"\x89PNG"


class TestJourneys:
    def test_retry_failed_step(self, db):
        seed_journey(db)
        client = make_client(db)
        resp = client.post("/api/v1/backoffice/journeys/executions/exec-1/retry",
                           json={"step_number": 2})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "running"
        step2 = [s for s in body["steps"] if s["step_number"] == 2][0]
        assert step2["status"] == "pending" and step2["error"] is None

    def test_retry_only_failed_steps(self, db):
        seed_journey(db)
        client = make_client(db)
        resp = client.post("/api/v1/backoffice/journeys/executions/exec-1/retry",
                           json={"step_number": 1})
        assert resp.status_code == 409

    def test_cancel_running_and_terminal_conflict(self, db):
        seed_journey(db, status="running")
        client = make_client(db)
        resp = client.post("/api/v1/backoffice/journeys/executions/exec-1/cancel",
                           json={"reason": "duplicate execution"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"
        again = client.post("/api/v1/backoffice/journeys/executions/exec-1/cancel",
                            json={"reason": "again"})
        assert again.status_code == 409


class TestAuditLedger:
    def test_hash_chain_integrity_and_tamper_detection(self, db):
        for i in range(3):
            append_event(db, tenant_id="default", event_type="test", actor_id="ops-1",
                         resource_type="doc", resource_id=f"d-{i}", action="create")
        assert verify_chain(db)["intact"] is True
        assert verify_chain(db)["entries"] == 3
        # tamper: rewrite a stored action directly (bypassing the app)
        db.execute("UPDATE backoffice_audit_ledger SET action = 'tampered' WHERE id = 2")
        result = verify_chain(db)
        assert result["intact"] is False
        assert result["first_broken_id"] == 2

    def test_export_csv_and_json(self, db):
        append_event(db, tenant_id="default", event_type="kyc.override",
                     actor_id="ops-1", resource_type="kyc", resource_id="k-1",
                     action="override_approve", details={"reason": "ok"})
        client = make_client(db)
        csv_resp = client.get("/api/v1/backoffice/audit/logs/export?format=csv")
        assert csv_resp.status_code == 200
        assert "override_approve" in csv_resp.text
        assert csv_resp.headers["content-type"].startswith("text/csv")
        json_resp = client.get("/api/v1/backoffice/audit/logs/export?format=json")
        assert json_resp.json()[0]["action"] == "override_approve"


class TestUsersAndSessions:
    def test_list_users_and_revoke_sessions(self, db):
        append_event(db, tenant_id="default", event_type="kyc.override",
                     actor_id="ops-1", resource_type="kyc", resource_id="k-1",
                     action="override_approve")
        client = make_client(db, ADMIN)
        users = client.get("/api/v1/backoffice/users").json()["users"]
        assert [u["sub"] for u in users] == ["ops-1"]
        resp = client.post("/api/v1/backoffice/users/ops-1/sessions/revoke",
                           json={"reason": "suspected compromise"})
        assert resp.status_code == 200
        row = db.query_one(
            "SELECT * FROM backoffice_session_revocations WHERE sub = 'ops-1' AND jti = '*'")
        assert row["revoked_by"] == "admin-1"


class TestDashboard:
    def test_stats_from_seeded_rows(self, db):
        seed_kyc(db)
        seed_alert(db)
        seed_review(db)
        seed_journey(db, status="running")
        client = make_client(db)
        body = client.get("/api/v1/backoffice/dashboard/stats").json()
        assert body["total_kyc_verifications"] == 1
        assert body["active_fraud_alerts"] == 1
        assert body["pending_document_reviews"] == 1
        assert body["active_journeys"] == 1
        assert body["kyc_by_status"] == [{"status": "manual_review", "count": 1}]
        assert body["fraud_by_type"] == [{"type": "identity", "count": 1}]
