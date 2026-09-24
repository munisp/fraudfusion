"""End-to-end tests for the onboarding service (SQLite backend, auth stubbed).

Auth is exercised through dependency overrides; the fail-closed Keycloak
introspection path is tested separately in test_auth_fail_closed.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

TENANT = Principal(sub="user-tenant-1", username="ada", roles=set())
TENANT2 = Principal(sub="user-tenant-2", username="bola", roles=set())
ADMIN_A = Principal(sub="staff-a", username="staffa", roles={"onboarding_admin"})
ADMIN_B = Principal(sub="staff-b", username="staffb", roles={"admin"})


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "onboarding.db"))
    yield database
    reset_db_for_tests(None)


def make_client(db, principal):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def request_key(client, organization="Acme Pay", environment="sandbox"):
    return client.post(
        "/api/v1/onboarding/api-keys",
        json={
            "organization": organization,
            "contactEmail": "dev@acme.example",
            "useCase": "sandbox integration",
            "environment": environment,
        },
    )


class TestTenantSelfServe:
    def test_request_api_key_creates_tenant_and_pending_key(self, db):
        client = make_client(db, TENANT)
        resp = request_key(client)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "pending"
        # plaintext key material must never be returned at request time
        assert body.get("apiKey") is None
        assert body["keyId"]

    def test_status_flow_and_checklist_seed(self, db):
        client = make_client(db, TENANT)
        request_key(client)
        status = client.get("/api/v1/onboarding/status").json()
        assert status["state"] == "pending_review"
        assert status["apiKeyIssued"] is False
        ids = {i["id"] for i in status["checklist"]}
        assert "request-api-key" in ids and "select-kyc-tier" in ids
        assert next(i for i in status["checklist"] if i["id"] == "request-api-key")["done"] is True

    def test_status_404_before_onboarding(self, db):
        client = make_client(db, TENANT)
        assert client.get("/api/v1/onboarding/status").status_code == 404

    def test_kyc_tier_selection_and_checklist_toggle(self, db):
        client = make_client(db, TENANT)
        request_key(client)
        tenant_id = client.get("/api/v1/onboarding/status").json()["tenantId"]
        resp = client.post("/api/v1/onboarding/kyc-tier", json={"tenantId": tenant_id, "tier": "enhanced"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["tier"] == "enhanced"
        item = client.post("/api/v1/onboarding/checklist/integrate-auth", json={"done": True})
        assert item.status_code == 200
        assert item.json() == {"id": "integrate-auth", "label": "Integrate Keycloak OIDC authentication",
                               "done": True, "required": True}
        assert client.post("/api/v1/onboarding/checklist/nope", json={"done": True}).status_code == 404

    def test_invalid_kyc_tier_rejected(self, db):
        client = make_client(db, TENANT)
        request_key(client)
        tenant_id = client.get("/api/v1/onboarding/status").json()["tenantId"]
        assert client.post("/api/v1/onboarding/kyc-tier",
                           json={"tenantId": tenant_id, "tier": "gold"}).status_code == 422

    def test_tenant_isolation(self, db):
        request_key(make_client(db, TENANT))
        other = make_client(db, TENANT2)
        # TENANT2 has no tenant of their own yet
        assert other.get("/api/v1/onboarding/status").status_code == 404
        tid = make_client(db, TENANT).get("/api/v1/onboarding/status").json()["tenantId"]
        assert other.post("/api/v1/onboarding/kyc-tier",
                          json={"tenantId": tid, "tier": "premium"}).status_code == 403


class TestStaffApprovalDualControl:
    def _key_id(self, db):
        resp = request_key(make_client(db, TENANT))
        return resp.json()["keyId"]

    def test_non_admin_cannot_approve(self, db):
        key_id = self._key_id(db)
        client = make_client(db, TENANT)
        assert client.post(f"/api/v1/onboarding/admin/requests/{key_id}/approve").status_code == 403
        assert client.get("/api/v1/onboarding/admin/requests").status_code == 403

    def test_full_dual_control_happy_path(self, db):
        key_id = self._key_id(db)
        admin_a = make_client(db, ADMIN_A)
        admin_b = make_client(db, ADMIN_B)

        listed = admin_a.get("/api/v1/onboarding/admin/requests").json()
        assert [r["keyId"] for r in listed] == [key_id]

        # approve before review is rejected
        assert admin_b.post(f"/api/v1/onboarding/admin/requests/{key_id}/approve").status_code == 409

        reviewed = admin_a.post(f"/api/v1/onboarding/admin/requests/{key_id}/review")
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["status"] == "reviewed"

        # reviewer cannot also approve (dual control)
        assert admin_a.post(f"/api/v1/onboarding/admin/requests/{key_id}/approve").status_code == 409

        approved = admin_b.post(f"/api/v1/onboarding/admin/requests/{key_id}/approve")
        assert approved.status_code == 200, approved.text
        body = approved.json()
        assert body["status"] == "approved"
        assert body["apiKey"].startswith("ffk_")

        # only the hash is persisted, never the plaintext
        row = db.query_one("SELECT * FROM tenant_api_keys WHERE id = :id", {"id": key_id})
        assert row["key_hash"] != body["apiKey"]
        import hashlib
        assert row["key_hash"] == hashlib.sha256(body["apiKey"].encode()).hexdigest()

        # tenant now active with issued key
        status = make_client(db, TENANT).get("/api/v1/onboarding/status").json()
        assert status["state"] == "active"
        assert status["apiKeyIssued"] is True

        # re-approval rejected
        assert admin_b.post(f"/api/v1/onboarding/admin/requests/{key_id}/approve").status_code == 409

    def test_requester_cannot_self_review(self, db):
        # tenant principal is also an admin -> still cannot review own request
        both = Principal(sub=TENANT.sub, username="ada", roles={"onboarding_admin"})
        key_id = self._key_id(db)
        client = make_client(db, both)
        assert client.post(f"/api/v1/onboarding/admin/requests/{key_id}/review").status_code == 409

    def test_reject_flow(self, db):
        key_id = self._key_id(db)
        admin = make_client(db, ADMIN_A)
        resp = admin.post(f"/api/v1/onboarding/admin/requests/{key_id}/reject",
                          json={"reason": "incomplete KYB documents"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "rejected"
        assert resp.json()["rejectionReason"] == "incomplete KYB documents"
        # rejected requests leave the queue
        assert admin.get("/api/v1/onboarding/admin/requests").json() == []
        # tenant drops back to in_progress
        status = make_client(db, TENANT).get("/api/v1/onboarding/status").json()
        assert status["state"] == "in_progress"

    def test_approval_events_audit_trail(self, db):
        key_id = self._key_id(db)
        make_client(db, ADMIN_A).post(f"/api/v1/onboarding/admin/requests/{key_id}/review")
        make_client(db, ADMIN_B).post(f"/api/v1/onboarding/admin/requests/{key_id}/approve")
        events = db.query(
            "SELECT action, actor_sub FROM onboarding_approval_events WHERE api_key_id = :id ORDER BY created_at",
            {"id": key_id},
        )
        actions = [(e["action"], e["actor_sub"]) for e in events]
        assert ("request", TENANT.sub) in actions
        assert ("review", ADMIN_A.sub) in actions
        assert ("approve", ADMIN_B.sub) in actions


class TestAuthFailClosed:
    def test_missing_bearer_rejected(self, db):
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        client = TestClient(app)
        assert client.get("/api/v1/onboarding/status").status_code == 401

    def test_no_keycloak_configured_fails_closed(self, db, monkeypatch):
        monkeypatch.setattr("app.auth.KEYCLOAK_URL", "")
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        client = TestClient(app)
        resp = client.get("/api/v1/onboarding/status", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 503

    def test_inactive_token_rejected(self, db, monkeypatch):
        monkeypatch.setattr("app.auth.KEYCLOAK_URL", "https://keycloak.example.test")

        class FakeResponse:
            status_code = 200

            def json(self):
                return {"active": False}

        monkeypatch.setattr("app.auth.httpx.post", lambda *a, **k: FakeResponse())
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        client = TestClient(app)
        resp = client.get("/api/v1/onboarding/status", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 401

    def test_plain_http_keycloak_rejected_without_flag(self, db, monkeypatch):
        monkeypatch.setattr("app.auth.KEYCLOAK_URL", "http://keycloak:8080")
        monkeypatch.delenv("KEYCLOAK_INSECURE_HTTP", raising=False)
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        client = TestClient(app)
        resp = client.get("/api/v1/onboarding/status", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 503


def test_health():
    client = TestClient(create_app())
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["service"] == "onboarding-service"
