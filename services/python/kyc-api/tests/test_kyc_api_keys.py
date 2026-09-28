"""Tests for the API-key data-plane seam: dual auth (staff JWT OR
X-API-Key via billing introspection), per-endpoint scope enforcement,
tenant isolation, Idempotency-Key replay/conflict, and the webhook emitter.

Run: python3 -m pytest tests/ -q   (from services/python/kyc-api)
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from fastapi.testclient import TestClient

import app.api_keys as api_keys
import app.webhooks as webhooks
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.identity import luhn_checksum_ok
from app.main import create_app

CALLER = Principal(sub="kyc-ops-1", username="ops", roles={"kyc_operator"})

PDF_BYTES = b"%PDF-1.4 fake-but-structurally-pdf\n%%EOF\n" + b"0" * 2048


def valid_bvn() -> str:
    base = "2234567890"
    for d in range(10):
        candidate = base + str(d)
        if luhn_checksum_ok(candidate):
            return candidate
    raise AssertionError("no luhn-valid suffix found")


BVN = valid_bvn()


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


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "kyc.db"))
    yield database
    reset_db_for_tests(None)


@pytest.fixture(autouse=True)
def _clear_key_cache():
    api_keys.reset_cache_for_tests()
    yield
    api_keys.reset_cache_for_tests()


def stub_introspect(monkeypatch, mapping):
    """Route api_keys._post through an httpx MockTransport keyed by the
    presented plaintext key. mapping: plaintext -> introspect payload."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        key = json.loads(request.content)["key"]
        calls.append(key)
        if key not in mapping:
            return httpx.Response(200, json={"active": False, "reason": "unknown key"})
        return httpx.Response(200, json=mapping[key])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(api_keys, "_post", lambda url, **kw: client.post(url, **kw))
    monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL", "http://billing.test/internal/api-keys/introspect")
    monkeypatch.setattr(api_keys, "BILLING_INTERNAL_TOKEN", "tok")
    return calls


ACTIVE_T1 = {"active": True, "tenant_id": "tenant-1", "scopes": ["kyc_verify"],
             "status": "active", "expires_at": None, "key_id": "key-t1",
             "key_type": "live"}
ACTIVE_T2 = {"active": True, "tenant_id": "tenant-2", "scopes": ["kyc_verify"],
             "status": "active", "expires_at": None, "key_id": "key-t2",
             "key_type": "test"}


def make_client(db, principal=CALLER):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


# ---------------------------------------------------------------------------
# Dual auth: API-key path
# ---------------------------------------------------------------------------

class TestApiKeyAuth:
    def test_api_key_accepted_and_tenant_recorded(self, db, monkeypatch):
        stub_introspect(monkeypatch, {"ffk_live_good": ACTIVE_T1})
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                           headers={"X-API-Key": "ffk_live_good"})
        assert resp.status_code == 200, resp.text
        row = db.query_one("SELECT tenant_id, actor_sub FROM kyc_requests"
                           " WHERE id = :id", {"id": resp.json()["request_id"]})
        assert row["tenant_id"] == "tenant-1"
        assert row["actor_sub"] == "apikey:key-t1"

    def test_api_key_validation_fail_closed_when_unconfigured(self, db, monkeypatch):
        monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL", "")
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                           headers={"X-API-Key": "ffk_live_good"})
        assert resp.status_code == 503

    def test_api_key_validator_unreachable_is_503(self, db, monkeypatch):
        def boom(url, **kw):
            raise httpx.ConnectError("billing down")
        monkeypatch.setattr(api_keys, "_post", boom)
        monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL", "http://billing.test/x")
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                           headers={"X-API-Key": "ffk_live_good"})
        assert resp.status_code == 503

    def test_inactive_key_401_with_reason(self, db, monkeypatch):
        stub_introspect(monkeypatch, {"ffk_live_dead": {"active": False, "reason": "key revoked"}})
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                           headers={"X-API-Key": "ffk_live_dead"})
        assert resp.status_code == 401
        assert "revoked" in resp.json()["detail"]

    def test_scope_enforced_per_endpoint_403(self, db, monkeypatch):
        key = {"active": True, "tenant_id": "tenant-1", "scopes": ["fraud_score"],
               "status": "active", "expires_at": None, "key_id": "k1", "key_type": "live"}
        stub_introspect(monkeypatch, {"ffk_live_fraudonly": key})
        client = make_client(db)
        # kyc_verify endpoint: denied.
        assert client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                           headers={"X-API-Key": "ffk_live_fraudonly"}).status_code == 403
        # fraud_score endpoint: allowed.
        assert client.post("/api/v1/risk/assess", json={"amount_ngn": 10},
                           headers={"X-API-Key": "ffk_live_fraudonly"}).status_code == 200

    def test_introspect_cached_by_key_hash(self, db, monkeypatch):
        calls = stub_introspect(monkeypatch, {"ffk_live_good": ACTIVE_T1})
        client = make_client(db)
        for _ in range(3):
            assert client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                               headers={"X-API-Key": "ffk_live_good"}).status_code == 200
        assert len(calls) == 1  # one introspection, then TTL-cache hits

    def test_staff_jwt_path_unchanged(self, db):
        # No X-API-Key: the staff-JWT dependency override still governs.
        client = make_client(db)
        resp = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 200
        row = db.query_one("SELECT tenant_id, actor_sub FROM kyc_requests"
                           " WHERE id = :id", {"id": resp.json()["request_id"]})
        assert row["actor_sub"] == "kyc-ops-1"
        assert row["tenant_id"] == "default"  # staff principals: default bucket

    def test_no_credentials_401(self, db, monkeypatch):
        import app.auth as auth_mod
        monkeypatch.setattr(auth_mod, "KEYCLOAK_URL", "https://keycloak.example")
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        resp = TestClient(app).post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tenant isolation for API-key principals
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_api_key_reads_only_own_tenant(self, db, monkeypatch):
        stub_introspect(monkeypatch, {"ffk_live_t1": ACTIVE_T1, "ffk_test_t2": ACTIVE_T2})
        client = make_client(db)
        created = client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                              headers={"X-API-Key": "ffk_live_t1"})
        rid = created.json()["request_id"]
        own = client.get(f"/api/v1/kyc/status/{rid}", headers={"X-API-Key": "ffk_live_t1"})
        assert own.status_code == 200
        other = client.get(f"/api/v1/kyc/status/{rid}", headers={"X-API-Key": "ffk_test_t2"})
        assert other.status_code == 404  # no existence leak across tenants
        staff = client.get(f"/api/v1/kyc/status/{rid}")  # JWT override, cross-tenant
        assert staff.status_code == 200


# ---------------------------------------------------------------------------
# Idempotency-Key on POST verify endpoints
# ---------------------------------------------------------------------------

class TestIdempotency:
    def test_first_wins_replay_same_request_id(self, db):
        client = make_client(db)
        headers = {"Idempotency-Key": "idem-1"}
        first = client.post("/api/v1/kyc/verify/basic", json=basic_payload(), headers=headers)
        assert first.status_code == 200
        replay = client.post("/api/v1/kyc/verify/basic", json=basic_payload(), headers=headers)
        assert replay.status_code == 200
        assert replay.json()["request_id"] == first.json()["request_id"]
        assert replay.headers.get("Idempotency-Replayed") == "true"
        rows = db.query("SELECT id FROM kyc_requests")
        assert len(rows) == 1  # executed exactly once

    def test_same_key_different_payload_409(self, db):
        client = make_client(db)
        headers = {"Idempotency-Key": "idem-2"}
        assert client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                           headers=headers).status_code == 200
        conflict = client.post("/api/v1/kyc/verify/basic",
                               json=basic_payload(customer_id="cust-2"), headers=headers)
        assert conflict.status_code == 409

    def test_key_scoped_per_tenant(self, db, monkeypatch):
        stub_introspect(monkeypatch, {"ffk_live_t1": ACTIVE_T1, "ffk_test_t2": ACTIVE_T2})
        client = make_client(db)
        # Same key value, different tenants => independent idempotency scopes.
        r1 = client.post("/api/v1/kyc/verify/basic", json=basic_payload(),
                         headers={"Idempotency-Key": "shared", "X-API-Key": "ffk_live_t1"})
        r2 = client.post("/api/v1/kyc/verify/basic", json=basic_payload(customer_id="cust-9"),
                         headers={"Idempotency-Key": "shared", "X-API-Key": "ffk_test_t2"})
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.json()["request_id"] != r2.json()["request_id"]

    def test_document_verify_replay(self, db):
        client = make_client(db)
        headers = {"Idempotency-Key": "doc-1"}
        files = {"document": ("doc.pdf", PDF_BYTES, "application/pdf")}
        data = {"document_type": "drivers_license"}
        first = client.post("/api/v1/document/verify", files=files, data=data, headers=headers)
        assert first.status_code == 200
        replay = client.post("/api/v1/document/verify", files=files, data=data, headers=headers)
        assert replay.json()["verification_id"] == first.json()["verification_id"]
        assert replay.headers.get("Idempotency-Replayed") == "true"
        # Different document under the same key conflicts.
        other = client.post("/api/v1/document/verify",
                            files={"document": ("doc.pdf", PDF_BYTES + b"x", "application/pdf")},
                            data=data, headers=headers)
        assert other.status_code == 409

    def test_no_header_unchanged_behavior(self, db):
        client = make_client(db)
        r1 = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        r2 = client.post("/api/v1/kyc/verify/basic", json=basic_payload())
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.json()["request_id"] != r2.json()["request_id"]


# ---------------------------------------------------------------------------
# Webhook emitter (kyc.verification.completed from /document/verify)
# ---------------------------------------------------------------------------

class TestWebhookEmitter:
    def _doc_verify(self, client):
        return client.post(
            "/api/v1/document/verify",
            files={"document": ("doc.pdf", PDF_BYTES, "application/pdf")},
            data={"document_type": "drivers_license"})

    def test_noop_when_webhook_url_unset(self, db, monkeypatch):
        monkeypatch.delenv("WEBHOOK_SERVICE_URL", raising=False)
        assert webhooks.emit_event("kyc.verification.completed", "tenant-1", {}) is False
        client = make_client(db)
        assert self._doc_verify(client).status_code == 200  # request unaffected

    def test_event_fired_with_envelope_and_no_pii(self, db, monkeypatch):
        sent = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append({"url": str(request.url),
                         "token": request.headers.get("X-Internal-Token"),
                         "body": json.loads(request.content)})
            return httpx.Response(202, json={"accepted": True})

        transport_client = httpx.Client(transport=httpx.MockTransport(handler))
        monkeypatch.setattr(webhooks, "_post", lambda url, **kw: transport_client.post(url, **kw))
        monkeypatch.setenv("WEBHOOK_SERVICE_URL", "http://webhooks.test")
        monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", "wh-tok")
        client = make_client(db)
        resp = self._doc_verify(client)
        assert resp.status_code == 200
        assert len(sent) == 1
        event = sent[0]
        assert event["url"] == "http://webhooks.test/internal/events"
        assert event["token"] == "wh-tok"
        body = event["body"]
        assert body["type"] == "kyc.verification.completed"
        assert set(body) == {"id", "type", "created_at", "tenant_id", "data"}
        data = body["data"]
        assert data["verification_id"] == resp.json()["verification_id"]
        assert data["document_type"] == "drivers_license"
        assert data["status"] == resp.json()["status"]
        assert len(data["sha256"]) == 64
        # NO PII / raw fields in the payload.
        assert set(data) == {"verification_id", "document_type", "status", "sha256"}

    def test_emit_failure_never_breaks_request(self, db, monkeypatch):
        def boom(url, **kw):
            raise httpx.ConnectError("webhook-service down")
        monkeypatch.setattr(webhooks, "_post", boom)
        monkeypatch.setenv("WEBHOOK_SERVICE_URL", "http://webhooks.test")
        client = make_client(db)
        assert self._doc_verify(client).status_code == 200

    def test_replay_does_not_re_emit(self, db, monkeypatch):
        calls = []
        monkeypatch.setattr(webhooks, "emit_event",
                            lambda *a, **kw: calls.append(a) or True)
        client = make_client(db)
        headers = {"Idempotency-Key": "doc-noreemit"}
        files = {"document": ("doc.pdf", PDF_BYTES, "application/pdf")}
        data = {"document_type": "drivers_license"}
        client.post("/api/v1/document/verify", files=files, data=data, headers=headers)
        client.post("/api/v1/document/verify", files=files, data=data, headers=headers)
        assert len(calls) == 1  # emitted on first execution only
