"""Dual-auth tests: /v1/webhooks via tenant API keys (X-API-Key + billing
introspection) alongside the unchanged staff-JWT path.

Mirrors services/python/kyc-api/tests/test_kyc_api_keys.py: billing's
POST /internal/api-keys/introspect is stubbed through an httpx
MockTransport via the api_keys._post seam.

Run: python3 -m pytest tests/test_api_keys.py -q
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app import api_keys
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

STAFF = Principal(sub="staff-1", username="ada", roles={"admin"})

KEY_T1 = "ffk_live_tenantone"
KEY_T2 = "ffk_test_tenanttwo"
ACTIVE_T1 = {"active": True, "tenant_id": "tenant-1",
             "scopes": ["webhooks_manage"], "status": "active",
             "expires_at": None, "key_id": "key-t1", "key_type": "live"}
ACTIVE_T2 = {"active": True, "tenant_id": "tenant-2",
             "scopes": ["webhooks_manage"], "status": "active",
             "expires_at": None, "key_id": "key-t2", "key_type": "test"}


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "webhooks.db"))
    yield database
    reset_db_for_tests(None)


@pytest.fixture(autouse=True)
def _clear_key_cache():
    api_keys.reset_cache_for_tests()
    yield
    api_keys.reset_cache_for_tests()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", "tok")
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: STAFF
    return TestClient(app)


def stub_introspect(monkeypatch, mapping):
    """Route api_keys._post through an httpx MockTransport keyed by the
    presented plaintext key. Returns the list of introspected keys."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content)["key"])
        if request.headers.get("X-Internal-Token") != "tok":
            return httpx.Response(401, json={"detail": "bad internal token"})
        payload = mapping.get(calls[-1])
        if payload is None:
            return httpx.Response(200, json={"active": False, "reason": "unknown key"})
        return httpx.Response(200, json=payload)

    transport_client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(api_keys, "_post", lambda url, **kw: transport_client.post(url, **kw))
    monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL",
                        "http://billing.test/internal/api-keys/introspect")
    monkeypatch.setattr(api_keys, "BILLING_INTERNAL_TOKEN", "tok")
    return calls


BODY = {"url": "https://me.example.com/hook",
        "event_types": ["kyc.verification.completed"]}


class TestApiKeyCrud:
    def test_api_key_full_crud_happy_path(self, client, monkeypatch):
        calls = stub_introspect(monkeypatch, {KEY_T1: ACTIVE_T1})
        auth = {"X-API-Key": KEY_T1}
        created = client.post("/v1/webhooks", json=BODY, headers=auth)
        assert created.status_code == 201, created.text
        ep = created.json()
        assert ep["tenant_id"] == "tenant-1"  # tenant comes FROM THE KEY
        assert ep["secret"].startswith("whsec_")
        assert ep["created_by"] == "apikey:key-t1"

        listing = client.get("/v1/webhooks", headers=auth).json()["endpoints"]
        assert [e["id"] for e in listing] == [ep["id"]]
        assert client.get(f"/v1/webhooks/{ep['id']}", headers=auth).status_code == 200
        assert client.get(f"/v1/webhooks/{ep['id']}/deliveries",
                          headers=auth).status_code == 200
        assert client.delete(f"/v1/webhooks/{ep['id']}", headers=auth).status_code == 204
        assert client.get("/v1/webhooks", headers=auth).json()["endpoints"] == []
        # The second identical request was served from the <=60s TTL cache:
        # billing saw the key only once.
        assert calls.count(KEY_T1) == 1

    def test_wrong_scope_403(self, client, monkeypatch):
        stub_introspect(monkeypatch, {KEY_T1: {**ACTIVE_T1, "scopes": ["kyc_verify"]}})
        auth = {"X-API-Key": KEY_T1}
        assert client.post("/v1/webhooks", json=BODY, headers=auth).status_code == 403
        assert client.get("/v1/webhooks", headers=auth).status_code == 403

    def test_inactive_and_unknown_keys_401(self, client, monkeypatch):
        stub_introspect(monkeypatch, {KEY_T1: {"active": False, "reason": "revoked"}})
        assert client.get("/v1/webhooks",
                          headers={"X-API-Key": KEY_T1}).status_code == 401
        assert client.get("/v1/webhooks",
                          headers={"X-API-Key": "ffk_live_unknown"}).status_code == 401
        assert client.get("/v1/webhooks",
                          headers={"X-API-Key": "not-a-key"}).status_code == 401

    def test_cross_tenant_isolation(self, client, monkeypatch):
        stub_introspect(monkeypatch, {KEY_T1: ACTIVE_T1, KEY_T2: ACTIVE_T2})
        ep = client.post("/v1/webhooks", json=BODY,
                         headers={"X-API-Key": KEY_T1}).json()
        auth2 = {"X-API-Key": KEY_T2}
        assert client.get("/v1/webhooks", headers=auth2).json()["endpoints"] == []
        assert client.get(f"/v1/webhooks/{ep['id']}", headers=auth2).status_code == 404
        assert client.get(f"/v1/webhooks/{ep['id']}/deliveries",
                          headers=auth2).status_code == 404
        assert client.delete(f"/v1/webhooks/{ep['id']}", headers=auth2).status_code == 404
        # A key may not even NAME another tenant explicitly.
        assert client.get("/v1/webhooks",
                          headers={**auth2, "X-Tenant-Id": "tenant-1"}).status_code == 403
        # Matching header is fine.
        assert client.get("/v1/webhooks",
                          headers={**auth2, "X-Tenant-Id": "tenant-2"}).status_code == 200

    def test_api_key_delivery_history_own_tenant_only(self, client, db, monkeypatch):
        stub_introspect(monkeypatch, {KEY_T1: ACTIVE_T1})
        auth = {"X-API-Key": KEY_T1}
        ep = client.post("/v1/webhooks", json=BODY, headers=auth).json()
        # An event for tenant-1 fans out to the key-created endpoint.
        resp = client.post("/internal/events",
                           json={"id": "evt_k1", "type": "kyc.verification.completed",
                                 "created_at": 1, "tenant_id": "tenant-1", "data": {}},
                           headers={"X-Internal-Token": "tok"})
        assert resp.json()["deliveries"] == 1
        deliveries = client.get(f"/v1/webhooks/{ep['id']}/deliveries",
                                headers=auth).json()["deliveries"]
        assert len(deliveries) == 1 and deliveries[0]["tenant_id"] == "tenant-1"

    def test_introspect_down_503(self, client, monkeypatch):
        monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL",
                            "http://billing.test/internal/api-keys/introspect")

        def boom(url, **kw):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(api_keys, "_post", boom)
        resp = client.get("/v1/webhooks", headers={"X-API-Key": KEY_T1})
        assert resp.status_code == 503

    def test_introspect_unconfigured_503(self, client, monkeypatch):
        monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL", "")
        resp = client.get("/v1/webhooks", headers={"X-API-Key": KEY_T1})
        assert resp.status_code == 503

    def test_staff_jwt_path_unchanged(self, client, monkeypatch):
        """Staff JWT + X-Tenant-Id keeps working; introspection never called."""
        calls = stub_introspect(monkeypatch, {})
        created = client.post("/v1/webhooks", json=BODY,
                              headers={"X-Tenant-Id": "tenant-staff"})
        assert created.status_code == 201
        assert created.json()["tenant_id"] == "tenant-staff"
        assert client.get("/v1/webhooks",
                          headers={"X-Tenant-Id": "tenant-staff"}).json()["endpoints"]
        assert calls == []  # no bearer key header -> no billing call
