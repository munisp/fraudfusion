"""Dual-auth tests for intel-service: previously the /v1/intel/* data plane
had NO auth at all. Now every data-plane route requires a staff Keycloak JWT
(app/auth.py) OR an X-API-Key validated via billing introspection
(app/api_keys.py) with the fraud_score scope. Fail-closed throughout.
"""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.conftest import ARTIFACT_DIR, override_auth  # noqa: E402  (path setup)

import app.api_keys as api_keys  # noqa: E402
from app.main import create_app  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (ARTIFACT_DIR / "summaries.json").exists(),
    reason="shipped artifact not built")


@pytest.fixture(autouse=True)
def _clear_key_cache():
    api_keys.reset_cache_for_tests()
    yield
    api_keys.reset_cache_for_tests()


@pytest.fixture()
def client():
    # Auth NOT overridden here — these tests exercise the real dual-auth path.
    return TestClient(create_app(artifact_dir=ARTIFACT_DIR))


def stub_introspect(monkeypatch, mapping):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        key = json.loads(request.content)["key"]
        calls.append(key)
        if key not in mapping:
            return httpx.Response(200, json={"active": False, "reason": "unknown key"})
        return httpx.Response(200, json=mapping[key])

    transport_client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(api_keys, "_post", lambda url, **kw: transport_client.post(url, **kw))
    monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL",
                        "http://billing.test/internal/api-keys/introspect")
    monkeypatch.setattr(api_keys, "BILLING_INTERNAL_TOKEN", "tok")
    return calls


ACTIVE = {"active": True, "tenant_id": "tenant-1", "scopes": ["fraud_score"],
          "status": "active", "expires_at": None, "key_id": "key-1",
          "key_type": "live"}


def test_no_credentials_denied(client, monkeypatch):
    import app.auth as auth_mod
    monkeypatch.setattr(auth_mod, "KEYCLOAK_URL", "https://keycloak.example")
    for path in ("/v1/intel/national/summary", "/v1/intel/states",
                 "/v1/intel/states/lagos", "/v1/intel/hotspots",
                 "/v1/intel/typology-mix", "/v1/intel/brief",
                 "/v1/intel/cultural/calendar?date=2026-12-25&state=enugu",
                 "/v1/intel/request-legitimacy/matrix"):
        assert client.get(path).status_code == 401, path
    # /health stays open for orchestrators.
    assert client.get("/health").status_code == 200


def test_no_keycloak_configured_is_503(client, monkeypatch):
    import app.auth as auth_mod
    monkeypatch.setattr(auth_mod, "KEYCLOAK_URL", "")
    resp = client.get("/v1/intel/states", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503


def test_api_key_accepted_on_all_planes(client, monkeypatch):
    stub_introspect(monkeypatch, {"ffk_live_good": ACTIVE})
    headers = {"X-API-Key": "ffk_live_good"}
    assert client.get("/v1/intel/national/summary", headers=headers).status_code == 200
    assert client.get("/v1/intel/states", headers=headers).status_code == 200
    assert client.get("/v1/intel/cultural/calendar",
                      params={"date": "2026-12-25", "state": "enugu"},
                      headers=headers).status_code == 200
    r = client.post("/v1/intel/request-legitimacy/assess",
                    json={"entity_type": "bank", "requested_fields": ["bvn"]},
                    headers=headers)
    assert r.status_code in (200, 422)  # auth passed either way


def test_api_key_scope_enforced_403(client, monkeypatch):
    key = {"active": True, "tenant_id": "tenant-1", "scopes": ["kyc_verify"],
           "status": "active", "expires_at": None, "key_id": "k2", "key_type": "live"}
    stub_introspect(monkeypatch, {"ffk_live_wrongscope": key})
    resp = client.get("/v1/intel/states", headers={"X-API-Key": "ffk_live_wrongscope"})
    assert resp.status_code == 403


def test_api_key_fail_closed_when_unconfigured(client, monkeypatch):
    monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL", "")
    resp = client.get("/v1/intel/states", headers={"X-API-Key": "ffk_live_good"})
    assert resp.status_code == 503


def test_api_key_validator_unreachable_is_503(client, monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectError("billing down")
    monkeypatch.setattr(api_keys, "_post", boom)
    monkeypatch.setattr(api_keys, "BILLING_INTROSPECT_URL", "http://billing.test/x")
    resp = client.get("/v1/intel/states", headers={"X-API-Key": "ffk_live_good"})
    assert resp.status_code == 503


def test_inactive_key_401(client, monkeypatch):
    stub_introspect(monkeypatch, {"ffk_live_dead": {"active": False, "reason": "key suspended (billing)"}})
    resp = client.get("/v1/intel/states", headers={"X-API-Key": "ffk_live_dead"})
    assert resp.status_code == 401
    assert "suspended" in resp.json()["detail"]


def test_introspect_cached_by_key_hash(client, monkeypatch):
    calls = stub_introspect(monkeypatch, {"ffk_live_good": ACTIVE})
    for _ in range(3):
        assert client.get("/v1/intel/national/summary",
                          headers={"X-API-Key": "ffk_live_good"}).status_code == 200
    assert len(calls) == 1  # one introspection, then TTL-cache hits


def test_override_auth_helper_keeps_endpoints_open(monkeypatch):
    # The conftest override_auth helper (used by the other 46 tests) bypasses
    # dual auth with a staff principal.
    import app.api_keys as ak
    monkeypatch.setattr(ak, "BILLING_INTROSPECT_URL", "")
    c = TestClient(override_auth(create_app(artifact_dir=ARTIFACT_DIR)))
    assert c.get("/v1/intel/national/summary").status_code == 200
