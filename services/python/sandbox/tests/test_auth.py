"""Auth paths + rate limiting."""

from __future__ import annotations

from tests.conftest import AUTH


def test_health_is_open(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["environment"] == "sandbox" and body["synthetic"] is True


def test_missing_key_is_401(client):
    r = client.get("/v1/intel/national/summary")
    assert r.status_code == 401
    assert "X-API-Key" in r.json()["detail"]


def test_malformed_key_is_401(client):
    r = client.get("/v1/intel/national/summary",
                   headers={"X-API-Key": "sk_something_else"})
    assert r.status_code == 401
    assert "ffk_test_" in r.json()["detail"]


def test_bare_prefix_is_401(client):
    r = client.get("/v1/intel/national/summary",
                   headers={"X-API-Key": "ffk_test_"})
    assert r.status_code == 401


def test_live_key_explicitly_rejected(client):
    r = client.get("/v1/intel/national/summary",
                   headers={"X-API-Key": "ffk_live_abc123"})
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert "ffk_live_" in detail
    assert "cannot be used in the sandbox" in detail


def test_any_test_key_accepted(client):
    for key in ("ffk_test_a", "ffk_test_another-dev-key", "ffk_test_000"):
        r = client.get("/v1/intel/national/summary",
                       headers={"X-API-Key": key})
        assert r.status_code == 200, key


def test_rate_limit_60rpm(client):
    key = {"X-API-Key": "ffk_test_rate-limited"}
    codes = [client.get("/v1/intel/national/summary", headers=key).status_code
             for _ in range(60)]
    assert all(c == 200 for c in codes)
    r = client.get("/v1/intel/national/summary", headers=key)
    assert r.status_code == 429
    assert "rate limit" in r.json()["detail"]
    assert "Retry-After" in r.headers


def test_rate_limit_is_per_key(client):
    for _ in range(60):
        client.get("/health")  # unauthenticated, unmetered
    # A different key is unaffected by the exhausted key above.
    r = client.get("/v1/intel/national/summary", headers=AUTH)
    assert r.status_code == 200
