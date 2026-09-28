"""Webhook-service API + delivery pipeline tests.

Covers: endpoint CRUD with tenant isolation, secret-shown-once +
hash-only storage, internal-token fail-closed intake, event fan-out,
full event->signed-delivery round trip against an httpx MockTransport
receiver, retry/backoff/dead-letter, circuit breaker, hash-chain
integrity, and event dedupe.

Run: python3 -m pytest tests/ -q   (from services/python/webhook-service)
"""

from __future__ import annotations

import asyncio
import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app import chain, signing, worker
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

STAFF = Principal(sub="staff-1", username="ada", roles={"admin"})
TOKEN = "test-internal-token"


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "webhooks.db"))
    yield database
    reset_db_for_tests(None)


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", TOKEN)
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: STAFF
    return TestClient(app)


def make_endpoint(client, *, tenant="default", url="https://receiver.test/hook",
                  event_types=("kyb.verification.completed",)) -> dict:
    resp = client.post("/v1/webhooks", json={"url": url, "event_types": list(event_types)},
                       headers={"X-Tenant-Id": tenant})
    assert resp.status_code == 201, resp.text
    return resp.json()


def post_event(client, *, event_id="evt_1", event_type="kyb.verification.completed",
               tenant="default", data=None, token=TOKEN):
    envelope = {"id": event_id, "type": event_type, "created_at": 1735689600,
                "tenant_id": tenant, "data": data or {"application_id": "app_1"}}
    return client.post("/internal/events", json=envelope,
                       headers={"X-Internal-Token": token})


def run_worker(db, handler, *, now=None):
    """One worker pass against a MockTransport receiver."""
    async def _run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await worker.process_due_deliveries(db, c, now=now)
    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# Endpoint CRUD / secret handling / tenant isolation
# ---------------------------------------------------------------------------

class TestEndpointCrud:
    def test_create_returns_secret_once_and_stores_hash_only(self, client, db):
        ep = make_endpoint(client)
        assert ep["secret"].startswith("whsec_") and len(ep["secret"]) == 38
        assert ep["status"] == "active"
        row = db.query_one("SELECT * FROM webhook_endpoints WHERE id = :id",
                           {"id": ep["id"]})
        assert row["secret_hash"] == hashlib.sha256(ep["secret"].encode()).hexdigest()
        assert ep["secret"].encode() not in json.dumps(row).encode()
        # Never shown again by any read path.
        for resp in (client.get("/v1/webhooks"),
                     client.get(f"/v1/webhooks/{ep['id']}")):
            assert resp.status_code == 200
            assert "secret" not in resp.text and row["secret_hash"] not in resp.text

    def test_list_get_delete(self, client):
        ep = make_endpoint(client)
        listing = client.get("/v1/webhooks").json()["endpoints"]
        assert [e["id"] for e in listing] == [ep["id"]]
        got = client.get(f"/v1/webhooks/{ep['id']}")
        assert got.status_code == 200 and got.json()["url"] == "https://receiver.test/hook"
        assert client.delete(f"/v1/webhooks/{ep['id']}").status_code == 204
        assert client.get(f"/v1/webhooks/{ep['id']}").status_code == 404
        assert client.get("/v1/webhooks").json()["endpoints"] == []

    def test_tenant_isolation(self, client):
        ep = make_endpoint(client, tenant="tenant-a")
        # tenant-b cannot see, read, or delete tenant-a's endpoint.
        assert client.get("/v1/webhooks",
                          headers={"X-Tenant-Id": "tenant-b"}).json()["endpoints"] == []
        assert client.get(f"/v1/webhooks/{ep['id']}",
                          headers={"X-Tenant-Id": "tenant-b"}).status_code == 404
        assert client.delete(f"/v1/webhooks/{ep['id']}",
                             headers={"X-Tenant-Id": "tenant-b"}).status_code == 404
        assert client.get(f"/v1/webhooks/{ep['id']}/deliveries",
                          headers={"X-Tenant-Id": "tenant-b"}).status_code == 404
        assert client.get(f"/v1/webhooks/{ep['id']}",
                          headers={"X-Tenant-Id": "tenant-a"}).status_code == 200

    def test_validation(self, client):
        assert client.post("/v1/webhooks", json={"url": "ftp://x", "event_types": ["a"]}
                           ).status_code == 422
        assert client.post("/v1/webhooks", json={"url": "https://x", "event_types": []}
                           ).status_code == 422
        assert client.post("/v1/webhooks",
                           json={"url": "https://x", "event_types": ["BAD TYPE!"]}
                           ).status_code == 422

    def test_requires_auth(self, db, monkeypatch):
        monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", TOKEN)
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db  # auth NOT overridden
        anon = TestClient(app)
        assert anon.post("/v1/webhooks", json={"url": "https://x.test",
                                               "event_types": ["a.b"]}).status_code == 401


# ---------------------------------------------------------------------------
# Internal event intake
# ---------------------------------------------------------------------------

class TestInternalEvents:
    def test_fail_closed_when_token_unset(self, client, monkeypatch):
        monkeypatch.delenv("WEBHOOK_INTERNAL_TOKEN", raising=False)
        resp = post_event(client)
        assert resp.status_code == 503

    def test_wrong_token_rejected(self, client):
        assert post_event(client, token="nope").status_code == 401
        assert post_event(client, token="").status_code == 401

    def test_fanout_to_subscribed_active_endpoints(self, client, db):
        ep1 = make_endpoint(client, url="https://a.test/hook")
        ep2 = make_endpoint(client, url="https://b.test/hook",
                            event_types=["identity.exposure.detected"])
        make_endpoint(client, tenant="other")  # different tenant: no fan-out
        resp = post_event(client)
        assert resp.status_code == 200 and resp.json() == {
            "status": "accepted", "event_id": "evt_1", "deliveries": 1}
        rows = db.query("SELECT * FROM webhook_deliveries")
        assert len(rows) == 1 and rows[0]["endpoint_id"] == ep1["id"]
        assert rows[0]["status"] == "pending"
        assert db.query_one("SELECT * FROM webhook_events WHERE id = 'evt_1'")
        # ep2 subscribed to a different type; wildcard endpoint gets it too.
        make_endpoint(client, url="https://wild.test/hook", event_types=["*"])
        resp = post_event(client, event_id="evt_2",
                          event_type="identity.exposure.detected",
                          data={"alert_id": "exp-1"})
        assert resp.json()["deliveries"] == 2

    def test_duplicate_event_no_refanout(self, client, db):
        make_endpoint(client)
        assert post_event(client).json()["status"] == "accepted"
        dup = post_event(client)
        assert dup.json()["status"] == "duplicate" and dup.json()["deliveries"] == 0
        assert len(db.query("SELECT * FROM webhook_deliveries")) == 1

    def test_envelope_validation(self, client):
        for body in ({"type": "a.b", "data": {}},          # no id
                     {"id": "x", "data": {}},              # no type
                     {"id": "x", "type": "a.b"},           # no data
                     {"id": "x", "type": "a.b", "data": []}):  # data not object
            assert client.post("/internal/events", json=body,
                               headers={"X-Internal-Token": TOKEN}).status_code == 422


# ---------------------------------------------------------------------------
# Delivery pipeline: round trip, retry/backoff, dead-letter, breaker
# ---------------------------------------------------------------------------

class TestDelivery:
    def test_backoff_schedule(self):
        assert [worker.backoff_for_attempt(n) for n in (1, 2, 3, 4, 5)] == \
            [1.0, 5.0, 25.0, 120.0, 600.0]
        assert worker.MAX_ATTEMPTS == 5

    def test_full_event_to_signed_delivery_round_trip(self, client, db):
        ep = make_endpoint(client)
        post_event(client, data={"application_id": "app_9", "verdict": "verified"})
        captured = {}

        def receiver(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            captured["sig"] = request.headers["X-FraudFusion-Signature"]
            captured["ct"] = request.headers["Content-Type"]
            return httpx.Response(200, json={"ok": True})

        assert run_worker(db, receiver) == 1
        # Receiver-side verification per the shared contract.
        envelope = json.loads(captured["body"])
        assert envelope["id"] == "evt_1" and envelope["type"] == "kyb.verification.completed"
        assert set(envelope) == {"id", "type", "created_at", "tenant_id", "data"}
        assert captured["ct"] == "application/json"
        assert signing.verify_signature(ep["secret"], captured["body"], captured["sig"])

        row = db.query_one("SELECT * FROM webhook_deliveries")
        assert row["status"] == "success" and row["attempt_count"] == 1
        assert row["completed_at"]
        history = json.loads(row["attempts_json"])
        assert len(history) == 1 and history[0]["status_code"] == 200

        deliveries = client.get(f"/v1/webhooks/{ep['id']}/deliveries").json()["deliveries"]
        assert len(deliveries) == 1
        assert deliveries[0]["status"] == "success"
        assert deliveries[0]["attempts"][0]["attempt"] == 1

    def test_retry_backoff_then_dead_letter(self, client, db):
        ep = make_endpoint(client)
        post_event(client)

        def failing(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"err": "boom"})

        db.execute("UPDATE webhook_deliveries SET next_attempt_at = 0")
        now = 1_000.0
        for expected_attempt in range(1, 6):
            assert run_worker(db, failing, now=now) == 1
            row = db.query_one("SELECT * FROM webhook_deliveries")
            assert row["attempt_count"] == expected_attempt
            if expected_attempt < 5:
                assert row["status"] == "pending"
                # Backoff honoured: not due again before the schedule says so.
                assert run_worker(db, failing, now=now + 0.5) == 0
                now = row["next_attempt_at"]
            else:
                assert row["status"] == "dead_letter"
        history = json.loads(row["attempts_json"])
        assert [h["attempt"] for h in history] == [1, 2, 3, 4, 5]
        assert all(h["status_code"] == 500 for h in history)
        # Circuit-breaker counter advanced once for the dead-lettered delivery.
        ep_row = db.query_one("SELECT * FROM webhook_endpoints WHERE id = :id",
                              {"id": ep["id"]})
        assert ep_row["consecutive_failures"] == 1 and ep_row["status"] == "active"
        # Dead-lettered rows are never picked up again.
        assert run_worker(db, failing, now=now + 10_000) == 0

    def test_network_error_counts_as_failed_attempt(self, client, db):
        make_endpoint(client)
        post_event(client)

        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        db.execute("UPDATE webhook_deliveries SET next_attempt_at = 0")
        assert run_worker(db, unreachable, now=1.0) == 1
        row = db.query_one("SELECT * FROM webhook_deliveries")
        assert row["status"] == "pending" and row["attempt_count"] == 1
        assert json.loads(row["attempts_json"])[0]["error"] == "ConnectError"

    def test_circuit_breaker_disables_endpoint(self, client, db, monkeypatch):
        monkeypatch.setattr(worker, "BREAKER_THRESHOLD", 1)
        ep = make_endpoint(client)
        post_event(client)
        db.execute("UPDATE webhook_deliveries SET next_attempt_at = 0")
        run_worker(db, lambda r: httpx.Response(500), now=1.0)
        run_worker(db, lambda r: httpx.Response(500), now=2.0)
        run_worker(db, lambda r: httpx.Response(500), now=7.0)
        run_worker(db, lambda r: httpx.Response(500), now=32.0)
        run_worker(db, lambda r: httpx.Response(500), now=152.0)
        row = db.query_one("SELECT * FROM webhook_endpoints WHERE id = :id",
                           {"id": ep["id"]})
        assert row["status"] == "disabled"
        # Disabled endpoints are excluded from fan-out.
        resp = post_event(client, event_id="evt_2")
        assert resp.json()["deliveries"] == 0

    def test_deleted_endpoint_dead_letters_pending(self, client, db):
        ep = make_endpoint(client)
        post_event(client)
        client.delete(f"/v1/webhooks/{ep['id']}")
        row = db.query_one("SELECT * FROM webhook_deliveries")
        assert row["status"] == "dead_letter" and row["last_error"] == "endpoint_deleted"


# ---------------------------------------------------------------------------
# Hash-chain integrity
# ---------------------------------------------------------------------------

class TestHashChain:
    def test_chain_intact_after_multiple_events(self, client, db):
        make_endpoint(client)
        for i in range(5):
            post_event(client, event_id=f"evt_{i}")
        result = chain.verify_chain(db, "default")
        assert result == {"broken_links": 0, "first_broken_id": None,
                          "entries": 5, "intact": True}
        # Rows really are linked tip-to-genesis.
        rows = db.query("SELECT prev_hash, entry_hash FROM webhook_deliveries")
        hashes = {r["entry_hash"] for r in rows}
        prevs = sorted(r["prev_hash"] for r in rows)
        assert prevs[0] == chain.GENESIS
        assert set(prevs[1:]) <= hashes

    def test_tampered_row_breaks_chain(self, client, db):
        make_endpoint(client)
        for i in range(3):
            post_event(client, event_id=f"evt_{i}")
        victim = db.query_one("SELECT id FROM webhook_deliveries LIMIT 1")
        db.execute("UPDATE webhook_deliveries SET entry_hash = :h WHERE id = :id",
                   {"h": "f" * 64, "id": victim["id"]})
        result = chain.verify_chain(db, "default")
        assert not result["intact"] and result["broken_links"] >= 1

    def test_empty_chain_is_intact(self, db):
        assert chain.verify_chain(db, "default")["intact"]


class TestLifespan:
    def test_background_worker_starts_and_stops_cleanly(self, db, monkeypatch):
        import time as _t

        monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", TOKEN)
        monkeypatch.setenv("WEBHOOK_WORKER_POLL_SECONDS", "0.05")
        monkeypatch.setattr(worker, "DELIVERY_TIMEOUT", 1.0)
        reset_db_for_tests(db)  # lifespan worker uses the global db
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_current_principal] = lambda: STAFF
        try:
            with TestClient(app) as live:
                assert live.get("/health").status_code == 200
                make_endpoint(live)
                post_event(live)
                # No receiver reachable at https://receiver.test -> the
                # in-process worker attempts and records a failed attempt.
                end = _t.time() + 8
                row = None
                while _t.time() < end:
                    row = db.query_one(
                        "SELECT status, attempt_count FROM webhook_deliveries")
                    if row and row["attempt_count"] >= 1:
                        break
                    _t.sleep(0.1)
                assert row and row["attempt_count"] >= 1
        finally:
            reset_db_for_tests(None)
