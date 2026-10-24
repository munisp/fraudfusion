"""Round 12 tests: land-module webhook events + SLA-breach sweeper.

- emit_event: fire-and-forget contract (unset URL = no-op, failures never
  raise), envelope shape matches the Round-9 emitter contract.
- Endpoint wiring: parcel registration/conflict/cleared, dispute
  opened/resolved, revocation opened/compensated each emit their event
  (captured via a monkeypatched _post).
- Sweeper: newly breached disputes emit dispute.sla.breached exactly once;
  unbreached and already-notified disputes are skipped; evidence chain
  records the breach.

Run: python3 -m pytest tests/test_land_webhooks.py -q
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import events  # noqa: E402
from api.data_store import LandDataStore, reset_land_store_for_tests  # noqa: E402
from api.main import create_app  # noqa: E402


@pytest.fixture()
def store(tmp_path):
    s = LandDataStore(sqlite_path=str(tmp_path / "land_wh.db"), seed=False)
    reset_land_store_for_tests(s)
    yield s
    reset_land_store_for_tests(None)


@pytest.fixture()
def client(store):
    return TestClient(create_app())


@pytest.fixture()
def captured(monkeypatch):
    """Capture envelopes the emitter would POST; force WEBHOOK_SERVICE_URL."""
    sent = []
    monkeypatch.setenv("WEBHOOK_SERVICE_URL", "http://webhook.test")
    monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", "tok")
    monkeypatch.setattr(events, "_post",
                        lambda url, **kw: sent.append({"url": url, **kw}) or _Resp())
    return sent


class _Resp:
    status_code = 202


def _register(client, ref="PLT-001", **overrides):
    payload = {"parcel_ref": ref, "state": "Lagos", "certificate_number": "CERT-452",
               "consent_required": ["Party A"],
               "notice_period_days": 0}  # R13: opt out of the notice window
    payload.update(overrides)
    return client.post("/api/v1/parcels", json=payload)


class TestEmitterContract:
    def test_unset_url_noop(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_SERVICE_URL", raising=False)
        assert events.emit_event("parcel.registered", "default", {}) is False

    def test_envelope_shape(self, captured):
        ok = events.emit_event("parcel.registered", "default", {"parcel_ref": "P1"})
        assert ok is True
        call = captured[0]
        assert call["url"] == "http://webhook.test/internal/events"
        assert call["headers"]["X-Internal-Token"] == "tok"
        env = call["json"]
        assert env["type"] == "parcel.registered"
        assert env["tenant_id"] == "default"
        assert env["data"] == {"parcel_ref": "P1"}
        assert set(env) == {"id", "type", "created_at", "tenant_id", "data"}

    def test_failure_never_raises(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SERVICE_URL", "http://webhook.test")
        def boom(url, **kw):
            raise ConnectionError("down")
        monkeypatch.setattr(events, "_post", boom)
        assert events.emit_event("dispute.opened", "default", {}) is False


class TestEndpointWiring:
    def test_parcel_registered_event(self, client, captured):
        _register(client)
        types = [c["json"]["type"] for c in captured]
        assert "parcel.registered" in types

    def test_conflict_events_on_duplicate(self, client, captured):
        _register(client)
        captured.clear()
        r = _register(client)  # duplicate ref -> 409
        assert r.status_code == 409
        types = [c["json"]["type"] for c in captured]
        assert "parcel.conflict.detected" in types

    def test_conflict_events_on_shared_certificate(self, client, captured):
        _register(client)
        captured.clear()
        _register(client, ref="PLT-002")  # same CERT-452 -> disputed
        types = [c["json"]["type"] for c in captured]
        assert "parcel.registered" in types
        assert "parcel.conflict.detected" in types

    def test_parcel_cleared_event(self, client, captured):
        _register(client)
        captured.clear()
        client.post("/api/v1/parcels/PLT-001/consents",
                    json={"party_name": "Party A", "confirmed": True})
        types = [c["json"]["type"] for c in captured]
        assert "parcel.cleared" in types

    def test_dispute_opened_and_resolved_events(self, client, captured):
        _register(client)
        captured.clear()
        d = client.post("/api/v1/parcels/PLT-001/disputes", json={}).json()
        client.post(f"/api/v1/disputes/{d['dispute_id']}/resolve",
                    json={"resolution": "settled"})
        types = [c["json"]["type"] for c in captured]
        assert "dispute.opened" in types
        assert "dispute.resolved" in types

    def test_revocation_events(self, client, captured):
        _register(client)
        captured.clear()
        r = client.post("/api/v1/parcels/PLT-001/revocations", json={}).json()
        client.post(f"/api/v1/revocations/{r['revocation_id']}/documents")
        client.post(f"/api/v1/revocations/{r['revocation_id']}/compensate",
                    json={"amount": 1000, "method": "transfer"})
        types = [c["json"]["type"] for c in captured]
        assert "revocation.opened" in types
        assert "revocation.compensated" in types


class TestSweeper:
    def test_newly_breached_emits_once(self, client, captured):
        _register(client)
        past = (datetime.utcnow() - timedelta(days=120)).isoformat()
        client.post("/api/v1/parcels/PLT-001/disputes", json={"filed_at": past})
        captured.clear()

        r1 = client.post("/internal/disputes/sweep")
        assert r1.json()["swept"] == 1
        assert [c["json"]["type"] for c in captured] == ["dispute.sla.breached"]
        assert captured[0]["json"]["data"]["days_open"] >= 120

        # Second sweep: already notified -> nothing re-emitted.
        captured.clear()
        r2 = client.post("/internal/disputes/sweep")
        assert r2.json()["swept"] == 0
        assert captured == []

    def test_unbreached_skipped(self, client, captured):
        _register(client)
        client.post("/api/v1/parcels/PLT-001/disputes", json={})  # filed now
        r = client.post("/internal/disputes/sweep")
        assert r.json()["swept"] == 0

    def test_resolved_not_swept(self, client, captured):
        _register(client)
        past = (datetime.utcnow() - timedelta(days=120)).isoformat()
        d = client.post("/api/v1/parcels/PLT-001/disputes", json={"filed_at": past}).json()
        client.post(f"/api/v1/disputes/{d['dispute_id']}/resolve",
                    json={"resolution": "won"})
        r = client.post("/internal/disputes/sweep")
        assert r.json()["swept"] == 0

    def test_breach_recorded_in_evidence(self, client, captured):
        _register(client)
        past = (datetime.utcnow() - timedelta(days=120)).isoformat()
        client.post("/api/v1/parcels/PLT-001/disputes", json={"filed_at": past})
        client.post("/internal/disputes/sweep")
        pack = client.get("/api/v1/parcels/PLT-001/evidence").json()
        assert any(e["event_type"] == "dispute_sla_breached" for e in pack["entries"])
        assert pack["chain_valid"] is True
