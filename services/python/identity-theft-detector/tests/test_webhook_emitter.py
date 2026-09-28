"""Tests for the identity.exposure.detected webhook emitter wiring.

The emitter itself (webhook_emitter.py) is contract-tested in the
webhook-service suite; these tests verify that exposure imports emit the
event ONLY for newly written alerts (deduped re-imports emit nothing) with
hash refs only — never plaintext identifiers.

Run: python3 -m pytest tests/test_webhook_emitter.py -q
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main as svc  # noqa: E402
from identity_store import IdentityStore, reset_store_for_tests  # noqa: E402


@pytest.fixture()
def store(tmp_path):
    s = IdentityStore(database_url="", sqlite_path=str(tmp_path / "id.db"))
    yield s
    reset_store_for_tests(None)


ADMIN_CLAIMS = {"active": True, "sub": "admin-1", "realm_access": {"roles": ["admin"]}}

BATCH = {
    "batch_id": "leak-2026-09-30",
    "source_note": "lawfully obtained indicator batch",
    "rows": [
        {"identifier_type": "bvn", "identifier_value": "22345678901",
         "breach_ref": "BR-1"},
    ],
}


def make_client(store):
    app = svc.app
    app.dependency_overrides[svc.authenticate] = lambda: ADMIN_CLAIMS
    app.dependency_overrides[svc.get_store] = lambda: store
    return TestClient(app, raise_server_exceptions=False)


def test_new_alert_emits_hash_only_event(store, monkeypatch):
    emitted = []
    monkeypatch.setattr("exposure.emit_event",
                        lambda t, tenant, data, **kw: emitted.append((t, tenant, data)) or True)
    store.execute(
        "INSERT INTO customer_identifiers (customer_id, id_type, id_value)"
        " VALUES ('cust-1', 'bvn', '22345678901')")
    resp = make_client(store).post("/admin/exposure/import", json=BATCH)
    assert resp.status_code == 200 and resp.json()["alerts_written"] == 1
    assert len(emitted) == 1
    event_type, tenant_id, data = emitted[0]
    assert event_type == "identity.exposure.detected"
    assert tenant_id == "default"
    assert data["alert_type"] == "exposure_detected"
    assert data["alert_id"].startswith("exp-")
    assert data["identifier_type"] == "bvn"
    assert data["identifier_hash"] == hashlib.sha256(b"22345678901").hexdigest()
    assert data["breach_ref"] == "BR-1" and data["risk_level"] == "high"
    # NO PII: plaintext identifier never leaves the service.
    assert "22345678901" not in str(data) and "cust-1" not in str(data)


def test_deduped_reimport_emits_nothing(store, monkeypatch):
    emitted = []
    monkeypatch.setattr("exposure.emit_event",
                        lambda t, tenant, data, **kw: emitted.append(t) or True)
    store.execute(
        "INSERT INTO customer_identifiers (customer_id, id_type, id_value)"
        " VALUES ('cust-1', 'bvn', '22345678901')")
    client = make_client(store)
    assert client.post("/admin/exposure/import", json=BATCH).json()["alerts_written"] == 1
    assert len(emitted) == 1
    second = client.post("/admin/exposure/import", json=BATCH).json()
    assert second["alerts_written"] == 0 and second["alerts_deduped"] == 1
    assert len(emitted) == 1  # deduped alert emits no second event


def test_unconfigured_webhook_url_is_noop(store, monkeypatch):
    monkeypatch.delenv("WEBHOOK_SERVICE_URL", raising=False)
    store.execute(
        "INSERT INTO customer_identifiers (customer_id, id_type, id_value)"
        " VALUES ('cust-1', 'bvn', '22345678901')")
    resp = make_client(store).post("/admin/exposure/import", json=BATCH)
    assert resp.status_code == 200 and resp.json()["alerts_written"] == 1
