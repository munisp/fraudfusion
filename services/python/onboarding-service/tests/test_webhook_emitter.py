"""Tests for the kyb.verification.completed webhook emitter wiring.

The emitter itself (app/webhook_emitter.py) is contract-tested in the
webhook-service suite; these tests verify that _run_kyb_verification fires
it with the contract payload (application id, verdict, doc sha256s only —
NO PII) and never lets emission failures reach the request path.

Run: python3 -m pytest tests/test_webhook_emitter.py -q
"""

from __future__ import annotations

import base64
import hashlib
import io

import pytest
from fastapi.testclient import TestClient

from app import kyb_verification
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

TENANT = Principal(sub="user-tenant-1", username="ada", roles=set())


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "onboarding.db"))
    yield database
    reset_db_for_tests(None)


@pytest.fixture(autouse=True)
def _no_optional_backends(monkeypatch):
    monkeypatch.setattr(kyb_verification, "_load_docling_adapter",
                        lambda: (None, None))
    monkeypatch.setattr(kyb_verification, "_load_local_cv", lambda: None)


def make_client(db, principal=TENANT):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def _png_b64() -> str:
    from PIL import Image

    img = Image.new("RGB", (64, 64), (200, 30, 30))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def _submit(client):
    return client.post("/api/v1/onboarding/kyb", json={
        "business_name": "Acme Logistics Ltd",
        "cac_number": "RC1234567",
        "business_type": "limited_liability",
        "contact_email": "ops@acme.example.com",
        "documents": [{"type": "utility_bill", "reference": "s3://kyb/bill.png",
                       "content": _png_b64()}],
    })


def test_kyb_verification_emits_contract_payload(db, monkeypatch):
    emitted = []
    monkeypatch.setattr("app.webhook_emitter.emit_event",
                        lambda t, tenant, data, **kw: emitted.append((t, tenant, data)) or True)
    resp = _submit(make_client(db))
    assert resp.status_code == 201, resp.text
    assert len(emitted) == 1
    event_type, tenant_id, data = emitted[0]
    assert event_type == "kyb.verification.completed"
    assert tenant_id == "default"  # no tenants row in this fixture
    assert data["application_id"] == resp.json()["applicationId"]
    assert data["verdict"] in ("verified", "manual_review", "rejected",
                               "engine_unavailable")
    doc_sha = hashlib.sha256(base64.b64decode(_png_b64())).hexdigest()
    assert data["document_sha256s"] == [doc_sha]
    # NO PII: neither business name nor CAC number may leave the service.
    blob = str(data)
    assert "Acme" not in blob and "RC1234567" not in blob


def test_unconfigured_webhook_url_is_noop_and_submission_succeeds(db, monkeypatch):
    """Fire-and-forget: with WEBHOOK_SERVICE_URL unset the emitter no-ops
    and the request path is unaffected."""
    monkeypatch.delenv("WEBHOOK_SERVICE_URL", raising=False)
    monkeypatch.delenv("WEBHOOK_INTERNAL_TOKEN", raising=False)
    resp = _submit(make_client(db))
    assert resp.status_code == 201, resp.text
