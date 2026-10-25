"""Contract tests for the auto-metering middleware (integration/metering.py).

The middleware is exercised against a real FastAPI app with a stubbed
billing mesh client — no live services. Covers: matched-route metering,
X-Request-Id idempotency keys, unmatched routes, unattributed requests,
failed responses never billed, and fail-closed billing outages.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import metering
from metering import UsageMeteringMiddleware, metering_stats


class StubBilling:
    """Records what the middleware posted, or simulates an outage."""

    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    def post(self, path, payload):
        self.calls.append((path, payload))
        if not self.ok:
            return {"status": "unavailable", "reason": "billing unreachable (ConnectError)"}
        return {"status": "ok", "data": {"recorded": True}}


def _app(billing, resolver=None):
    app = FastAPI()

    @app.post("/api/v1/signals/{detector}")
    def score(detector: str):
        return {"detector": detector, "verdict": "clear"}

    @app.post("/api/v1/signals/shadow/{detector}")
    def shadow(detector: str):
        return {"detector": detector, "mode": "shadow"}

    @app.post("/api/v1/failing")
    def failing():
        raise HTTPException(status_code=422, detail="bad input")

    @app.get("/api/v1/signals/scores/{detector}")
    def scores(detector: str):
        return {"rows": 0}

    app.add_middleware(
        UsageMeteringMiddleware,
        routes=[("POST", "/api/v1/signals", "fraud_score"),
                ("POST", "/api/v1/failing", "fraud_score")],
        service_name="fraud-signals",
        tenant_resolver=resolver,
        billing=billing,
    )
    return TestClient(app)


@pytest.fixture(autouse=True)
def _stats():
    metering.reset_metering_stats()
    yield
    metering.reset_metering_stats()


TENANT = {"x-tenant-id": "tenant-1"}


def test_matched_post_is_metered_with_idempotency_key():
    billing = StubBilling()
    client = _app(billing)
    resp = client.post("/api/v1/signals/mule", headers={**TENANT, "x-request-id": "req-42"})
    assert resp.status_code == 200
    assert len(billing.calls) == 1
    path, payload = billing.calls[0]
    assert path == "/internal/usage"
    assert payload["tenant_id"] == "tenant-1"
    assert payload["service"] == "fraud-signals"
    assert payload["operation"] == "fraud_score"
    assert payload["units"] == 1
    assert payload["idempotency_key"] == "fraud-signals:req-42"
    assert metering_stats()["metered"] == 1


def test_shadow_route_also_metered():
    billing = StubBilling()
    client = _app(billing)
    resp = client.post("/api/v1/signals/shadow/mule", headers=TENANT)
    assert resp.status_code == 200
    assert len(billing.calls) == 1
    assert billing.calls[0][1]["operation"] == "fraud_score"


def test_unmatched_route_not_metered():
    billing = StubBilling()
    client = _app(billing)
    resp = client.get("/api/v1/signals/scores/mule", headers=TENANT)
    assert resp.status_code == 200
    assert billing.calls == []
    assert metering_stats()["skipped_unmatched"] == 1


def test_unattributed_request_skipped_not_guessed():
    billing = StubBilling()
    client = _app(billing)
    resp = client.post("/api/v1/signals/mule")  # no tenant header
    assert resp.status_code == 200
    assert billing.calls == []
    assert metering_stats()["skipped_unattributed"] == 1


def test_failed_response_never_billed():
    billing = StubBilling()
    client = _app(billing)
    resp = client.post("/api/v1/failing", headers=TENANT)
    assert resp.status_code == 422
    assert billing.calls == []
    assert metering_stats()["skipped_failed_response"] == 1


def test_billing_outage_fails_closed_and_is_counted():
    billing = StubBilling(ok=False)
    client = _app(billing)
    resp = client.post("/api/v1/signals/mule", headers=TENANT)
    # The client request still succeeds; the loss is honestly counted.
    assert resp.status_code == 200
    assert metering_stats()["failed"] == 1
    assert metering_stats()["metered"] == 0


def test_custom_tenant_resolver():
    billing = StubBilling()
    client = _app(billing, resolver=lambda req: req.headers.get("x-api-key-tenant"))
    resp = client.post("/api/v1/signals/mule", headers={"x-api-key-tenant": "tenant-9"})
    assert resp.status_code == 200
    assert billing.calls[0][1]["tenant_id"] == "tenant-9"
