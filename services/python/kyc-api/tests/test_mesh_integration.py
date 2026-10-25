"""Integration tests: kyc-api risk endpoint enriched via the service mesh.

Covers the intel-service national-intelligence fold-in on /risk/assess and
the /integrations/status mesh-health endpoint: configured peers enrich the
response; unconfigured peers degrade to honest status blocks; the score
itself is never moved by advisory enrichment.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import integration
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app

CALLER = Principal(sub="risk-ops", username="ops", roles={"fraud_ops"})


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "kyc.db"))
    yield database
    reset_db_for_tests(None)


@pytest.fixture()
def client(db):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: CALLER
    return TestClient(app)


def _assess(client):
    return client.post("/api/v1/risk/assess",
                       json={"customer_id": "c-1", "amount_ngn": 500_000})


class TestIntelEnrichment:
    def test_unconfigured_intel_is_honest_block(self, client, monkeypatch):
        monkeypatch.delenv("INTEL_SERVICE_URL", raising=False)
        body = _assess(client).json()
        assert body["national_intelligence"]["status"] == "unavailable"

    def test_intel_summary_enriches_response(self, client, monkeypatch):
        monkeypatch.setenv("INTEL_SERVICE_URL", "http://intel:8500")
        monkeypatch.setattr(
            integration.flows, "intel_national_summary",
            lambda m=None: {"status": "ok",
                            "data": {"national_rate": 0.041,
                                     "trend": "rising"},
                            "latency_ms": 3.2})
        resp = _assess(client)
        body = resp.json()
        assert body["national_intelligence"]["status"] == "ok"
        assert body["national_intelligence"]["data"]["national_rate"] == 0.041
        # Advisory only: the rule-based score is unchanged.
        assert body["risk_score"] == 0.20

    def test_intel_outage_never_breaks_assess(self, client, monkeypatch):
        monkeypatch.setenv("INTEL_SERVICE_URL", "http://intel:8500")
        monkeypatch.setattr(
            integration.flows, "intel_national_summary",
            lambda m=None: {"status": "unavailable",
                            "reason": "intel unreachable (ConnectError)"})
        resp = _assess(client)
        assert resp.status_code == 200
        assert resp.json()["national_intelligence"]["status"] == "unavailable"


class TestMeshStatus:
    def test_integrations_status_endpoint(self, client, monkeypatch):
        monkeypatch.delenv("INTEL_SERVICE_URL", raising=False)
        r = client.get("/api/v1/integrations/status")
        assert r.status_code == 200
        body = r.json()
        assert body["mesh"] == "ok"
        assert "intel" in body["services"]
        assert body["services"]["intel"]["configured"] is False
