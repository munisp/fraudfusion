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
from embedded_pg import clone_migrated

CALLER = Principal(sub="risk-ops", username="ops", roles={"fraud_ops"})


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url=clone_migrated("kyc"))
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


class TestScamSignals:
    def test_unconfigured_fraud_signals_is_honest_block(self, client, monkeypatch):
        monkeypatch.delenv("FRAUD_SIGNALS_URL", raising=False)
        body = client.post("/api/v1/risk/assess", json={
            "customer_id": "c-1", "amount_ngn": 500_000,
            "payee_is_new": True}).json()
        assert body["scam_signals"]["status"] == "unavailable"

    def test_no_transfer_context_skips_scam_block(self, client, monkeypatch):
        body = _assess(client).json()
        # No payee/session fields: block still present as unavailable, never fired.
        assert body["scam_signals"]["status"] == "unavailable"

    def test_app_scam_and_mule_fold_in(self, client, monkeypatch):
        monkeypatch.setenv("FRAUD_SIGNALS_URL", "http://signals:8600")
        calls = {}

        def fake_app_scam(subject_id, payload, mesh=None):
            calls["app_scam"] = payload
            return {"status": "ok", "latency_ms": 2.0,
                    "data": {"score": 0.8, "verdict": "block",
                             "factors": [{"code": "new_payee"},
                                         {"code": "payee_mule_like"}]}}

        def fake_mule(subject_id, payload, events=None, mesh=None):
            calls["mule_subject"] = subject_id
            return {"status": "ok", "latency_ms": 1.0,
                    "data": {"score": 0.6, "verdict": "review", "factors": []}}

        monkeypatch.setattr(integration.flows, "fraud_signal_app_scam",
                            fake_app_scam)
        monkeypatch.setattr(integration.flows, "fraud_signal_mule", fake_mule)
        body = client.post("/api/v1/risk/assess", json={
            "customer_id": "c-1", "amount_ngn": 500_000,
            "payee_is_new": True, "payee_id": "payee-7",
            "session_seconds": 20}).json()
        assert body["scam_signals"]["status"] == "ok"
        assert body["scam_signals"]["verdict"] == "block"
        assert calls["mule_subject"] == "payee-7"
        # The payee's mule score feeds the app-scam payload.
        assert calls["app_scam"]["payee_mule_score"] == 0.6
        # Advisory only: the rule-based score is unchanged.
        assert body["risk_score"] == 0.20

    def test_fraud_signals_outage_never_breaks_assess(self, client, monkeypatch):
        monkeypatch.setattr(
            integration.flows, "fraud_signal_app_scam",
            lambda *a, **k: {"status": "unavailable",
                             "reason": "fraud_signals unreachable"})
        monkeypatch.setattr(
            integration.flows, "fraud_signal_mule",
            lambda *a, **k: {"status": "unavailable", "reason": "down"})
        resp = client.post("/api/v1/risk/assess", json={
            "customer_id": "c-1", "payee_is_new": True, "payee_id": "p-1"})
        assert resp.status_code == 200
        assert resp.json()["scam_signals"]["status"] == "unavailable"
