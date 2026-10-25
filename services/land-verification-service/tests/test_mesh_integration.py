"""Integration tests: land due diligence enriched via the service mesh.

Covers the kyc-api PEP/sanctions screening fold-in: configured peers that
report hits produce scored factors; unconfigured/unavailable peers degrade
to an honest status block and never change the verdict.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api import mesh_boot
from api.main import create_app
from api.data_store import LandDataStore, get_land_store
from embedded_pg import clone_migrated, fresh_database


@pytest.fixture()
def store(tmp_path):
    s = LandDataStore(database_url=clone_migrated("land"))
    yield s


@pytest.fixture()
def client(store):
    app = create_app()
    app.dependency_overrides[get_land_store] = lambda: store
    return TestClient(app)


def _register(client, ref="MESH-1", registered_by=None):
    body = {
        "parcel_ref": ref, "state": "Lagos", "lga": "Eti-Osa",
        "certificate_number": f"CERT-{ref}", "owner_name": "Chief Seller",
        "notice_period_days": 0}
    if registered_by:
        body["registered_by"] = registered_by
    return client.post("/api/v1/parcels", json=body)


class TestSellerScreening:
    def test_unconfigured_peer_is_honest_block(self, client, monkeypatch):
        monkeypatch.delenv("KYC_API_URL", raising=False)
        _register(client)
        r = client.post("/api/v1/due-diligence", json={
            "state": "Lagos", "parcel_ref": "MESH-1",
            "claimed_owner": "Chief Seller"})
        body = r.json()
        block = body["signals"]["identity_screening"]
        assert block["status"] == "unavailable"
        assert "seller_pep_hit" not in {f["code"] for f in body["factors"]}

    def test_sanctions_hit_adds_high_severity_factor(self, client, monkeypatch):
        monkeypatch.setenv("KYC_API_URL", "http://kyc:8000")

        def ok(payload, m=None):
            return {"status": "ok", "data": {"is_sanctioned": True},
                    "latency_ms": 1.0}
        monkeypatch.setattr(mesh_boot.flows, "kyc_sanctions_screening", ok)
        monkeypatch.setattr(mesh_boot.flows, "kyc_pep_screening",
                            lambda payload, m=None: {
                                "status": "ok", "data": {"is_pep": False}})
        _register(client)
        r = client.post("/api/v1/due-diligence", json={
            "state": "Lagos", "parcel_ref": "MESH-1",
            "claimed_owner": "Chief Seller"})
        body = r.json()
        assert body["signals"]["identity_screening"]["status"] == "ok"
        assert "seller_sanctions_hit" in {f["code"] for f in body["factors"]}
        assert body["verdict"] == "high_risk"

    def test_peer_error_never_breaks_due_diligence(self, client, monkeypatch):
        monkeypatch.setenv("KYC_API_URL", "http://kyc:8000")
        unavailable = {"status": "unavailable", "reason": "kyc unreachable"}
        monkeypatch.setattr(mesh_boot.flows, "kyc_sanctions_screening",
                            lambda payload, m=None: dict(unavailable))
        monkeypatch.setattr(mesh_boot.flows, "kyc_pep_screening",
                            lambda payload, m=None: dict(unavailable))
        _register(client)
        r = client.post("/api/v1/due-diligence", json={
            "state": "Lagos", "parcel_ref": "MESH-1",
            "claimed_owner": "Chief Seller"})
        assert r.status_code == 200
        body = r.json()
        assert body["signals"]["identity_screening"]["pep"]["status"] == \
            "unavailable"


class TestMeshStatusEndpoint:
    def test_integrations_status(self, client, monkeypatch):
        monkeypatch.delenv("KYC_API_URL", raising=False)
        r = client.get("/api/v1/integrations/status")
        assert r.status_code == 200
        body = r.json()
        assert body["mesh"] == "ok"
        assert "kyc" in body["services"]
        assert body["services"]["kyc"]["configured"] is False


class TestIssuanceAnomaly:
    def test_unconfigured_fraud_signals_is_honest_block(self, client, monkeypatch):
        monkeypatch.delenv("FRAUD_SIGNALS_URL", raising=False)
        _register(client)
        body = client.post("/api/v1/due-diligence", json={
            "state": "Lagos", "parcel_ref": "MESH-1"}).json()
        assert body["signals"]["issuance_anomaly"]["status"] == "unavailable"

    def test_issuance_anomaly_adds_factor(self, client, monkeypatch):
        monkeypatch.setenv("FRAUD_SIGNALS_URL", "http://signals:8600")
        monkeypatch.setattr(
            mesh_boot.flows, "fraud_signal_issuance",
            lambda subject_id, payload, mesh=None: {
                "status": "ok", "latency_ms": 2.0,
                "data": {"score": 0.85, "verdict": "block",
                         "factors": [{"code": "officer_velocity_outlier"}]}})
        _register(client, ref="MESH-2", registered_by="officer-9")
        body = client.post("/api/v1/due-diligence", json={
            "state": "Lagos", "parcel_ref": "MESH-2"}).json()
        block = body["signals"]["issuance_anomaly"]
        assert block["status"] == "ok" and block["verdict"] == "block"
        assert "issuance_anomaly" in {f["code"] for f in body["factors"]}

    def test_clean_issuance_no_factor(self, client, monkeypatch):
        monkeypatch.setattr(
            mesh_boot.flows, "fraud_signal_issuance",
            lambda subject_id, payload, mesh=None: {
                "status": "ok", "latency_ms": 1.0,
                "data": {"score": 0.05, "verdict": "clear", "factors": []}})
        _register(client, ref="MESH-3", registered_by="officer-1")
        body = client.post("/api/v1/due-diligence", json={
            "state": "Lagos", "parcel_ref": "MESH-3"}).json()
        assert body["signals"]["issuance_anomaly"]["verdict"] == "clear"
        assert "issuance_anomaly" not in {f["code"] for f in body["factors"]}
