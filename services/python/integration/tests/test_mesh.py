"""Contract tests for the service mesh (services/python/integration).

Covers the fail-closed contract every cross-service call relies on:
unconfigured peers, transport errors, HTTP errors, auth headers, latency
provenance, the status aggregator, and the typed flows — all against
httpx.MockTransport, no live services.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import flows
import mesh as mesh_mod
from mesh import Mesh, MeshService


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("KYC_API_URL", "LAND_SERVICE_URL", "INTEL_SERVICE_URL",
                "ONBOARDING_SERVICE_URL", "BACKOFFICE_API_URL",
                "BILLING_SERVICE_URL", "WEBHOOK_SERVICE_URL",
                "DOC_INTEL_URL", "KYC_API_KEY", "INTEL_INTERNAL_TOKEN",
                "FRAUDFUSION_INTERNAL_TOKEN"):
        monkeypatch.delenv(var, raising=False)


def _ok_transport(route_body: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json=route_body or {"echo": request.url.path})
    return httpx.MockTransport(handler)


class TestFailClosed:
    def test_unconfigured_service_is_unavailable(self):
        svc = MeshService("intel")
        assert svc.available is False
        result = svc.get("/v1/intel/national/summary")
        assert result["status"] == "unavailable"
        assert "INTEL_SERVICE_URL" in result["reason"]

    def test_unreachable_peer_is_unavailable(self, monkeypatch):
        monkeypatch.setenv("INTEL_SERVICE_URL", "http://intel:8500")

        def boom(request):
            raise httpx.ConnectError("refused")
        svc = MeshService("intel", transport=httpx.MockTransport(boom))
        result = svc.get("/health")
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]

    def test_http_error_is_unavailable(self, monkeypatch):
        monkeypatch.setenv("KYC_API_URL", "http://kyc:8000")
        svc = MeshService("kyc", transport=httpx.MockTransport(
            lambda req: httpx.Response(401, json={"detail": "no scope"})))
        result = svc.post("/api/v1/screening/pep", {"name": "X"})
        assert result["status"] == "unavailable"
        assert "401" in result["reason"]


class TestContracts:
    def test_ok_call_carries_provenance(self, monkeypatch):
        monkeypatch.setenv("INTEL_SERVICE_URL", "http://intel:8500")
        svc = MeshService("intel", transport=_ok_transport({"rate": 0.041}))
        result = svc.get("/v1/intel/national/summary")
        assert result["status"] == "ok"
        assert result["data"] == {"rate": 0.041}
        assert result["adapter"] == "service_mesh"
        assert result["service"] == "intel"
        assert result["source"] == "http://intel:8500"
        assert result["latency_ms"] >= 0

    def test_internal_token_and_api_key_headers(self, monkeypatch):
        monkeypatch.setenv("KYC_API_URL", "http://kyc:8000")
        monkeypatch.setenv("KYC_API_KEY", "svc-key-1")
        monkeypatch.setenv("FRAUDFUSION_INTERNAL_TOKEN", "tok-1")
        seen = {}

        def handler(request):
            seen.update(dict(request.headers))
            return httpx.Response(200, json={"is_pep": False})
        svc = MeshService("kyc", transport=httpx.MockTransport(handler))
        svc.post("/api/v1/screening/pep", {"name": "A B"})
        assert seen.get("x-internal-token") == "tok-1"
        assert seen.get("x-api-key") == "svc-key-1"

    def test_mesh_status_reports_all_services(self, monkeypatch):
        monkeypatch.setenv("INTEL_SERVICE_URL", "http://intel:8500")
        m = Mesh(transport=_ok_transport())
        status = m.status()
        assert status["intel"]["configured"] is True
        assert status["intel"]["reachable"] is True
        assert status["kyc"]["configured"] is False
        assert status["kyc"]["reachable"] is False
        assert set(status) == set(mesh_mod.REGISTRY)


class TestFlows:
    def test_intel_summary_flow(self, monkeypatch):
        monkeypatch.setenv("INTEL_SERVICE_URL", "http://intel:8500")
        m = Mesh(transport=_ok_transport({"national_rate": 0.04}))
        result = flows.intel_national_summary(m)
        assert result["status"] == "ok"
        assert result["data"]["national_rate"] == 0.04

    def test_kyc_screening_flow(self, monkeypatch):
        monkeypatch.setenv("KYC_API_URL", "http://kyc:8000")
        m = Mesh(transport=_ok_transport({"is_sanctioned": True}))
        result = flows.kyc_sanctions_screening("Bad Actor", m)
        assert result["status"] == "ok"
        assert result["data"]["is_sanctioned"] is True

    def test_land_status_flow(self, monkeypatch):
        monkeypatch.setenv("LAND_SERVICE_URL", "http://land:8200")
        m = Mesh(transport=_ok_transport({"verdict": "clear"}))
        result = flows.land_verification_status("v-1", m)
        assert result["status"] == "ok"

    def test_flow_on_unconfigured_peer_is_honest(self):
        result = flows.onboarding_kyb_status("app-1", Mesh())
        assert result["status"] == "unavailable"
