"""Sandbox lands-registry double tests (Round 11).

Covers /sandbox/registry/lands/owner and /lands/history magic values, plus a
conformance round trip: land-verification-service's HttpLandsRegistryAdapter
pointed at the double parses owner/history correctly (the same dry-run story
as Round 10's BVN/NIN/CAC doubles).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import create_app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(create_app())


BASE = "/sandbox/registry/lands"


class TestLandsOwner:
    def test_found_default(self, client):
        r = client.get(f"{BASE}/owner", params={"state": "lagos", "certificate_number": "CERT-4521"})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "found"
        assert body["owner_name"] == "SANDBOX LANDOWNER 4521"
        assert body["synthetic"] is True

    def test_ending_9_not_found(self, client):
        r = client.get(f"{BASE}/owner", params={"state": "lagos", "certificate_number": "CERT-0009"})
        assert r.status_code == 404

    def test_ending_8_stranger_mismatch(self, client):
        r = client.get(f"{BASE}/owner", params={"state": "lagos", "certificate_number": "CERT-0008"})
        assert r.json()["owner_name"] == "SANDBOX STRANGER"

    def test_address_only_lookup(self, client):
        r = client.get(f"{BASE}/owner",
                       params={"state": "lagos", "property_address": "Plot 1, Ikoyi"})
        assert r.status_code == 200

    def test_missing_state_422(self, client):
        r = client.get(f"{BASE}/owner", params={"certificate_number": "CERT-1"})
        assert r.status_code == 422

    def test_missing_identifier_422(self, client):
        r = client.get(f"{BASE}/owner", params={"state": "lagos"})
        assert r.status_code == 422


class TestLandsHistory:
    def test_history_records(self, client):
        r = client.get(f"{BASE}/history", params={"state": "lagos", "certificate_number": "CERT-4521"})
        body = r.json()
        assert body["status"] == "found"
        assert len(body["records"]) == 2
        assert body["records"][-1]["owner_name"] == "SANDBOX LANDOWNER 4521"

    def test_ending_9_not_found(self, client):
        r = client.get(f"{BASE}/history", params={"state": "lagos", "certificate_number": "CERT-0009"})
        assert r.status_code == 404


class TestAdapterConformance:
    """HttpLandsRegistryAdapter (land-verification-service) against the double,
    served by a REAL uvicorn thread (the adapter's httpx.Client is sync, so
    ASGITransport cannot be used — same constraint as Round 10)."""

    @pytest.fixture(scope="class")
    def lands_url(self):
        import threading
        import time
        import uvicorn
        config = uvicorn.Config(create_app(), host="127.0.0.1", port=0,
                                log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 10
        port = None
        while time.time() < deadline:
            if server.started and server.servers:
                port = server.servers[0].sockets[0].getsockname()[1]
                break
            time.sleep(0.05)
        assert port, "sandbox server did not start"
        yield f"http://127.0.0.1:{port}/sandbox/registry/lands"
        server.should_exit = True
        thread.join(timeout=5)

    def _adapter(self, base_url):
        land_api = Path(__file__).resolve().parents[3] / "land-verification-service"
        sys.path.insert(0, str(land_api))
        try:
            from api.registry_adapters import HttpLandsRegistryAdapter
        finally:
            sys.path.remove(str(land_api))
        return HttpLandsRegistryAdapter(base_url=base_url)

    def test_owner_round_trip(self, lands_url):
        result = self._adapter(lands_url).owner(state="lagos", certificate_number="CERT-4521")
        assert result["status"] == "found"
        assert result["owner_name"] == "SANDBOX LANDOWNER 4521"

    def test_history_round_trip(self, lands_url):
        result = self._adapter(lands_url).history(state="lagos", certificate_number="CERT-4521")
        assert result["status"] == "found"
        assert len(result["ownership_history"]) == 2

    def test_not_found_round_trip(self, lands_url):
        result = self._adapter(lands_url).owner(state="lagos", certificate_number="CERT-0009")
        assert result["status"] == "not_found"
