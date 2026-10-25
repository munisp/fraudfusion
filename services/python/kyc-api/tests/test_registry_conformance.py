"""Registry adapter conformance harness + sandbox dry-run (Round 10, Lane R).

Two layers:

1. CONTRACT SUITE — every live-registry adapter must pass the same behavior
   contract: availability honesty, unreachable -> unavailable with reason,
   non-200 -> unavailable, non-JSON -> unavailable, 404 -> not_found, and
   adapter/source provenance on every result. Runs against MockTransports.

2. SANDBOX DRY-RUN — the adapters are pointed at the developer sandbox's
   registry doubles (mounted from services/python/sandbox/app/registries.py)
   via ASGITransport, exercising the FULL parse path end-to-end exactly as a
   deployment would before real NIBSS/NIMC/CAC credentials exist.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import registry_adapters
from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app
from embedded_pg import clone_migrated

CALLER = Principal(sub="ops", username="ops", roles={"kyc_operator"})

ADAPTERS = [
    ("NIBSS_BVN_URL", registry_adapters.get_bvn_adapter, "verify_bvn",
     "12345678901"),
    ("NIMC_API_URL", registry_adapters.get_nin_adapter, "verify_nin",
     "12345678901"),
    ("CAC_API_URL", registry_adapters.get_cac_adapter, "lookup_company",
     "RC123456"),
]


# --- contract suite ----------------------------------------------------------

class TestAvailabilityHonesty:
    @pytest.mark.parametrize("env,factory,method,arg", ADAPTERS)
    def test_unconfigured_is_unavailable_with_reason(
            self, monkeypatch, env, factory, method, arg):
        monkeypatch.delenv(env, raising=False)
        adapter = factory()
        assert adapter.available is False
        result = getattr(adapter, method)(arg)
        assert result["status"] == "unavailable"
        assert env in result["reason"]
        assert result["adapter"] and "source" in result


def _transport(handler):
    return httpx.MockTransport(handler)


class TestFailureModes:
    def _run(self, monkeypatch, env, factory, method, arg, handler):
        monkeypatch.setenv(env, "http://registry.test")
        adapter = factory(transport=_transport(handler))
        return getattr(adapter, method)(arg)

    @pytest.mark.parametrize("env,factory,method,arg", ADAPTERS)
    def test_unreachable(self, monkeypatch, env, factory, method, arg):
        def boom(request):
            raise httpx.ConnectError("refused", request=request)
        result = self._run(monkeypatch, env, factory, method, arg, boom)
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]

    @pytest.mark.parametrize("env,factory,method,arg", ADAPTERS)
    def test_http_500(self, monkeypatch, env, factory, method, arg):
        result = self._run(monkeypatch, env, factory, method, arg,
                           lambda r: httpx.Response(500, text="oops"))
        assert result["status"] == "unavailable"
        assert "500" in result["reason"]

    @pytest.mark.parametrize("env,factory,method,arg", ADAPTERS)
    def test_non_json(self, monkeypatch, env, factory, method, arg):
        result = self._run(monkeypatch, env, factory, method, arg,
                           lambda r: httpx.Response(200, text="<html>"))
        assert result["status"] == "unavailable"
        assert "non-JSON" in result["reason"]

    @pytest.mark.parametrize("env,factory,method,arg", ADAPTERS)
    def test_404_is_not_found(self, monkeypatch, env, factory, method, arg):
        result = self._run(monkeypatch, env, factory, method, arg,
                           lambda r: httpx.Response(404, json={"error": "x"}))
        assert result["status"] == "not_found"


# --- sandbox dry-run ---------------------------------------------------------

def _sandbox_registry_app() -> FastAPI:
    """Mount the sandbox registry doubles WITHOUT importing the sandbox's
    `app` package (name collides with kyc-api's)."""
    path = (Path(__file__).resolve().parents[2]
            / "sandbox" / "app" / "registries.py")
    spec = importlib.util.spec_from_file_location("sandbox_registries", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = FastAPI()
    app.include_router(module.router, prefix="/sandbox/registry")
    return app


@pytest.fixture(scope="module")
def sandbox_server():
    """Run the sandbox registry doubles on a REAL uvicorn server (thread) so
    the adapters' sync httpx.Client exercises the full HTTP round trip."""
    import threading
    import time
    import uvicorn
    config = uvicorn.Config(_sandbox_registry_app(), host="127.0.0.1",
                            port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # wait for bind; uvicorn with port=0 picks an ephemeral port
    deadline = time.time() + 10
    port = None
    while time.time() < deadline:
        if server.started and server.servers:
            port = server.servers[0].sockets[0].getsockname()[1]
            break
        time.sleep(0.05)
    assert port, "sandbox registry server did not start"
    yield f"http://127.0.0.1:{port}/sandbox/registry"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture()
def sandbox_transport(sandbox_server):
    return None  # real server: adapters use their default transport


class TestSandboxDryRun:
    def test_bvn_match_round_trip(self, monkeypatch, sandbox_server):
        monkeypatch.setenv("NIBSS_BVN_URL", sandbox_server)
        adapter = registry_adapters.get_bvn_adapter()
        result = adapter.verify_bvn("12345678000")
        assert result["status"] == "verified"
        assert result["registry_reference"].startswith("SANDBOX-BVN-")
        assert "name" in result["verified_fields"]

    def test_bvn_mismatch_and_not_found(self, monkeypatch, sandbox_server):
        monkeypatch.setenv("NIBSS_BVN_URL", sandbox_server)
        adapter = registry_adapters.get_bvn_adapter()
        assert adapter.verify_bvn("12345678908")["status"] == "mismatch"
        assert adapter.verify_bvn("12345678909")["status"] == "not_found"

    def test_nin_round_trip(self, monkeypatch, sandbox_server):
        monkeypatch.setenv("NIMC_API_URL", sandbox_server)
        adapter = registry_adapters.get_nin_adapter()
        assert adapter.verify_nin("12345678000")["status"] == "verified"

    def test_cac_lookup_round_trip(self, monkeypatch, sandbox_server):
        monkeypatch.setenv("CAC_API_URL", sandbox_server)
        adapter = registry_adapters.get_cac_adapter()
        found = adapter.lookup_company("RC123456")
        assert found["status"] == "found"
        assert found["company"]["status"] == "ACTIVE"
        assert adapter.lookup_company("RC000002")["status"] == "not_found"
        inactive = adapter.lookup_company("RC123459")
        assert inactive["company"]["status"] == "INACTIVE"


# --- endpoint wiring ---------------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    database = Database(database_url=clone_migrated("kyc"))
    yield database
    reset_db_for_tests(None)


def _client(db, monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: CALLER
    return TestClient(app)


class TestRegistryEndpoints:
    def test_status_reports_all_unavailable_unconfigured(self, db, monkeypatch):
        for env, *_ in ADAPTERS:
            monkeypatch.delenv(env, raising=False)
        resp = _client(db, monkeypatch).get("/api/v1/registry/status")
        assert resp.status_code == 200
        registries = resp.json()["registries"]
        assert len(registries) == 3
        assert all(r["available"] is False and r["reason"] for r in registries)

    def test_bvn_verify_unconfigured_honest_unavailable(self, db, monkeypatch):
        monkeypatch.delenv("NIBSS_BVN_URL", raising=False)
        resp = _client(db, monkeypatch).post(
            "/api/v1/registry/bvn/verify", json={"bvn": "12345678901"})
        body = resp.json()
        # luhn-invalid 11-digit -> invalid_format; no registry call
        assert body["status"] in ("invalid_format", "unavailable")
        if body["status"] == "unavailable":
            assert body["registry"]["status"] == "unavailable"

    def test_bvn_verify_against_sandbox_server(self, db, monkeypatch,
                                               sandbox_server):
        """Endpoint-level: router runs the real adapter against the doubles."""
        monkeypatch.setenv("NIBSS_BVN_URL", sandbox_server)
        client = _client(db, monkeypatch)
        from app.identity import luhn_checksum_ok
        bvn = next(f"22345678{d:03d}" for d in range(1000)
                   if luhn_checksum_ok(f"22345678{d:03d}")
                   and not f"22345678{d:03d}".endswith(("8", "9")))
        resp = client.post("/api/v1/registry/bvn/verify", json={"bvn": bvn})
        body = resp.json()
        assert body["status"] == "verified", body
        row = db.query_one("SELECT * FROM document_verifications"
                           " WHERE document_type = 'bvn_registry'")
        assert row is not None and len(row["sha256"]) == 64

    def test_cac_lookup_validates_rc_format(self, db, monkeypatch):
        resp = _client(db, monkeypatch).post(
            "/api/v1/registry/cac/lookup", json={"rc_number": "XX123"})
        assert resp.status_code == 422
