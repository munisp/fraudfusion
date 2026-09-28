"""Tests for identity-theft-detector registry adapters + cross-reference.

Run: python3 -m pytest tests/ -q   (from services/python/identity-theft-detector)
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main as svc  # noqa: E402
from identity_store import IdentityStore, reset_store_for_tests  # noqa: E402
from registry import HTTPRegistryAdapter, LocalRegistryAdapter  # noqa: E402


@pytest.fixture()
def store(tmp_path):
    s = IdentityStore(database_url="", sqlite_path=str(tmp_path / "id.db"))
    yield s
    reset_store_for_tests(None)


def make_client(store, claims=None):
    claims = claims or {"active": True, "sub": "analyst-1",
                        "realm_access": {"roles": ["analyst"]}}
    app = svc.app
    app.dependency_overrides[svc.authenticate] = lambda: claims
    app.dependency_overrides[svc.get_store] = lambda: store
    return TestClient(app, raise_server_exceptions=False)


class TestLocalRegistryAdapter:
    def test_lookup_found_synthetic_seed(self, store):
        adapter = LocalRegistryAdapter("bvn", store)
        result = adapter.lookup("22345678901")
        assert result["status"] == "found"
        assert result["is_synthetic"] is True
        assert result["record"]["full_name"].startswith("SYNTHETIC")

    def test_lookup_not_found_is_honest(self, store):
        adapter = LocalRegistryAdapter("nin", store)
        result = adapter.lookup("99999999999")
        assert result["status"] == "not_found"
        assert "reason" in result

    def test_reverse_lookup_by_phone(self, store):
        adapter = LocalRegistryAdapter("bvn", store)
        hits = adapter.search_by_contact(phone="+2348012345678")
        assert {h["id_value"] for h in hits} == {"22345678901", "22345678903"}


class TestHTTPRegistryAdapter:
    def test_timeout_fails_closed_unavailable(self, store):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route", request=request)

        adapter = HTTPRegistryAdapter("bvn", "https://nibss.example.test",
                                      transport=httpx.MockTransport(handler))
        result = adapter.lookup("22345678901")
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]

    def test_http_200_returns_record(self, store):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"found": True, "record": {"full_name": "Real Person"}})

        adapter = HTTPRegistryAdapter("nin", "https://nimc.example.test",
                                      transport=httpx.MockTransport(handler))
        result = adapter.lookup("12345678901")
        assert result["status"] == "found"
        assert result["record"]["full_name"] == "Real Person"


class TestCrossReference:
    def test_seeded_phone_returns_real_cluster(self, store):
        client = make_client(store)
        resp = client.post("/cross-reference-check",
                           json={"user_id": "cust-syn-9", "phone_number": "+2348012345678"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # phone +2348012345678 is shared by cust-syn-1 and cust-syn-2
        assert set(body["matched_customers"]) == {"cust-syn-1", "cust-syn-2"}
        assert body["clusters"], "expected an identity cluster"
        big = [c for c in body["clusters"] if c["cluster_size"] > 1]
        assert big and set(big[0]["customers"]) == {"cust-syn-1", "cust-syn-2"}
        assert any("+2348012345678" in s for s in big[0]["shared_identifiers"])
        assert big[0]["evidence"], "cluster must carry evidence links"
        assert body["risk_score"] >= 0.6
        sources = {s["source"] for s in body["searched_sources"]}
        assert "customer_identifiers" in sources and "identity_theft_alerts" in sources

    def test_no_match_returns_empty_with_searched_sources(self, store):
        client = make_client(store)
        resp = client.post("/cross-reference-check",
                           json={"user_id": "nobody", "phone_number": "+2340000000000",
                                 "email": "nobody@nowhere.test"})
        body = resp.json()
        assert body["matched_customers"] == []
        assert body["clusters"] == []
        assert body["searched_sources"], "sources must be listed even when empty"
        assert body["all_checks_passed"] is True

    def test_nin_forward_lookup_and_alert_evidence(self, store):
        store.execute(
            "INSERT INTO identity_theft_alerts (user_id, alert_type, risk_level, details)"
            " VALUES ('cust-syn-1', 'bvn_takeover', 'high', '{\"phone_number\": \"+2348012345678\"}')"
        )
        client = make_client(store)
        resp = client.post("/cross-reference-check",
                           json={"user_id": "cust-syn-9", "nin": "12345678901",
                                 "phone_number": "+2348012345678"})
        body = resp.json()
        assert body["cross_reference_results"]["nin"]["status"] == "found"
        assert any(e["source"] == "identity_theft_alerts"
                   for c in body["clusters"] for e in c["evidence"]) or body["alerts"]
        assert body["risk_score"] > 0


class TestVerifyIdentityRegistries:
    def test_known_bvn_is_registry_checked(self, store):
        client = make_client(store)
        resp = client.post("/verify-identity", json={
            "user_id": "u-1", "bvn": "22345678901",
            "first_name": "Adaeze", "last_name": "Eze",
            "date_of_birth": "1990-05-20", "phone_number": "+2348012345678",
        })
        body = resp.json()
        assert body["verification_results"]["bvn_registry"] == "found"
        assert body["verification_status"] == "registry_verified"
        assert body["is_verified"] is True

    def test_unknown_bvn_is_not_verified(self, store):
        client = make_client(store)
        resp = client.post("/verify-identity", json={
            "user_id": "u-2", "bvn": "99999999999",
            "first_name": "Ghost", "last_name": "Person",
            "date_of_birth": "1990-01-01", "phone_number": "+2348012345678",
        })
        body = resp.json()
        assert body["verification_results"]["bvn_registry"] == "not_found"
        assert body["is_verified"] is False
        assert "bvn_not_in_registry" in body["red_flags"]


class TestRegistryImport:
    CSV = "bvn,full_name,date_of_birth,phone_number,email\n" \
          "22345678999,Real Imported Person,1980-01-01,+2348000000001,real@example.test\n" \
          "bad,Bad Row,,,\n"

    def test_admin_import_upserts_rows(self, store):
        claims = {"active": True, "sub": "admin-1", "realm_access": {"roles": ["admin"]}}
        client = make_client(store, claims)
        resp = client.post("/admin/registry/import",
                           data={"registry": "bvn"},
                           files={"file": ("bvn-2026-09.csv", self.CSV, "text/csv")})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["imported"] == 1
        assert body["rejected_count"] == 1
        assert body["provenance"] == "admin-import:bvn-2026-09.csv"
        row = store.query_one("SELECT * FROM bvn_registry WHERE bvn = '22345678999'")
        assert row["full_name"] == "Real Imported Person"
        assert row["is_synthetic"] == 0
        assert row["imported_by"] == "admin-1"

    def test_import_requires_admin_role(self, store):
        client = make_client(store)  # analyst only
        resp = client.post("/admin/registry/import",
                           data={"registry": "bvn"},
                           files={"file": ("x.csv", self.CSV, "text/csv")})
        assert resp.status_code == 403
