"""Tests for lane I1: enrollment-source tracing + exposure detection/redress.

Run: python3 -m pytest tests/ -q   (from services/python/identity-theft-detector)
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main as svc  # noqa: E402
from cross_reference import enrollment_agent_rollup  # noqa: E402
from identity_store import IdentityStore, reset_store_for_tests  # noqa: E402


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


ADMIN_CLAIMS = {"active": True, "sub": "admin-1", "realm_access": {"roles": ["admin"]}}

BREACH_BATCH = {
    "batch_id": "efcc-crackdown-2026-09",
    "source_note": "EFCC account-supplier crackdown, lawfully obtained indicators",
    "rows": [
        {"identifier_type": "bvn", "identifier_value": "22345678901",
         "breach_ref": "EFCC-2026-0917", "observed_at": "2026-09-20T10:00:00Z"},
        {"identifier_type": "phone", "identifier_value": "+2348012345678",
         "breach_ref": "EFCC-2026-0917", "observed_at": "2026-09-20T10:00:00Z"},
        {"identifier_type": "email", "identifier_value": "nobody@nowhere.test",
         "breach_ref": "EFCC-2026-0917"},
    ],
}


class TestEnrollmentSourceTracing:
    """Task 1: duplicate clusters / NIN<->BVN conflicts traceable to source."""

    def test_registry_import_accepts_enrollment_columns(self, store):
        csv = (
            "bvn,full_name,enrollment_source,enrollment_agent_id,enrollment_channel,enrolled_at\n"
            "22345678988,Traced Person,bank_branch,agent-LAG-042,branch,2024-03-01T09:00:00Z\n"
        )
        client = make_client(store, ADMIN_CLAIMS)
        resp = client.post("/admin/registry/import", data={"registry": "bvn"},
                           files={"file": ("bvn.csv", csv, "text/csv")})
        assert resp.status_code == 200, resp.text
        row = store.query_one("SELECT * FROM bvn_registry WHERE bvn = '22345678988'")
        assert row["enrollment_source"] == "bank_branch"
        assert row["enrollment_agent_id"] == "agent-LAG-042"

    def test_import_without_enrollment_columns_defaults_unknown(self, store):
        csv = "bvn,full_name\n22345678977,No Source Person\n"
        client = make_client(store, ADMIN_CLAIMS)
        resp = client.post("/admin/registry/import", data={"registry": "bvn"},
                           files={"file": ("bvn.csv", csv, "text/csv")})
        assert resp.status_code == 200, resp.text
        row = store.query_one("SELECT * FROM bvn_registry WHERE bvn = '22345678977'")
        assert row["enrollment_source"] == "unknown"  # backward compatible

    def test_duplicate_cluster_surfaces_differing_enrollment_sources(self, store):
        store.execute(
            "UPDATE customer_identifiers SET enrollment_source = 'bank_branch',"
            " enrollment_agent_id = 'agent-A' WHERE customer_id = 'cust-syn-1'"
            " AND id_type = 'phone' AND id_value = '+2348012345678'")
        store.execute(
            "UPDATE customer_identifiers SET enrollment_source = 'sim_registration_agent',"
            " enrollment_agent_id = 'agent-B' WHERE customer_id = 'cust-syn-2'"
            " AND id_type = 'phone' AND id_value = '+2348012345678'")
        client = make_client(store)
        resp = client.post("/cross-reference-check",
                           json={"user_id": "u-x", "phone_number": "+2348012345678"})
        assert resp.status_code == 200, resp.text
        big = [c for c in resp.json()["clusters"] if c["cluster_size"] > 1]
        assert big, "expected duplicate-identity cluster"
        traces = big[0]["enrollment_traces"]
        phone_trace = [t for t in traces if t["shared_identifier"] == "phone:+2348012345678"]
        assert phone_trace, "cluster evidence must trace shared identifier to enrollment source"
        assert phone_trace[0]["differing_enrollment_sources"] == ["bank_branch", "sim_registration_agent"]
        assert phone_trace[0]["differing_enrollment_agents"] == ["agent-A", "agent-B"]
        holders = {e["customer_id"]: e["enrollment_source"] for e in phone_trace[0]["enrollments"]}
        assert holders == {"cust-syn-1": "bank_branch", "cust-syn-2": "sim_registration_agent"}

    def test_nin_bvn_inconsistency_carries_enrollment_tracing(self, store):
        store.execute(
            "UPDATE nin_registry SET enrollment_source = 'nimc_fep',"
            " enrollment_agent_id = 'fep-77' WHERE nin = '12345678901'")
        store.execute(
            "UPDATE bvn_registry SET date_of_birth = '1990-05-21',"
            " enrollment_source = 'bank_branch', enrollment_agent_id = 'agent-B'"
            " WHERE bvn = '22345678901'")
        client = make_client(store)
        resp = client.post("/cross-reference-check",
                           json={"user_id": "u-x", "nin": "12345678901", "bvn": "22345678901"})
        body = resp.json()
        assert "dob_mismatch_between_nin_and_bvn" in body["inconsistencies"]
        tracing = body["registry_enrollment_tracing"]
        assert tracing["nin"]["enrollment_source"] == "nimc_fep"
        assert tracing["bvn"]["enrollment_source"] == "bank_branch"
        assert tracing["differing_enrollment_sources"] == ["nimc_fep", "bank_branch"]
        assert tracing["differing_enrollment_agents"] == ["fep-77", "agent-B"]

    def test_agent_rollup_counts_flagged_clusters(self, store):
        store.execute(
            "UPDATE customer_identifiers SET enrollment_agent_id = 'agent-B',"
            " enrollment_source = 'sim_registration_agent'"
            " WHERE customer_id = 'cust-syn-2' AND id_type = 'phone'")
        rollup = enrollment_agent_rollup(store)
        by_agent = {str(a["enrollment_agent_id"]): a for a in rollup}
        # seeded shared phone +2348012345678 (cust-syn-1/cust-syn-2) is the flagged cluster
        assert by_agent["agent-B"]["flagged_clusters"] == 1
        assert set(by_agent["agent-B"]["linked_customers"]) == {"cust-syn-2"}
        assert by_agent["None"]["flagged_clusters"] == 1  # cust-syn-1 holder, no agent recorded
        assert "sim_registration_agent" in by_agent["agent-B"]["enrollment_sources"]

    def test_agent_rollup_endpoint_requires_admin(self, store):
        client = make_client(store)  # analyst only
        assert client.get("/admin/enrollment/agent-rollup").status_code == 403
        admin_client = make_client(store, ADMIN_CLAIMS)
        resp = admin_client.get("/admin/enrollment/agent-rollup")
        assert resp.status_code == 200, resp.text
        assert resp.json()["agent_count"] >= 1  # seeded shared phone is a flagged cluster


class TestExposureImport:
    """Task 2: exposure import -> match -> alert; dedupe on re-import."""

    def test_import_matches_customers_and_writes_alerts(self, store):
        client = make_client(store, ADMIN_CLAIMS)
        resp = client.post("/admin/exposure/import", json=BREACH_BATCH)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["row_count"] == 3
        assert body["matched_count"] == 2  # bvn + phone match; unknown email does not
        # phone +2348012345678 is held by cust-syn-1 and cust-syn-2; bvn registry hit only
        assert body["alerts_written"] == 2
        alerts = store.query(
            "SELECT * FROM identity_theft_alerts WHERE alert_type = 'exposure_detected'")
        assert {a["user_id"] for a in alerts} == {"cust-syn-1", "cust-syn-2"}
        assert all(a["risk_level"] == "medium" for a in alerts)  # phone sensitivity
        details = json.loads(alerts[0]["details"])
        assert details["breach_ref"] == "EFCC-2026-0917"
        assert details["identifier_type"] == "phone"
        # hash-only evidence: no plaintext identifier persisted anywhere new
        assert "+2348012345678" not in alerts[0]["details"]
        assert details["identifier_hash"] == hashlib.sha256(b"+2348012345678").hexdigest()

    def test_bvn_indicator_is_high_severity_and_matched_via_registry(self, store):
        store.execute(
            "INSERT INTO customer_identifiers (customer_id, id_type, id_value)"
            " VALUES ('cust-real-1', 'bvn', '22345678901')")
        client = make_client(store, ADMIN_CLAIMS)
        resp = client.post("/admin/exposure/import", json=BREACH_BATCH)
        assert resp.status_code == 200, resp.text
        alert = store.query_one(
            "SELECT * FROM identity_theft_alerts WHERE alert_type = 'exposure_detected'"
            " AND user_id = 'cust-real-1'")
        assert alert["risk_level"] == "high"  # bvn is high-sensitivity
        details = json.loads(alert["details"])
        assert details["identifier_type"] == "bvn"
        assert details["registry_status"] == "found"
        assert "22345678901" not in alert["details"]

    def test_reimport_is_idempotent_no_duplicate_alerts(self, store):
        client = make_client(store, ADMIN_CLAIMS)
        first = client.post("/admin/exposure/import", json=BREACH_BATCH).json()
        second = client.post("/admin/exposure/import", json=BREACH_BATCH).json()
        assert first["alerts_written"] == 2 and first["alerts_deduped"] == 0
        assert second["alerts_written"] == 0 and second["alerts_deduped"] == 2
        alerts = store.query(
            "SELECT * FROM identity_theft_alerts WHERE alert_type = 'exposure_detected'")
        assert len(alerts) == 2  # unchanged
        indicators = store.query("SELECT * FROM exposure_indicators")
        assert len(indicators) == 3  # indicator-level dedupe too
        batches = store.query("SELECT * FROM exposure_import_batches")
        assert len(batches) == 1 and batches[0]["batch_id"] == "efcc-crackdown-2026-09"
        assert batches[0]["matched_count"] == 2

    def test_indicator_table_stores_hashes_only(self, store):
        client = make_client(store, ADMIN_CLAIMS)
        client.post("/admin/exposure/import", json=BREACH_BATCH)
        ind = store.query_one(
            "SELECT * FROM exposure_indicators WHERE identifier_type = 'bvn'")
        assert ind["identifier_hash"] == hashlib.sha256(b"22345678901").hexdigest()
        assert all(
            "22345678901" not in str(v) and "+2348012345678" not in str(v)
            for row in store.query("SELECT * FROM exposure_indicators")
            for k, v in row.items() if k != "id"
        )

    def test_import_requires_admin_role(self, store):
        client = make_client(store)  # analyst only
        resp = client.post("/admin/exposure/import", json=BREACH_BATCH)
        assert resp.status_code == 403

    def test_invalid_rows_rejected_honestly(self, store):
        client = make_client(store, ADMIN_CLAIMS)
        batch = {"batch_id": "b-bad", "rows": [
            {"identifier_type": "passport", "identifier_value": "X", "breach_ref": "R1"},
            {"identifier_type": "bvn", "identifier_value": "", "breach_ref": "R1"},
            {"identifier_type": "bvn", "identifier_value": "22345678901", "breach_ref": ""},
        ]}
        resp = client.post("/admin/exposure/import", json=batch)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["rejected_count"] == 3
        assert body["alerts_written"] == 0


class TestIdentityExposureEndpoint:
    """Task 2: customer-facing exposure view + redress guidance."""

    def test_exposure_view_with_redress_guidance(self, store):
        admin_client = make_client(store, ADMIN_CLAIMS)
        admin_client.post("/admin/exposure/import", json=BREACH_BATCH)
        client = make_client(store)
        resp = client.get("/identity-exposure/cust-syn-1")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "exposed"
        assert body["exposure_count"] == 1
        exp = body["exposures"][0]
        assert exp["alert_type"] == "exposure_detected"
        assert exp["identifier_type"] == "phone"
        assert exp["breach_ref"] == "EFCC-2026-0917"
        assert exp["identifier_hash"] == hashlib.sha256(b"+2348012345678").hexdigest()

        guidance = body["redress_guidance"]
        steps = {s["id"]: s for s in guidance["steps"]}
        # transcript-mandated redress content
        assert set(steps) == {"formal_complaint", "fccpc_complaint", "ndpc_report", "immediate_steps"}
        assert "organisation" in steps["formal_complaint"]["body"]
        assert "FCCPC" in steps["fccpc_complaint"]["body"]
        assert "NDPC" in steps["ndpc_report"]["body"]
        assert "NDPR" in steps["ndpc_report"]["body"]
        immediate = steps["immediate_steps"]["body"].lower()
        assert "bank" in immediate and "credential" in immediate and "otp" in immediate

    def test_unexposed_customer_gets_clean_status_with_guidance(self, store):
        client = make_client(store)
        resp = client.get("/identity-exposure/cust-nobody")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "no_known_exposure"
        assert body["exposures"] == []
        assert body["redress_guidance"]["steps"], "guidance is always returned"


class TestFailClosedIntact:
    """Registry-unavailable fail-closed posture must be unaffected."""

    def test_http_registry_unavailable_still_fails_closed(self, store):
        import httpx
        from registry import HTTPRegistryAdapter

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route", request=request)

        svc.get_bvn_adapter = lambda s=None: HTTPRegistryAdapter(  # noqa: E731
            "bvn", "https://nibss.example.test", transport=httpx.MockTransport(handler))
        try:
            client = make_client(store)
            resp = client.post("/verify-identity", json={
                "user_id": "u-9", "bvn": "22345678901", "first_name": "A", "last_name": "B",
                "date_of_birth": "1990-01-01", "phone_number": "+2348012345678",
            })
            body = resp.json()
            assert body["verification_results"]["bvn_registry"] == "unavailable"
            assert body["is_verified"] is False
            assert body["verification_status"] == "registry_unavailable"
        finally:
            import registry as registry_mod
            svc.get_bvn_adapter = registry_mod.get_bvn_adapter

    def test_exposure_import_with_unavailable_registry_still_matches_graph(self, store):
        import httpx
        from registry import HTTPRegistryAdapter

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route", request=request)

        svc.get_bvn_adapter = lambda s=None: HTTPRegistryAdapter(  # noqa: E731
            "bvn", "https://nibss.example.test", transport=httpx.MockTransport(handler))
        try:
            client = make_client(store, ADMIN_CLAIMS)
            resp = client.post("/admin/exposure/import", json=BREACH_BATCH)
            assert resp.status_code == 200, resp.text
            body = resp.json()
            # phone graph matches still produce alerts even with BVN registry down
            assert body["alerts_written"] == 2
            bvn_match = [m for m in body["matches"] if m["identifier_type"] == "bvn"]
            assert not bvn_match, "unavailable registry must not fabricate a match"
        finally:
            import registry as registry_mod
            svc.get_bvn_adapter = registry_mod.get_bvn_adapter
