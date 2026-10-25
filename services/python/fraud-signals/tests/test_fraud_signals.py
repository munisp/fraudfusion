"""Fraud-signals tests: per-detector calibration, API round-trip, audit chain."""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors  # noqa: E402
import geo_enrich  # noqa: E402
from main import app  # noqa: E402
from store import now_iso  # noqa: E402

NOW = datetime.now(timezone.utc)


def ev(days_ago: float, **payload):
    return {
        "payload": payload,
        "created_at": (NOW - timedelta(days=days_ago)).isoformat(),
    }


# ---------------------------------------------------------------------------
# Detector units
# ---------------------------------------------------------------------------

class TestAppScam:
    def test_legit_transfer_clears(self):
        score, verdict, factors = detectors.app_scam(
            {"amount_ngn": 5000, "customer_avg_amount": 8000,
             "session_seconds": 300, "payee_is_new": False}, [ev(1)])
        assert verdict == "clear" and score < detectors.REVIEW_MIN

    def test_coerced_new_payee_blocks(self):
        score, verdict, factors = detectors.app_scam(
            {"payee_is_new": True, "payee_age_hours": 0.2,
             "amount_ngn": 500_000, "customer_avg_amount": 10_000,
             "session_seconds": 20, "device_is_new": True,
             "payee_mule_score": 0.8}, [])
        assert verdict == "block"
        codes = {f["code"] for f in factors}
        assert {"new_payee", "payee_just_added", "amount_outlier",
                "rushed_session", "payee_mule_like"} <= codes

    def test_no_history_is_honest(self):
        _, _, factors = detectors.app_scam({"amount_ngn": 100}, [])
        assert any(f["code"] == "history_unavailable" for f in factors)


class TestMule:
    def test_pass_through_and_fan_in(self):
        history = [ev(1, direction="in", amount_ngn=100_000, counterparty=f"s{i}")
                   for i in range(6)]
        history += [ev(0.5, direction="out", amount_ngn=95_000, counterparty=f"x{i}")
                    for i in range(6)]
        score, verdict, factors = detectors.mule({}, history)
        codes = {f["code"] for f in factors}
        assert "pass_through" in codes and "fan_in" in codes
        assert verdict in ("review", "block")

    def test_normal_account_clears(self):
        history = [ev(1, direction="in", amount_ngn=100_000, counterparty="salary"),
                   ev(1, direction="out", amount_ngn=5_000, counterparty="shop")]
        _, verdict, _ = detectors.mule({}, history)
        assert verdict == "clear"

    def test_dormancy_burst(self):
        _, _, factors = detectors.mule(
            {"dormant_days_before": 120},
            [ev(0.1, direction="in", amount_ngn=10_000, counterparty="a")])
        assert any(f["code"] == "dormancy_burst" for f in factors)


class TestAgent:
    def test_structuring_ring_blocks(self):
        history = [ev(0.05, type="cash_out", amount_ngn=48_000) for _ in range(4)]
        score, verdict, factors = detectors.agent(
            {"baseline_tx_per_day": 1, "float_mismatch_ngn": 250_000}, history)
        assert verdict == "block"
        codes = {f["code"] for f in factors}
        assert "structuring" in codes and "float_diversion" in codes

    def test_normal_agent_clears(self):
        history = [ev(0.05, type="cash_out", amount_ngn=20_000),
                   ev(0.02, type="cash_in", amount_ngn=15_000)]
        _, verdict, _ = detectors.agent(
            {"baseline_tx_per_day": 10, "distance_from_registered_km": 1}, history)
        assert verdict == "clear"


class TestAgentGeoEnrich:
    """Service-side computation of distance_from_registered_km (R26)."""

    def test_embedded_enrichment_fires_off_location(self, fresh_store):
        client = TestClient(app)
        r = client.post("/api/v1/signals/agent", json={
            "subject_id": "agent-1",
            "payload": {"baseline_tx_per_day": 10,
                        "registered_location": "lagos",
                        "operating_location": "abuja"},
        })
        assert r.status_code == 200
        body = r.json()
        codes = {f["code"] for f in body["factors"]}
        assert "off_location" in codes  # lagos-abuja ~536km > 5km
        assert "geo_enrichment" in codes
        detail = next(f["detail"] for f in body["factors"] if f["code"] == "off_location")
        assert "km from registered location" in detail

    def test_caller_supplied_distance_wins(self, fresh_store):
        payload = {"distance_from_registered_km": 1.0,
                   "registered_location": "lagos", "operating_location": "abuja"}
        enriched, note = geo_enrich.enrich_agent_distance(payload, fresh_store)
        assert enriched["distance_from_registered_km"] == 1.0  # not overwritten
        assert note is None

    def test_unknown_place_honest_skip(self, fresh_store):
        client = TestClient(app)
        r = client.post("/api/v1/signals/agent", json={
            "subject_id": "agent-2",
            "payload": {"baseline_tx_per_day": 10,
                        "registered_location": "lagos",
                        "operating_location": "atlantis"},
        })
        assert r.status_code == 200
        body = r.json()
        codes = {f["code"] for f in body["factors"]}
        assert "off_location" not in codes  # honest skip, never a silent 0
        note = next(f["detail"] for f in body["factors"] if f["code"] == "geo_enrichment")
        assert "geo_unresolved" in note

    def test_hyphenated_name_normalised(self, fresh_store):
        enriched, _ = geo_enrich.enrich_agent_distance(
            {"registered_location": "lagos", "operating_location": "Ado-Ekiti"},
            fresh_store)
        assert enriched["distance_from_registered_km"] > 5  # ~240km

    def test_no_locations_no_enrichment(self, fresh_store):
        payload = {"baseline_tx_per_day": 5}
        enriched, note = geo_enrich.enrich_agent_distance(payload, fresh_store)
        assert enriched is payload and note is None

    def test_postgres_path_uses_db_function(self):
        class FakePg:
            _is_pg = True

            def query(self, sql, params):
                assert "geo_distance_km" in sql
                return [{"d": 321.5}]

        enriched, note = geo_enrich.enrich_agent_distance(
            {"registered_location": "lagos", "operating_location": "kano"}, FakePg())
        assert enriched["distance_from_registered_km"] == 321.5
        assert note is None  # DB is authoritative; no fallback note

    def test_postgres_failure_falls_back_embedded(self):
        class BrokenPg:
            _is_pg = True

            def query(self, sql, params):
                raise RuntimeError("function geo_distance_km does not exist")

        enriched, note = geo_enrich.enrich_agent_distance(
            {"registered_location": "lagos", "operating_location": "abuja"}, BrokenPg())
        assert enriched["distance_from_registered_km"] > 5  # embedded haversine
        assert "embedded gazetteer fallback" in note

    def test_embedded_gazetteer_matches_migration_seed(self):
        import re
        seed_sql = open(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "..", "..", "..", "database", "20261026_postgis_geo.sql"),
            encoding="utf-8").read()
        seed = {n.lower(): (float(lat), float(lon)) for n, lat, lon in re.findall(
            r"\('([^']+)',\s*([\d.-]+),\s*([\d.-]+),\s*'[^']+',\s*'[A-Z]{2}'\)", seed_sql)}
        assert len(seed) == 72
        assert geo_enrich.GAZETTEER == seed


class TestLoanStacking:
    def test_multi_lender_stack(self):
        history = [ev(2, lender_id=f"lender{i}") for i in range(3)]
        score, verdict, factors = detectors.loan_stacking(
            {"thin_file": True}, history)
        assert verdict in ("review", "block")
        assert any(f["code"] == "multi_lender_stack" for f in factors)

    def test_forged_docs_from_doc_engine(self):
        score, verdict, factors = detectors.loan_stacking(
            {"document_authenticity_score": 72, "first_payment_default": True}, [])
        assert verdict in ("review", "block")
        assert any(f["code"] == "forged_income_docs" for f in factors)

    def test_single_lender_clears(self):
        _, verdict, _ = detectors.loan_stacking(
            {"thin_file": False}, [ev(2, lender_id="l1"), ev(3, lender_id="l1")])
        assert verdict == "clear"


class TestIssuance:
    def test_officer_outlier_after_hours(self):
        history = [ev(0.02, certificate=f"C{i}") for i in range(20)]
        score, verdict, factors = detectors.issuance(
            {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 2,
             "issued_hour_local": 2, "registry_survey_mismatch": True}, history)
        assert verdict == "block"
        codes = {f["code"] for f in factors}
        assert {"officer_velocity_outlier", "after_hours_issuance",
                "registry_survey_mismatch"} <= codes

    def test_normal_issuance_clears(self):
        history = [ev(0.02, certificate="C1") for _ in range(4)]
        _, verdict, _ = detectors.issuance(
            {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 2,
             "issued_hour_local": 11}, history)
        assert verdict == "clear"

    def test_sequence_gap_flag(self):
        _, _, factors = detectors.issuance({"sequence_gap": True}, [])
        assert any(f["code"] == "certificate_sequence_gap" for f in factors)


class TestChannel:
    def test_sim_swap_ussd_blocks(self):
        score, verdict, factors = detectors.channel(
            {"channel": "ussd", "sim_change_hours": 3,
             "alert_integrity_fail": True}, [])
        assert verdict == "block"

    def test_legit_ussd_clears(self):
        _, verdict, _ = detectors.channel(
            {"channel": "ussd", "sim_change_hours": 200,
             "phone_tenure_days": 400}, [])
        assert verdict == "clear"

    def test_new_imei_high_value(self):
        _, _, factors = detectors.channel(
            {"imei_is_new": True, "amount_ngn": 500_000}, [])
        assert any(f["code"] == "new_imei_high_value" for f in factors)


class TestGhostPayroll:
    def test_shared_account_and_duplicate_identity(self):
        history = [ev(1, employee_id="e2", bank_account_hash="A",
                      identity_hash="X"),
                   ev(1, employee_id="e3", bank_account_hash="A",
                      identity_hash="Y")]
        score, verdict, factors = detectors.ghost_payroll(
            {"employee_id": "e1", "bank_account_hash": "A",
             "identity_hash": "X"}, history)
        assert verdict in ("review", "block")
        codes = {f["code"] for f in factors}
        assert "shared_salary_account" in codes and "duplicate_identity" in codes

    def test_deceased_registry_blocks(self):
        _, verdict, _ = detectors.ghost_payroll(
            {"employee_id": "e1", "deceased_registry_hit": True}, [])
        assert verdict == "block"

    def test_normal_payroll_row_clears(self):
        history = [ev(1, employee_id="e2", bank_account_hash="B",
                      identity_hash="Z")]
        _, verdict, _ = detectors.ghost_payroll(
            {"employee_id": "e1", "bank_account_hash": "A",
             "identity_hash": "X"}, history)
        assert verdict == "clear"


class TestSubsidy:
    def test_phantom_farmer_blocks(self):
        score, verdict, factors = detectors.subsidy(
            {"farm_hectares": 2, "claim_ngn": 2_000_000,
             "farm_geocode_outside_lga": True, "no_field_activity_evidence": True},
            [ev(1, claim_id="c2", identity_hash="X")])
        payload = dict(farm_hectares=2, claim_ngn=2_000_000,
                       farm_geocode_outside_lga=True,
                       no_field_activity_evidence=True, claim_id="c1",
                       identity_hash="X")
        score, verdict, factors = detectors.subsidy(payload,
                                                    [ev(1, claim_id="c2",
                                                        identity_hash="X")])
        assert verdict == "block"
        codes = {f["code"] for f in factors}
        assert {"implausible_claim_ratio", "farm_outside_lga",
                "no_field_activity", "duplicate_claimant"} <= codes

    def test_genuine_claim_clears(self):
        _, verdict, _ = detectors.subsidy(
            {"farm_hectares": 5, "claim_ngn": 200_000, "claim_id": "c1",
             "identity_hash": "X"}, [])
        assert verdict == "clear"


# ---------------------------------------------------------------------------
# API + store round-trip
# ---------------------------------------------------------------------------

class TestApi:
    def test_evaluate_and_audit_chain(self, fresh_store):
        client = TestClient(app)
        r = client.post("/api/v1/signals/app_scam", json={
            "subject_id": "acct-1",
            "payload": {"payee_is_new": True, "payee_age_hours": 0.1,
                        "session_seconds": 10},
        })
        assert r.status_code == 200
        body = r.json()
        assert body["verdict"] in ("review", "block")
        assert body["audit"] == "ok" and body["audit_hash"]

        # second eval chains onto the first
        r2 = client.post("/api/v1/signals/app-scam", json={  # hyphen alias
            "subject_id": "acct-1", "payload": {"payee_is_new": False}})
        assert r2.status_code == 200

        chain = client.get("/api/v1/signals/chain/app_scam").json()
        assert chain["valid"] is True and chain["entries"] == 2

    def test_history_feeds_detector(self, fresh_store):
        client = TestClient(app)
        for i in range(6):
            client.post("/api/v1/signals/events", json={
                "kind": "mule", "subject_id": "acct-9",
                "payload": {"direction": "in", "amount_ngn": 50_000,
                            "counterparty": f"s{i}"}})
        r = client.post("/api/v1/signals/mule", json={
            "subject_id": "acct-9", "payload": {}, "record_event": False})
        codes = {f["code"] for f in r.json()["factors"]}
        assert "fan_in" in codes

    def test_unknown_detector_404(self, fresh_store):
        client = TestClient(app)
        assert client.post("/api/v1/signals/nope", json={
            "subject_id": "x", "payload": {}}).status_code == 404

    def test_chain_detects_tamper(self, fresh_store):
        client = TestClient(app)
        client.post("/api/v1/signals/app_scam", json={
            "subject_id": "a", "payload": {"payee_is_new": True,
                                           "payee_age_hours": 0.5,
                                           "device_is_new": True},
            "record_event": False})
        fresh_store.execute(
            "UPDATE signal_evals SET verdict = 'clear'")
        chain = client.get("/api/v1/signals/chain/app_scam").json()
        assert chain["valid"] is False

    def test_health(self, fresh_store):
        client = TestClient(app)
        body = client.get("/health").json()
        assert body["store"] == "ok" and len(body["detectors"]) == 9

    def test_mule_self_enriches_sender_risk(self, fresh_store):
        """Service-side enrichment: senders with stored high-score evals get
        counterparty_risk annotated automatically — no caller annotation."""
        client = TestClient(app)
        # three senders each have a stored high mule score
        for s in ("s0", "s1", "s2"):
            client.post("/api/v1/signals/mule", json={
                "subject_id": s, "record_event": False,
                "payload": {"dormant_days_before": 120,
                            "shared_device_accounts": 5},
                "events": [{"payload": {"direction": "in", "amount_ngn": 50_000,
                                        "counterparty": "x"},
                            "created_at": NOW.isoformat()}]})
        # receiver fans in from those three senders, one clean, forwards 80%
        events = [
            {"payload": {"direction": "in", "amount_ngn": 100_000,
                         "counterparty": f"s{i}"},
             "created_at": NOW.isoformat()} for i in range(3)]
        events.append({"payload": {"direction": "in", "amount_ngn": 100_000,
                                   "counterparty": "clean"},
                       "created_at": NOW.isoformat()})
        events.append({"payload": {"direction": "out", "amount_ngn": 80_000,
                                   "counterparty": "x"},
                       "created_at": NOW.isoformat()})
        r = client.post("/api/v1/signals/mule", json={
            "subject_id": "receiver-1", "payload": {}, "events": events,
            "record_event": False})
        codes = {f["code"] for f in r.json()["factors"]}
        assert "high_risk_fan_in" in codes
