"""Intel endpoint fixtures and shape conformance (intel-service shapes)."""

from __future__ import annotations

from tests.conftest import AUTH

# GET /v1/intel/national/summary keys (intel-service app/main.py).
NATIONAL_KEYS = {
    "data_period_weeks", "provenance", "national_fraud_rate", "week_trend",
    "top_typologies", "totals", "forecast_4wk", "model_version",
}

# POST /v1/intel/request-legitimacy/assess keys (request_legitimacy.assess).
LEGITIMACY_KEYS = {
    "score", "risk_band", "requesting_entity_type", "channel", "link_present",
    "field_verdicts", "rule_bonuses", "explanation", "safe_action",
    "matrix_version", "note",
}

# POST /v1/intel/cultural/score keys (cultural.py /score).
CULTURAL_KEYS = {
    "cultural_fraud_score", "risk_band", "indicator_breakdown",
    "authenticity_discount", "authenticity_notes", "weights_source",
    "provenance",
}


class TestNationalSummary:
    def test_shape_and_markers(self, client):
        r = client.get("/v1/intel/national/summary", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert NATIONAL_KEYS <= set(body)
        assert body["environment"] == "sandbox" and body["synthetic"] is True
        assert {"posterior_mean", "ci95"} <= set(body["national_fraud_rate"])
        assert {"direction", "delta_last4_vs_prior4"} <= set(body["week_trend"])
        assert {"txn_year", "fraud_year"} <= set(body["totals"])
        assert len(body["forecast_4wk"]) == 4

    def test_deterministic(self, client):
        a = client.get("/v1/intel/national/summary", headers=AUTH).json()
        b = client.get("/v1/intel/national/summary", headers=AUTH).json()
        assert a == b


class TestRequestLegitimacy:
    def test_shape_and_markers(self, client):
        r = client.post("/v1/intel/request-legitimacy/assess", headers=AUTH,
                        json={"requesting_entity_type": "bank",
                              "fields_requested": ["bvn", "phone"],
                              "channel": "web_form"})
        assert r.status_code == 200
        body = r.json()
        assert LEGITIMACY_KEYS <= set(body)
        assert body["environment"] == "sandbox" and body["synthetic"] is True
        assert body["requesting_entity_type"] == "bank"
        assert [v["verdict"] for v in body["field_verdicts"]] == [
            "expected", "expected"]
        assert body["risk_band"] == "low"

    def test_road_safety_asking_bvn_is_hostile(self, client):
        body = client.post(
            "/v1/intel/request-legitimacy/assess", headers=AUTH,
            json={"requesting_entity_type": "road_safety",
                  "fields_requested": ["bvn", "otp"],
                  "channel": "sms", "link_present": True}).json()
        assert body["risk_band"] == "critical"
        assert all(v["verdict"] == "inappropriate"
                   for v in body["field_verdicts"])
        assert body["rule_bonuses"]  # smishing signature bonus fired

    def test_unknown_entity_and_field_normalisation(self, client):
        body = client.post(
            "/v1/intel/request-legitimacy/assess", headers=AUTH,
            json={"requesting_entity_type": "ACME Corp",
                  "fields_requested": ["Plate Number", "favourite-colour"],
                  "channel": "SMS"}).json()
        assert body["requesting_entity_type"] == "unknown"
        verdicts = {v["field"]: v["verdict"] for v in body["field_verdicts"]}
        assert verdicts["plate_number"] == "inappropriate"
        assert verdicts["favourite_colour"] == "unrecognized"

    def test_link_downgrades_credential_expected(self, client):
        body = client.post(
            "/v1/intel/request-legitimacy/assess", headers=AUTH,
            json={"requesting_entity_type": "bank", "fields_requested": ["bvn"],
                  "channel": "email", "link_present": True}).json()
        assert body["field_verdicts"][0]["verdict"] == "plausible"

    def test_deterministic(self, client):
        req = {"requesting_entity_type": "telco",
               "fields_requested": ["nin", "phone"], "channel": "ussd"}
        a = client.post("/v1/intel/request-legitimacy/assess", headers=AUTH,
                        json=req).json()
        b = client.post("/v1/intel/request-legitimacy/assess", headers=AUTH,
                        json=req).json()
        assert a == b


class TestCulturalScore:
    def test_shape_and_markers(self, client):
        r = client.post("/v1/intel/cultural/score", headers=AUTH,
                        json={"indicators": {"temporal_anomaly": 0.5,
                                             "urgency": 0.9}})
        assert r.status_code == 200
        body = r.json()
        assert CULTURAL_KEYS <= set(body)
        assert body["environment"] == "sandbox" and body["synthetic"] is True
        assert set(body["indicator_breakdown"]) == {
            "temporal_anomaly", "network_anomaly", "cultural_inconsistency",
            "amount_anomaly", "communication_anomaly", "urgency"}
        # raw = 0.20*0.5 + 0.10*0.9 = 0.19
        assert body["cultural_fraud_score"] == 0.19
        assert body["risk_band"] == "low"

    def test_unknown_indicator_422(self, client):
        r = client.post("/v1/intel/cultural/score", headers=AUTH,
                        json={"indicators": {"nonsense": 1.0}})
        assert r.status_code == 422
        assert "unknown indicators" in r.json()["detail"]

    def test_event_window_discount_and_mismatch(self, client):
        in_window = client.post(
            "/v1/intel/cultural/score", headers=AUTH,
            json={"indicators": {"temporal_anomaly": 0.5},
                  "claimed_event": "detty_december",
                  "date": "2026-12-20"}).json()
        assert in_window["authenticity_discount"] == 0.05
        out_window = client.post(
            "/v1/intel/cultural/score", headers=AUTH,
            json={"indicators": {"temporal_anomaly": 0.5},
                  "claimed_event": "detty_december",
                  "date": "2026-03-20"}).json()
        assert out_window["authenticity_discount"] == 0.0
        assert any("OUT OF ITS CULTURAL WINDOW" in n
                   for n in out_window["authenticity_notes"])

    def test_high_score_band(self, client):
        body = client.post("/v1/intel/cultural/score", headers=AUTH,
                           json={"indicators": {
                               "temporal_anomaly": 1.0, "network_anomaly": 1.0,
                               "cultural_inconsistency": 1.0,
                               "amount_anomaly": 1.0,
                               "communication_anomaly": 1.0,
                               "urgency": 1.0}}).json()
        assert body["cultural_fraud_score"] == 1.0
        assert body["risk_band"] == "critical"
