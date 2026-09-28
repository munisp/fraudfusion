"""Request-legitimacy endpoint tests (TestClient).

Covers the NIN/BVN identity-theft heuristic ("a data request is suspicious
when the entity has no legitimate need for that field"): the transcript's
canonical examples — road-safety asking for BVN (never legitimate) vs asking
for a plate number (legitimate) — plus channel/link risk multipliers, the
OTP-over-link smishing signature, unknown-entity defaults, the matrix audit
endpoint, and validation.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


ASSESS = "/v1/intel/request-legitimacy/assess"


def _verdict(body, field):
    return next(v for v in body["field_verdicts"] if v["field"] == field)


# --- canonical transcript examples ------------------------------------------

def test_road_safety_never_needs_bvn(client):
    """'If FRSC asks for your plate number that makes sense; your BVN, not
    so much.' — road_safety + BVN over SMS with a link is critical."""
    r = client.post(ASSESS, json={
        "requesting_entity_type": "road_safety",
        "fields_requested": ["bvn", "dob"],
        "channel": "sms",
        "link_present": True,
    })
    assert r.status_code == 200
    body = r.json()
    assert _verdict(body, "bvn")["verdict"] == "inappropriate"
    assert _verdict(body, "dob")["verdict"] == "plausible"
    assert body["risk_band"] == "critical"
    assert body["score"] >= 0.8
    assert "no legitimate need" in body["explanation"]
    assert "official website" in body["safe_action"]


def test_road_safety_plate_number_is_legitimate(client):
    """The other half of the heuristic: plate_number IS road_safety's
    business — low risk even over SMS."""
    r = client.post(ASSESS, json={
        "requesting_entity_type": "road_safety",
        "fields_requested": ["plate_number"],
        "channel": "sms",
        "link_present": False,
    })
    assert r.status_code == 200
    body = r.json()
    assert _verdict(body, "plate_number")["verdict"] == "expected"
    assert body["risk_band"] == "low"
    assert body["score"] < 0.4


def test_bank_may_request_bvn_via_ussd(client):
    """Banks legitimately capture BVN via verified flows (USSD/branch/app)."""
    r = client.post(ASSESS, json={
        "requesting_entity_type": "bank",
        "fields_requested": ["bvn", "phone", "dob"],
        "channel": "ussd",
        "link_present": False,
    })
    body = r.json()
    assert _verdict(body, "bvn")["verdict"] == "expected"
    assert body["risk_band"] == "low"


def test_bank_bvn_request_via_sms_link_is_downgraded(client):
    """Even a legitimate NEED never makes the LINK safe: expected -> plausible
    downgrade for credential fields when a link is present."""
    r = client.post(ASSESS, json={
        "requesting_entity_type": "bank",
        "fields_requested": ["bvn"],
        "channel": "sms",
        "link_present": True,
    })
    body = r.json()
    assert _verdict(body, "bvn")["verdict"] == "plausible"
    assert "downgraded" in _verdict(body, "bvn")["reason"]
    assert body["risk_band"] in ("medium", "high", "critical")
    assert "Do NOT use any link" in body["safe_action"]


def test_no_legitimate_entity_requests_otp_via_link(client):
    """OTP over a link is the canonical smishing signature — for ANY entity
    type, including banks."""
    for entity in ("bank", "fintech", "telco", "road_safety", "employer",
                   "unknown"):
        r = client.post(ASSESS, json={
            "requesting_entity_type": entity,
            "fields_requested": ["otp"],
            "channel": "sms",
            "link_present": True,
        })
        body = r.json()
        assert _verdict(body, "otp")["verdict"] == "inappropriate", entity
        assert body["risk_band"] == "critical", entity
        assert "OTP" in body["safe_action"]


def test_palliative_style_unknown_entity_harvest(client):
    """Palliative-queue lure: unknown claimant demanding NIN + voter's card
    via SMS link (identity-theft harvest)."""
    r = client.post(ASSESS, json={
        "requesting_entity_type": "unknown",
        "fields_requested": ["nin", "voters_card"],
        "channel": "sms",
        "link_present": True,
    })
    body = r.json()
    assert _verdict(body, "nin")["verdict"] == "inappropriate"
    assert _verdict(body, "voters_card")["verdict"] == "inappropriate"
    assert body["risk_band"] == "critical"
    assert any("inappropriate field" in b for b in body["rule_bonuses"])


def test_telco_nin_sim_registration(client):
    """NIN-SIM linkage is a statutory telco mandate: NIN over USSD is fine,
    but a telco asking for BVN is not."""
    ok = client.post(ASSESS, json={
        "requesting_entity_type": "telco",
        "fields_requested": ["nin", "phone"],
        "channel": "ussd",
        "link_present": False,
    }).json()
    assert _verdict(ok, "nin")["verdict"] == "expected"
    assert ok["risk_band"] == "low"
    bad = client.post(ASSESS, json={
        "requesting_entity_type": "telco",
        "fields_requested": ["bvn"],
        "channel": "web_form",
        "link_present": True,
    }).json()
    assert _verdict(bad, "bvn")["verdict"] == "inappropriate"
    assert bad["score"] >= 0.8


# --- scoring mechanics --------------------------------------------------------

def test_channel_multiplier_ordering(client):
    """For the same inappropriate request, risk increases in person < web
    form < email < SMS."""
    # mixed fields keep the base below the 1.0 clip so ordering is observable
    scores = {}
    for channel in ("in_person", "web_form", "email", "sms"):
        body = client.post(ASSESS, json={
            "requesting_entity_type": "road_safety",
            "fields_requested": ["bvn", "dob"],
            "channel": channel,
            "link_present": False,
        }).json()
        scores[channel] = body["score"]
    assert scores["in_person"] < scores["web_form"] < scores["email"] < scores["sms"]


def test_unknown_entity_type_falls_back_to_unknown(client):
    body = client.post(ASSESS, json={
        "requesting_entity_type": "Crypto Investment Platform LLC",
        "fields_requested": ["bvn"],
        "channel": "email",
        "link_present": True,
    }).json()
    assert body["requesting_entity_type"] == "unknown"
    assert _verdict(body, "bvn")["verdict"] == "inappropriate"


def test_unrecognized_field_is_flagged_not_crashing(client):
    body = client.post(ASSESS, json={
        "requesting_entity_type": "bank",
        "fields_requested": ["mother's maiden name"],
        "channel": "web_form",
        "link_present": False,
    }).json()
    v = _verdict(body, "mothers_maiden_name")
    assert v["verdict"] == "unrecognized"
    assert 0.0 < body["score"] < 1.0


def test_field_normalization(client):
    body = client.post(ASSESS, json={
        "requesting_entity_type": " Road_Safety ",
        "fields_requested": ["Plate Number"],
        "channel": "SMS",
        "link_present": False,
    }).json()
    assert body["requesting_entity_type"] == "road_safety"
    assert _verdict(body, "plate_number")["verdict"] == "expected"


def test_score_bounds_and_schema(client):
    body = client.post(ASSESS, json={
        "requesting_entity_type": "unknown",
        "fields_requested": ["bvn", "nin", "otp", "voters_card"],
        "channel": "sms",
        "link_present": True,
    }).json()
    assert 0.0 <= body["score"] <= 1.0
    assert body["risk_band"] == "critical"
    for key in ("score", "risk_band", "field_verdicts", "explanation",
                "safe_action", "matrix_version", "rule_bonuses", "note"):
        assert key in body


def test_validation_missing_required_fields(client):
    r = client.post(ASSESS, json={"fields_requested": ["bvn"]})
    assert r.status_code == 422


def test_matrix_audit_endpoint(client):
    r = client.get("/v1/intel/request-legitimacy/matrix")
    assert r.status_code == 200
    body = r.json()
    assert body["appropriateness_matrix"]["road_safety"]["bvn"] == "inappropriate"
    assert body["appropriateness_matrix"]["road_safety"]["plate_number"] == "expected"
    assert body["appropriateness_matrix"]["bank"]["bvn"] == "expected"
    assert body["appropriateness_matrix"]["telco"]["nin"] == "expected"
    # no real company names anywhere in the matrix (entity-TYPE based)
    assert set(body["appropriateness_matrix"]) <= set(body["entity_types"])
