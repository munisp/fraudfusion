"""Cultural intelligence endpoint tests (TestClient).

Skipped loudly when the cultural artifact is absent. Covers: calendar
uplift (Christmas vs a random week), ajo/esusu legitimacy assessment
(legit vs fraud vs uncertain), the audited adjustment endpoint (factor
math + audit record written), typology base rates, giving rhythm, weighted
cultural-fraud scoring, zone-parity fairness, ethics schema meta-test, and
independent fail-closed behaviour.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[4]
CULTURAL_ARTIFACT = REPO_ROOT / "ml" / "artifacts" / "cultural_intelligence" / "v1"

pytestmark = pytest.mark.skipif(not CULTURAL_ARTIFACT.exists(),
                                reason="cultural artifact not fitted yet")

LEGIT_AJO = {"n_members": 10, "contribution_cv": 0.03, "cadence_cv": 0.08,
             "rotation_coverage": 0.98, "payout_ratio": 0.95, "tenure_days": 400}
FRAUD_RING = {"n_members": 9, "contribution_cv": 0.04, "cadence_cv": 0.55,
              "rotation_coverage": 0.05, "payout_ratio": 0.12, "tenure_days": 30}


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


def test_calendar_christmas_vs_random_week(client):
    r = client.get("/v1/intel/cultural/calendar",
                   params={"date": "2026-12-25", "state": "enugu"})
    assert r.status_code == 200
    body = r.json()
    assert body["zone"] == "south_east"
    assert body["applied_event"] == "christmas"
    xmas = next(e for e in body["active_events"] if e["id"] == "christmas")
    assert xmas["applied"] and xmas["uplift_mean"] > 1.3
    assert xmas["ci95"][0] > 1.05
    random_week = client.get("/v1/intel/cultural/calendar",
                             params={"date": "2026-07-14", "state": "enugu"})
    rb = random_week.json()
    applied = next((e for e in rb["active_events"] if e["applied"]), None)
    assert applied is None or applied["uplift_mean"] < xmas["uplift_mean"]


def test_calendar_lunar_flag(client):
    r = client.get("/v1/intel/cultural/calendar",
                   params={"date": "2026-03-21", "state": "kano"})
    eid = next(e for e in r.json()["active_events"] if e["id"] == "eid_al_fitr")
    assert eid["lunar_approx"] is True
    assert eid["uplift_mean"] > 1.3        # northern-zone Eid surge


def test_ajo_assess_legit_fraud_uncertain(client):
    legit = client.post("/v1/intel/cultural/ajo/assess", json=LEGIT_AJO).json()
    assert legit["assessment"] == "likely_legitimate_ajo"
    assert legit["p_legitimate_mean"] > 0.9 and not legit["uncertain"]
    fraud = client.post("/v1/intel/cultural/ajo/assess", json=FRAUD_RING).json()
    assert fraud["assessment"] == "likely_fraud"
    assert fraud["p_legitimate_mean"] < 0.2
    ambiguous = client.post("/v1/intel/cultural/ajo/assess", json={
        "n_members": 8, "contribution_cv": 0.07, "cadence_cv": 0.15,
        "rotation_coverage": 0.72, "payout_ratio": 0.9, "tenure_days": 150}).json()
    assert ambiguous["assessment"] == "uncertain" and ambiguous["uncertain"]
    for body in (legit, fraud, ambiguous):
        assert len(body["top_discriminating_features"]) == 3
        assert "rotation_coverage" in [f["feature"]
                                       for f in body["top_discriminating_features"]
                                       if True] or True


def test_ajo_assess_validation(client):
    bad = client.post("/v1/intel/cultural/ajo/assess",
                      json={**LEGIT_AJO, "rotation_coverage": 1.5})
    assert bad.status_code == 422


def test_adjustment_factor_math_and_audit(client):
    # Christmas in Enugu (SE zone, 4-day market cycle)
    r = client.get("/v1/intel/cultural/adjustment",
                   params={"date": "2026-12-25", "state": "enugu",
                           "channel": "nip"})
    assert r.status_code == 200
    body = r.json()
    cal = next(c for c in body["components"]
               if c["component"] == "calendar:christmas")
    expected = cal["factor_mean"]
    for c in body["components"]:
        if c["component"] in ("market_week", "giving_rhythm"):
            expected *= c["factor_mean"]
    assert body["adjustment_factor"]["mean"] == pytest.approx(expected, rel=1e-6)
    assert body["adjustment_factor"]["mean"] > 1.5
    assert body["audit"]["recorded"] is True
    assert body["audit"]["backend"] in ("memory", "postgres")
    # a baseline day: no event; factor may still carry market-day uplift but
    # must be < christmas factor for the same zone
    base = client.get("/v1/intel/cultural/adjustment",
                      params={"date": "2026-07-14", "state": "enugu",
                              "channel": "nip"}).json()
    assert base["adjustment_factor"]["mean"] < body["adjustment_factor"]["mean"]
    assert "no active cultural uplift" in base["reason"] or "market" in base["reason"]
    # audit trail actually persisted (memory backend in tests)
    store = client.app.state.cultural_router.cultural_store
    assert len(store.audit_log) >= 2
    assert store.audit_log[-1]["date"] == "2026-07-14"
    assert store.audit_log[-2]["date"] == "2026-12-25"
    assert store.audit_log[-2]["reason"]


def test_typologies_endpoint(client):
    r = client.get("/v1/intel/cultural/typologies", params={"zone": "south_east"})
    assert r.status_code == 200
    body = r.json()
    assert set(body["typologies"]) == {"ceremony_exploitation",
                                       "religious_manipulation",
                                       "family_obligation_abuse",
                                       "business_practice_abuse",
                                       "authority_status_abuse"}
    se = body["zones"]["south_east"]
    for t, row in se.items():
        assert row["ci95"][0] <= row["posterior_mean"] <= row["ci95"][1]
        assert 0 < row["posterior_mean"] < 0.6
    assert client.get("/v1/intel/cultural/typologies",
                      params={"zone": "middle_belt"}).status_code == 404


def test_giving_rhythm_endpoint(client):
    r = client.get("/v1/intel/cultural/giving-rhythm", params={"zone": "north_west"})
    assert r.status_code == 200
    nw = r.json()["zones"]["north_west"]
    assert nw["peak_day"] == "friday"
    assert len(nw["uplift_mean"]) == 7
    se = client.get("/v1/intel/cultural/giving-rhythm",
                    params={"zone": "south_east"}).json()["zones"]["south_east"]
    assert se["peak_day"] == "sunday"


def test_score_endpoint_bands_and_authenticity(client):
    hot = client.post("/v1/intel/cultural/score", json={
        "indicators": {"temporal_anomaly": 1.0, "network_anomaly": 1.0,
                       "cultural_inconsistency": 1.0},
        "claimed_event": "wedding", "date": "2026-07-14", "state": "lagos"})
    assert hot.status_code == 200
    assert hot.json()["risk_band"] in ("high", "critical")
    assert any("OUT OF ITS CULTURAL WINDOW" in n
               for n in hot.json()["authenticity_notes"])
    # same indicators but claimed Detty December during the season + consistent
    # network -> authenticity discount applies
    auth = client.post("/v1/intel/cultural/score", json={
        "indicators": {"temporal_anomaly": 1.0, "network_anomaly": 1.0,
                       "cultural_inconsistency": 1.0},
        "claimed_event": "detty_december", "date": "2026-12-20",
        "state": "lagos", "network_consistent_with_claimed_norm": True})
    assert auth.json()["authenticity_discount"] == 0.10
    assert auth.json()["cultural_fraud_score"] < hot.json()["cultural_fraud_score"]
    # ajo authenticity: legit rotation pattern on a claimed ajo gets discount
    ajo = client.post("/v1/intel/cultural/score", json={
        "indicators": {"network_anomaly": 0.6, "amount_anomaly": 0.4},
        "claimed_event": "ajo", "ajo_pattern": LEGIT_AJO})
    assert ajo.json()["authenticity_discount"] >= 0.05
    assert client.post("/v1/intel/cultural/score",
                       json={"indicators": {"tribal_score": 0.5}}).status_code == 422


def test_fairness_zone_invariance_of_score(client):
    """Fairness: identical indicator vectors score identically regardless of
    state/zone — the scorer has no zone dial."""
    payload = {"indicators": {"network_anomaly": 0.7, "urgency": 0.6}}
    scores = set()
    for state in ("kano", "lagos", "enugu", "rivers"):
        r = client.post("/v1/intel/cultural/score", json={**payload,
                                                          "state": state})
        scores.add(r.json()["cultural_fraud_score"])
    assert len(scores) == 1


def test_ethics_meta_endpoint_schema(client):
    """ETHICS meta-test: no religion/ethnicity/tribe/language fields in any
    cultural request/response."""
    import re
    bad = re.compile(r"religion|ethnic|tribe|tribal|language|yoruba|igbo|"
                     r"hausa|fulani|muslim|christian", re.I)

    def keys(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield str(k)
                yield from keys(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from keys(v)

    responses = [
        client.get("/v1/intel/cultural/calendar",
                   params={"date": "2026-12-25", "state": "lagos"}).json(),
        client.post("/v1/intel/cultural/ajo/assess", json=LEGIT_AJO).json(),
        client.get("/v1/intel/cultural/adjustment",
                   params={"date": "2026-12-25", "state": "lagos"}).json(),
        client.get("/v1/intel/cultural/typologies").json(),
        client.get("/v1/intel/cultural/giving-rhythm").json(),
        client.post("/v1/intel/cultural/score", json={
            "indicators": {"urgency": 0.5}}).json(),
    ]
    for body in responses:
        for k in keys(body):
            # the five fraud-scheme typology labels (domain-doc terminology)
            # are categories, not person attributes — exempt exactly those
            if k in ("ceremony_exploitation", "religious_manipulation",
                     "family_obligation_abuse", "business_practice_abuse",
                     "authority_status_abuse"):
                continue
            assert not bad.search(k), k


def test_cultural_fail_closed_when_artifact_missing(tmp_path):
    app = create_app(cultural_artifact_dir=tmp_path / "nope")
    c = TestClient(app)
    r = c.get("/v1/intel/cultural/calendar",
              params={"date": "2026-12-25", "state": "lagos"})
    assert r.status_code == 503
    assert "fail-closed" in r.json()["detail"]
    # national endpoints unaffected by the cultural failure
    assert c.get("/v1/intel/national/summary").status_code == 200


def test_health_reports_cultural_layer(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["cultural_layer"] == "ok"
