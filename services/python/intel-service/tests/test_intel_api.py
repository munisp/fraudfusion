"""API tests for intel-service: fail-closed health, all endpoints via
TestClient, suppression logic, brief content."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ARTIFACT_DIR  # noqa: E402  (path setup)

from app.main import SUPPRESS_MIN_N, create_app  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (ARTIFACT_DIR / "summaries.json").exists(),
    reason="shipped artifact not built")


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(artifact_dir=ARTIFACT_DIR))


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "synthetic" in body["provenance"]


def test_fail_closed_when_artifact_missing(tmp_path):
    c = TestClient(create_app(artifact_dir=tmp_path / "nope"))
    h = c.get("/health")
    assert h.status_code == 503                      # loud, not silent
    for path in ("/v1/intel/national/summary", "/v1/intel/states",
                 "/v1/intel/states/lagos", "/v1/intel/hotspots",
                 "/v1/intel/typology-mix", "/v1/intel/brief"):
        assert c.get(path).status_code == 503, path


def test_national_summary(client):
    r = client.get("/v1/intel/national/summary")
    assert r.status_code == 200
    nat = r.json()["national_fraud_rate"]
    assert nat["ci95"][0] < nat["posterior_mean"] < nat["ci95"][1]
    assert 0 < nat["posterior_mean"] < 0.05
    assert r.json()["week_trend"]["direction"] in ("rising", "falling", "flat")
    assert len(r.json()["top_typologies"]) == 4
    assert len(r.json()["forecast_4wk"]["rate_mean"]) == 4


def test_states_ranked_with_intervals(client):
    r = client.get("/v1/intel/states")
    assert r.status_code == 200
    states = r.json()["states"]
    assert len(states) == 37
    means = [s["posterior_mean"] for s in states if not s.get("suppressed")]
    assert means == sorted(means, reverse=True)
    for s in states:
        if s.get("suppressed"):
            continue
        assert s["ci95"][0] <= s["posterior_mean"] <= s["ci95"][1]
        assert 0.0 <= s["p_above_national"] <= 1.0
        assert s["zone"]


def test_state_detail_lga_table_and_suppression(client):
    r = client.get("/v1/intel/states/kano")
    assert r.status_code == 200
    lgas = r.json()["lgas"]
    assert len(lgas) == 44
    suppressed = [g for g in lgas if g.get("suppressed")]
    assert suppressed, "expected at least one suppressed sparse Kano LGA"
    assert "Shanono" in [g["lga"] for g in suppressed]
    for g in lgas:
        if not g.get("suppressed"):
            assert g["weekly_txn_mean"] >= SUPPRESS_MIN_N
            assert g["ci95"][0] <= g["posterior_mean"] <= g["ci95"][1]
    # non-pilot state: no LGA table
    r2 = client.get("/v1/intel/states/borno")
    assert r2.status_code == 200
    assert r2.json()["lgas"] is None


def test_state_detail_unknown_404(client):
    assert client.get("/v1/intel/states/atlantis").status_code == 404


def test_hotspots(client):
    r = client.get("/v1/intel/hotspots?k=5")
    assert r.status_code == 200
    body = r.json()
    assert len(body["hotspots"]) == 5
    for h in body["hotspots"]:
        assert 0.0 <= h["p_exceeds_threshold"] <= 1.0
        assert h["ci95"][0] <= h["posterior_mean"] <= h["ci95"][1]
    # threshold override: a very low threshold -> every P ~ 1
    r2 = client.get("/v1/intel/hotspots?k=3&threshold=0.0001")
    assert all(h["p_exceeds_threshold"] > 0.99 for h in r2.json()["hotspots"])
    # k clamp: k > 37 rejected by validation
    assert client.get("/v1/intel/hotspots?k=99").status_code == 422
    assert len(client.get("/v1/intel/hotspots?k=37").json()["hotspots"]) == 37


def test_typology_mix_endpoint(client):
    r = client.get("/v1/intel/typology-mix")
    assert r.status_code == 200
    zones = r.json()["zones"]
    assert len(zones) == 6
    for z, blk in zones.items():
        shares = [m["posterior_mean"] for m in blk["mix"]]
        assert abs(sum(shares) - 1.0) < 0.02
        assert len(blk["mix"]) == 8
        for m in blk["mix"]:
            assert m["ci95"][0] <= m["posterior_mean"] <= m["ci95"][1]


def test_brief_content(client):
    r = client.get("/v1/intel/brief")
    assert r.status_code == 200
    text = r.text
    assert "National Fraud Intelligence Brief" in text
    assert "synthetic" in text                      # honest provenance
    assert "Caveats" in text and "ecological fallacy" in text
    assert "Methodology" in text and "MCMC" in text
    assert "Hotspots" in text and "Forecast" in text
    assert "k-anonymity" in text
