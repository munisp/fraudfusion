"""Round 13 tests: ten land-fraud innovation features.

  F1  geospatial overlap detection (beacon polygons, not just labels)
  F2  centroid-geohash re-survey proximity flag
  F3  root-of-title chain analysis (missing root, quick flip, churn)
  F4  seller velocity / serial-fraud detection
  F5  public notice period + objections workflow
  F6  explainable 0-100 risk score alongside the legacy verdict
  F7  professional attestation cross-check on deeds
  F8  consent identity binding (BVN/NIN hash-only, liveness challenge)
  F9  evidence-chain Merkle anchoring
  F10 fraud-typology analytics

Run: python3 -m pytest tests/test_land_innovations.py -q
     (from services/land-verification-service)
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.data_store import LandDataStore, reset_land_store_for_tests  # noqa: E402
from api.geospatial import centroid_geohash, parse_beacons, polygons_overlap  # noqa: E402
from api.main import create_app  # noqa: E402
from api.risk import score_factors  # noqa: E402
from api.title_chain import analyze_title_chain  # noqa: E402
from embedded_pg import clone_migrated, fresh_database

SQUARE_A = "6.4500N 3.4000E, 6.4510N 3.4000E, 6.4510N 3.4010E, 6.4500N 3.4010E"
SQUARE_B_OVERLAP = "6.4505N 3.4005E, 6.4515N 3.4005E, 6.4515N 3.4015E, 6.4505N 3.4015E"
SQUARE_C_FAR = "6.4600N 3.4100E, 6.4610N 3.4100E, 6.4610N 3.4110E, 6.4600N 3.4110E"
# Distinct from A but close enough to share a precision-6 geohash cell
SQUARE_D_NEAR = "6.4511N 3.4000E, 6.4512N 3.4000E, 6.4512N 3.4001E, 6.4511N 3.4001E"


@pytest.fixture()
def store(tmp_path):
    s = LandDataStore(database_url=clone_migrated("land"), seed=False)
    reset_land_store_for_tests(s)
    yield s
    reset_land_store_for_tests(None)


@pytest.fixture()
def client(store):
    return TestClient(create_app())


def _register(client, ref="PLT-100", **overrides):
    payload = {"parcel_ref": ref, "state": "Lagos", "lga": "Eti-Osa",
               "certificate_number": f"CERT-{ref}", "beacons": SQUARE_A,
               "consent_required": ["Party A"], "notice_period_days": 0}
    payload.update(overrides)
    return client.post("/api/v1/parcels", json=payload)


# ---------------------------------------------------------------------------
# F1/F2 geospatial primitives + registration wiring
# ---------------------------------------------------------------------------

class TestGeospatial:
    def test_parse_beacons_text_and_json(self):
        poly = parse_beacons(SQUARE_A)
        assert len(poly) == 4 and abs(poly[0][0] - 6.45) < 1e-6
        assert parse_beacons("[[6.45, 3.40], [6.46, 3.41]]") == [(6.45, 3.40), (6.46, 3.41)]
        assert parse_beacons("garbage") == []
        assert parse_beacons(None) == []

    def test_polygons_overlap_and_disjoint(self):
        a, b, c = (parse_beacons(x) for x in (SQUARE_A, SQUARE_B_OVERLAP, SQUARE_C_FAR))
        assert polygons_overlap(a, b) is True
        assert polygons_overlap(a, c) is False

    def test_centroid_geohash_shared_cell(self):
        a, d, c = (parse_beacons(x) for x in (SQUARE_A, SQUARE_D_NEAR, SQUARE_C_FAR))
        assert centroid_geohash(a, 6) == centroid_geohash(d, 6)
        assert centroid_geohash(a, 6) != centroid_geohash(c, 6)

    def test_overlap_registration_disputed_and_conflict_recorded(self, client):
        _register(client, ref="PLT-100")
        r = _register(client, ref="PLT-101", beacons=SQUARE_B_OVERLAP)
        assert r.status_code == 201
        assert r.json()["status"] == "disputed"
        keys = [c["conflict_key"] for c in r.json()["conflicts"]]
        assert "geospatial_overlap:PLT-100" in keys
        conflicts = client.get("/api/v1/parcels/PLT-101").json()
        assert conflicts["status"] == "disputed"

    def test_far_parcel_no_geospatial_conflict(self, client):
        _register(client, ref="PLT-100")
        r = _register(client, ref="PLT-102", beacons=SQUARE_C_FAR)
        assert r.status_code == 201
        assert all(not c["conflict_key"].startswith("geospatial_overlap")
                   for c in r.json()["conflicts"])

    def test_proximity_flag_does_not_block_clearing(self, client):
        _register(client, ref="PLT-100")
        r = _register(client, ref="PLT-103", beacons=SQUARE_D_NEAR)
        keys = [c["conflict_key"] for c in r.json()["conflicts"]]
        assert "resurvey_proximity:PLT-100" in keys
        assert r.json()["status"] == "provisional"  # review flag, not a block
        client.post("/api/v1/parcels/PLT-103/consents",
                    json={"party_name": "Party A", "confirmed": True})
        assert client.get("/api/v1/parcels/PLT-103").json()["status"] == "clear"


# ---------------------------------------------------------------------------
# F3 title-chain analysis
# ---------------------------------------------------------------------------

class TestTitleChain:
    def test_missing_root_flagged(self):
        result = analyze_title_chain(
            [{"transfer_type": "assignment", "owner_name": "X", "transfer_date": "2020-01-01"}])
        assert any(i["code"] == "missing_root" for i in result["issues"])
        assert result["score_penalty"] >= 35

    def test_clean_chain_no_penalty(self):
        result = analyze_title_chain([
            {"transfer_type": "certificate_of_occupancy", "owner_name": "A",
             "transfer_date": "2001-01-01"},
            {"transfer_type": "assignment", "owner_name": "B",
             "transfer_date": "2010-01-01"}])
        assert result["issues"] == [] and result["score_penalty"] == 0

    def test_quick_flip_and_churn(self):
        records = [{"transfer_type": "registration", "owner_name": "A",
                    "transfer_date": "2026-01-01"}]
        for i in range(6):
            records.append({"transfer_type": "sale", "owner_name": f"B{i}",
                            "transfer_date": f"2026-0{min(i + 2, 9)}-01"})
        result = analyze_title_chain(records)
        codes = {i["code"] for i in result["issues"]}
        assert "quick_flip" in codes and "excessive_transfers" in codes
        assert result["score_penalty"] <= 60

    def test_no_history(self):
        assert analyze_title_chain([])["issues"][0]["code"] == "no_history"


# ---------------------------------------------------------------------------
# F5 notice period + objections; F4 velocity; F6 score; F8 identity; F9; F10
# ---------------------------------------------------------------------------

class TestNoticeAndObjections:
    def test_notice_window_blocks_clearing_until_expired(self, client):
        _register(client, ref="PLT-110", notice_period_days=21)
        client.post("/api/v1/parcels/PLT-110/consents",
                    json={"party_name": "Party A", "confirmed": True})
        body = client.get("/api/v1/parcels/PLT-110").json()
        assert body["status"] == "provisional"
        assert body["notice_active"] is True

    def test_zero_notice_clears_immediately(self, client):
        _register(client, ref="PLT-111")
        client.post("/api/v1/parcels/PLT-111/consents",
                    json={"party_name": "Party A", "confirmed": True})
        assert client.get("/api/v1/parcels/PLT-111").json()["status"] == "clear"

    def test_objection_disputes_and_resolution_restores(self, client):
        _register(client, ref="PLT-112")
        client.post("/api/v1/parcels/PLT-112/consents",
                    json={"party_name": "Party A", "confirmed": True})
        assert client.get("/api/v1/parcels/PLT-112").json()["status"] == "clear"
        r = client.post("/api/v1/parcels/PLT-112/objections",
                        json={"objector_name": "Community Head",
                              "grounds": "family land sold without consent"})
        assert r.status_code == 201
        oid = r.json()["objection_id"]
        assert client.get("/api/v1/parcels/PLT-112").json()["status"] == "disputed"
        r2 = client.post(f"/api/v1/objections/{oid}/resolve",
                         json={"status": "dismissed", "resolution": "no evidence"})
        assert r2.json()["status"] == "dismissed"
        assert client.get("/api/v1/parcels/PLT-112").json()["status"] == "clear"

    def test_objector_id_stored_hash_only(self, client, store):
        _register(client, ref="PLT-113")
        client.post("/api/v1/parcels/PLT-113/objections",
                    json={"objector_name": "Chief X", "objector_id": "12345678901",
                          "grounds": "boundary encroachment"})
        row = store.query_one("SELECT * FROM parcel_objections")
        assert row["objector_id_hash"] == hashlib.sha256(b"12345678901").hexdigest()
        assert "12345678901" not in str(row)


class TestConsentIdentityBinding:
    def test_bvn_validated_and_hashed(self, client, store):
        _register(client, ref="PLT-120")
        bad = client.post("/api/v1/parcels/PLT-120/consents",
                          json={"party_name": "Party A", "bvn_or_nin": "123"})
        assert bad.status_code == 422
        ok = client.post("/api/v1/parcels/PLT-120/consents",
                         json={"party_name": "Party A", "bvn_or_nin": "22233344455"})
        assert ok.status_code == 200
        row = store.query_one("SELECT * FROM parcel_consents")
        assert row["identity_hash"] == hashlib.sha256(b"22233344455").hexdigest()
        assert "22233344455" not in str(row)

    def test_liveness_requires_challenge_id(self, client):
        _register(client, ref="PLT-121")
        r = client.post("/api/v1/parcels/PLT-121/consents",
                        json={"party_name": "Party A", "method": "liveness"})
        assert r.status_code == 422
        ok = client.post("/api/v1/parcels/PLT-121/consents",
                         json={"party_name": "Party A", "method": "liveness",
                               "liveness_challenge_id": "ch_abc123"})
        assert ok.status_code == 200


class TestRiskScoring:
    def test_bands(self):
        assert score_factors([])["band"] == "clear"
        assert score_factors([{"code": "consent_incomplete"}])["band"] == "clear"  # 15
        assert score_factors([{"code": "registry_not_found"}])["band"] == "caution"  # 30
        assert score_factors([{"code": "owner_mismatch"},
                              {"code": "open_dispute"}])["band"] == "high_risk"  # 60

    def test_score_capped_at_100_and_factors_reported(self):
        scored = score_factors([{"code": "owner_mismatch"},
                                {"code": "geospatial_overlap"},
                                {"code": "uncompensated_revocation"}])
        assert scored["risk_score"] == 100
        assert all("penalty" in f and "detail" in f for f in scored["factors"])

    def test_due_diligence_returns_score_and_factors(self, client):
        _register(client, ref="PLT-130")
        client.post("/api/v1/parcels/PLT-130/revocations", json={"reason": "public purpose"})
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "parcel_ref": "PLT-130"})
        body = r.json()
        assert body["verdict"] == "high_risk"
        assert body["risk_score"] >= 40
        codes = {f["code"] for f in body["factors"]}
        assert "uncompensated_revocation" in codes
        assert body["reasons"]  # legacy back-compat list retained

    def test_serial_seller_factor(self, client):
        for i in range(5):
            _register(client, ref=f"PLT-14{i}", beacons=None,
                      registered_by="Omo Onile X")
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "parcel_ref": "PLT-140"})
        body = r.json()
        assert body["signals"]["seller_velocity"]["parcels_in_window"] == 5
        assert "serial_seller" in {f["code"] for f in body["factors"]}


class TestDeedAttestation:
    DEED = """
DEED OF ASSIGNMENT made this 10th day of March, 2026.
BETWEEN Chief A (the Assignor) AND Mrs. B (the Assignee).
WHEREAS the Assignor is the beneficial owner of ALL THAT parcel of land
situate at Plot 1, Lagos with a good root of title.
NOW THIS DEED WITNESSES that in consideration of the sum of N5,000,000 paid,
the Assignor assigns the parcel TO HAVE AND TO HOLD unto the Assignee.
The Assignor hereby covenants quiet enjoyment.
Subject to the Governor's consent pursuant to section 22 of the Land Use Act.
IN WITNESS WHEREOF the parties have executed this deed.
SIGNED by the Assignor: Chief A (signature)
SIGNED by the Assignee: Mrs. B (signature)
In the presence of: Barrister W (witness signature)
Surveyed by: Surveyor S, SURCON/2026/1234
"""

    def test_attestation_cross_check(self, client):
        r = client.post("/api/v1/deeds/conformance", json={
            "deed_text": self.DEED, "witness_names": ["Barrister W"],
            "surveyor_name": "Surveyor S", "surveyor_license": "SURCON/2026/1234"})
        att = r.json()["professional_attestation"]
        assert att["all_attested"] is True
        assert att["surveyor"]["mentioned_in_deed"] is True
        assert att["surveyor"]["license_verified"] is None  # honest: no live adapter

    def test_unattested_witness_fails_conformance(self, client):
        r = client.post("/api/v1/deeds/conformance", json={
            "deed_text": self.DEED, "witness_names": ["Ghost Witness"]})
        att = r.json()["professional_attestation"]
        assert att["all_attested"] is False
        assert att["unattested_witnesses"] == ["Ghost Witness"]
        assert r.json()["conformant"] is False


class TestMerkleAnchor:
    def test_anchor_changes_with_chain_and_is_stable(self, client):
        _register(client, ref="PLT-150")
        a1 = client.get("/api/v1/parcels/PLT-150/evidence/anchor").json()
        assert a1["chain_valid"] is True and a1["leaf_count"] >= 1
        again = client.get("/api/v1/parcels/PLT-150/evidence/anchor").json()
        assert again["merkle_root"] == a1["merkle_root"]
        client.post("/api/v1/parcels/PLT-150/consents",
                    json={"party_name": "Party A", "confirmed": True})
        a2 = client.get("/api/v1/parcels/PLT-150/evidence/anchor").json()
        assert a2["merkle_root"] != a1["merkle_root"]

    def test_record_anchor_event(self, client):
        _register(client, ref="PLT-151")
        r = client.post("/api/v1/parcels/PLT-151/evidence/anchor")
        assert r.status_code == 201
        pack = client.get("/api/v1/parcels/PLT-151/evidence").json()
        assert pack["chain_valid"] is True
        assert any(e["event_type"] == "evidence_anchored" for e in pack["entries"])


class TestFraudTypologies:
    def test_analytics_aggregates_by_class(self, client):
        _register(client, ref="PLT-160")
        _register(client, ref="PLT-161", beacons=SQUARE_B_OVERLAP)
        _register(client, ref="PLT-162", beacons=SQUARE_C_FAR,
                  certificate_number="CERT-PLT-160")  # cert reuse conflict
        client.post("/api/v1/parcels/PLT-160/objections",
                    json={"objector_name": "Chief Y", "grounds": "grabbed land"})
        r = client.get("/api/v1/analytics/fraud-typologies?state=lagos")
        body = r.json()
        assert body["typologies"]["geospatial_overlap"] == 1
        assert body["typologies"]["certificate_number"] == 1
        assert body["totals"]["objections_open"] == 1
        empty = client.get("/api/v1/analytics/fraud-typologies?state=kano").json()
        assert empty["totals"]["conflicts"] == 0
