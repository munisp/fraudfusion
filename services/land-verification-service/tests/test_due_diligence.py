"""Round 11 tests: land due-diligence module.

Covers the buildable recommendations from the Channels TV land-fraud
interview (docs/land-fraud-video-recommendations.md):

  * parcels: first-wins registration; duplicate parcel_ref -> 409 + recorded
    conflict; same certificate/survey hash under a new ref -> conflict record
    + disputed status (multiple-sale detection at registration time).
  * consents: parcel stays provisional until EVERY required party confirms
    ("bought from two families instead of seven" is not consent).
  * deed conformance: standard clause list enforced; consent-party signature
    blocks required (name in recitals alone is not consent).
  * disputes: 90-day SLA clock; overdue open cases flagged sla_breached;
    resolution restores parcel status.
  * revocations: Land Use Act ordering — compensation only after documents
    collected; acquisition_lawful only when compensated.
  * evidence: hash chain verifies; tampering detected.
  * due-diligence composite: registry owner cross-check (CTC equivalent),
    owner mismatch, multiple claimants, consent gaps, uncompensated
    revocation -> clear|caution|high_risk|unavailable.

Run: python3 -m pytest tests/test_due_diligence.py -q
     (from services/land-verification-service)
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.data_store import LandDataStore, reset_land_store_for_tests  # noqa: E402
from api.deed_conformance import check_deed_conformance  # noqa: E402
from api.evidence import verify_chain  # noqa: E402
from api.main import create_app  # noqa: E402

GOOD_DEED = """
DEED OF ASSIGNMENT made this 10th day of March, 2026.
BETWEEN Chief Adewale Okafor (the Assignor) of the one part AND
Mrs. Ngozi Eze (the Assignee) of the other part.
WHEREAS the Assignor is the beneficial owner of ALL THAT parcel of land
situate at Plot 452, Badore, Eti-Osa LGA, Lagos State, covered by survey plan
No. LS/452/2001 with beacons 6.45N 3.40E and 6.46N 3.41E, having a good root
of title.
NOW THIS DEED WITNESSES that in consideration of the sum of N25,000,000
(Twenty-Five Million Naira) paid by the Assignee, the Assignor assigns the
parcel TO HAVE AND TO HOLD unto the Assignee absolutely.
The Assignor hereby covenants that he has good title and that the Assignee
shall have quiet enjoyment of the parcel.
This assignment is subject to the Governor's consent pursuant to section 22
of the Land Use Act 1978.
IN WITNESS WHEREOF the parties have executed this deed.
SIGNED by the Assignor: Chief Adewale Okafor (signature)
SIGNED by the Assignee: Mrs. Ngozi Eze (signature)
SIGNED in consent by: Emeka Okafor (signature of consent party)
In the presence of: Barrister T. Adeyemi (witness)
"""


@pytest.fixture()
def store(tmp_path):
    s = LandDataStore(sqlite_path=str(tmp_path / "land_test.db"), seed=False)
    reset_land_store_for_tests(s)
    yield s
    reset_land_store_for_tests(None)


@pytest.fixture()
def client(store):
    return TestClient(create_app())


def _register(client, ref="PLT-001", **overrides):
    payload = {"parcel_ref": ref, "state": "Lagos", "lga": "Eti-Osa",
               "property_address": "Plot 452, Badore", "certificate_number": "CERT-452",
               "consent_required": ["Emeka Okafor", "Ngozi Family Head"],
               "notice_period_days": 0}  # R13: opt out of the notice window
    payload.update(overrides)
    return client.post("/api/v1/parcels", json=payload)


# ---------------------------------------------------------------------------
# Parcels: first-wins + conflict detection
# ---------------------------------------------------------------------------

class TestParcelFirstWins:
    def test_register_creates_provisional(self, client):
        r = _register(client)
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "provisional"
        assert body["consent_complete"] is False
        assert set(body["consent_outstanding"]) == {"Emeka Okafor", "Ngozi Family Head"}

    def test_duplicate_ref_409_and_conflict_recorded(self, client):
        _register(client)
        r = _register(client)
        assert r.status_code == 409
        detail = r.json()["detail"]
        assert detail["error"] == "parcel_conflict"
        assert detail["existing_ref"] == "PLT-001"

    def test_same_certificate_new_ref_flagged_disputed(self, client):
        _register(client)
        r = _register(client, ref="PLT-002")
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "disputed"
        assert body["conflicts"][0]["conflict_key"] == "certificate_number:CERT-452"

    def test_same_survey_hash_new_ref_conflict(self, client):
        _register(client, survey_plan_hash="hash-abc")
        r = _register(client, ref="PLT-009", certificate_number="CERT-999",
                      survey_plan_hash="hash-abc")
        assert r.json()["status"] == "disputed"
        assert any("survey_plan_hash" in c["conflict_key"] for c in r.json()["conflicts"])

    def test_get_unknown_parcel_404(self, client):
        assert client.get("/api/v1/parcels/NOPE").status_code == 404


# ---------------------------------------------------------------------------
# Consents: every required party must confirm
# ---------------------------------------------------------------------------

class TestConsents:
    def test_partial_consent_stays_provisional(self, client):
        _register(client)
        r = client.post("/api/v1/parcels/PLT-001/consents",
                        json={"party_name": "Emeka Okafor", "confirmed": True,
                              "method": "signature"})
        assert r.json()["status"] == "provisional"

    def test_full_consent_clears(self, client):
        _register(client)
        for party in ("Emeka Okafor", "Ngozi Family Head"):
            client.post("/api/v1/parcels/PLT-001/consents",
                        json={"party_name": party, "confirmed": True})
        assert client.get("/api/v1/parcels/PLT-001").json()["status"] == "clear"

    def test_consent_withdrawal_recorded(self, client):
        _register(client)
        client.post("/api/v1/parcels/PLT-001/consents",
                    json={"party_name": "Emeka Okafor", "confirmed": True})
        client.post("/api/v1/parcels/PLT-001/consents",
                    json={"party_name": "Emeka Okafor", "confirmed": False})
        body = client.get("/api/v1/parcels/PLT-001").json()
        assert "Emeka Okafor" in body["consent_outstanding"]

    def test_conflict_blocks_clear_even_with_full_consent(self, client):
        _register(client, ref="PLT-100")
        r = _register(client, ref="PLT-101")
        assert r.json()["status"] == "disputed"
        for party in ("Emeka Okafor", "Ngozi Family Head"):
            client.post("/api/v1/parcels/PLT-101/consents",
                        json={"party_name": party, "confirmed": True})
        assert client.get("/api/v1/parcels/PLT-101").json()["status"] == "disputed"


# ---------------------------------------------------------------------------
# Deed conformance
# ---------------------------------------------------------------------------

class TestDeedConformance:
    def test_good_deed_conformant(self):
        result = check_deed_conformance(GOOD_DEED, consent_parties=["Emeka Okafor"])
        assert result["conformant"] is True
        assert result["missing"] == []
        assert result["consent_parties_missing"] == []

    def test_missing_clauses_reported(self):
        result = check_deed_conformance("The Assignor and the Assignee agree to a sale.")
        assert result["conformant"] is False
        missing = {m["clause"] for m in result["missing"]}
        assert {"recitals", "habendum", "governors_consent", "parcel_description"} & missing

    def test_consent_party_name_without_signature_not_consent(self):
        # The video's exact fraud: an heir's name appears, but they never
        # signed — they later deny consent.
        deed = GOOD_DEED.replace("SIGNED in consent by: Emeka Okafor (signature of consent party)",
                                 "The family includes Emeka Okafor.")
        result = check_deed_conformance(deed, consent_parties=["Emeka Okafor"])
        assert result["conformant"] is False
        assert result["consent_parties_missing"] == ["Emeka Okafor"]

    def test_empty_deed_not_conformant(self):
        assert check_deed_conformance("")["conformant"] is False

    def test_endpoint_records_evidence(self, client):
        _register(client)
        r = client.post("/api/v1/deeds/conformance",
                        json={"deed_text": GOOD_DEED, "parcel_ref": "PLT-001",
                              "consent_parties": ["Emeka Okafor"]})
        assert r.json()["conformant"] is True
        pack = client.get("/api/v1/parcels/PLT-001/evidence").json()
        assert any(e["event_type"] == "deed_conformance_checked" for e in pack["entries"])


# ---------------------------------------------------------------------------
# Disputes: 90-day SLA clock
# ---------------------------------------------------------------------------

class TestDisputes:
    def test_open_dispute_sets_sla_and_disputes_parcel(self, client):
        _register(client)
        r = client.post("/api/v1/parcels/PLT-001/disputes",
                        json={"case_number": "LD/452/2026", "description": "land grabber"})
        assert r.status_code == 201
        body = r.json()
        assert body["sla_days"] == 90
        assert body["sla_breached"] is False
        assert client.get("/api/v1/parcels/PLT-001").json()["status"] == "disputed"

    def test_sla_breach_flagged(self, client):
        _register(client)
        past = (datetime.utcnow() - timedelta(days=120)).isoformat()
        r = client.post("/api/v1/parcels/PLT-001/disputes", json={"filed_at": past})
        assert r.json()["sla_breached"] is True
        assert r.json()["days_open"] >= 120

    def test_custom_sla(self, client):
        _register(client)
        past = (datetime.utcnow() - timedelta(days=45)).isoformat()
        r = client.post("/api/v1/parcels/PLT-001/disputes",
                        json={"filed_at": past, "sla_days": 30})
        assert r.json()["sla_breached"] is True

    def test_resolve_restores_status_and_lists(self, client):
        _register(client)
        d = client.post("/api/v1/parcels/PLT-001/disputes", json={}).json()
        r = client.post(f"/api/v1/disputes/{d['dispute_id']}/resolve",
                        json={"resolution": "consent judgement for buyer"})
        assert r.json()["status"] == "resolved"
        parcel = client.get("/api/v1/parcels/PLT-001").json()
        assert parcel["status"] == "provisional"  # consents still outstanding
        listing = client.get("/api/v1/parcels/PLT-001/disputes").json()
        assert listing["open"] == 0 and len(listing["disputes"]) == 1

    def test_double_resolve_409(self, client):
        _register(client)
        d = client.post("/api/v1/parcels/PLT-001/disputes", json={}).json()
        client.post(f"/api/v1/disputes/{d['dispute_id']}/resolve", json={"resolution": "x"})
        r = client.post(f"/api/v1/disputes/{d['dispute_id']}/resolve", json={"resolution": "y"})
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# Revocations: Land Use Act ordering + lawfulness
# ---------------------------------------------------------------------------

class TestRevocations:
    def test_full_workflow_lawful_only_after_compensation(self, client):
        _register(client)
        r = client.post("/api/v1/parcels/PLT-001/revocations",
                        json={"notice_ref": "GOV-NOTICE-1", "reason": "public purpose"})
        rid = r.json()["revocation_id"]
        assert r.json()["acquisition_lawful"] is False
        assert client.get("/api/v1/parcels/PLT-001").json()["status"] == "revoked"

        # Compensation before documents -> rejected (documents first).
        r = client.post(f"/api/v1/revocations/{rid}/compensate",
                        json={"amount": 5000000, "method": "bank transfer"})
        assert r.status_code == 409

        r = client.post(f"/api/v1/revocations/{rid}/documents")
        assert r.json()["status"] == "documents_collected"
        assert r.json()["acquisition_lawful"] is False

        r = client.post(f"/api/v1/revocations/{rid}/compensate",
                        json={"amount": 5000000, "method": "bank transfer"})
        assert r.json()["acquisition_lawful"] is True

    def test_second_open_revocation_409(self, client):
        _register(client)
        client.post("/api/v1/parcels/PLT-001/revocations", json={})
        assert client.post("/api/v1/parcels/PLT-001/revocations", json={}).status_code == 409

    def test_uncompensated_listed(self, client):
        _register(client)
        client.post("/api/v1/parcels/PLT-001/revocations", json={})
        listing = client.get("/api/v1/parcels/PLT-001/revocations").json()
        assert listing["uncompensated"] == 1


# ---------------------------------------------------------------------------
# Evidence chain
# ---------------------------------------------------------------------------

class TestEvidence:
    def test_chain_verifies_after_full_journey(self, client):
        _register(client)
        client.post("/api/v1/parcels/PLT-001/consents",
                    json={"party_name": "Emeka Okafor", "confirmed": True})
        d = client.post("/api/v1/parcels/PLT-001/disputes", json={}).json()
        client.post(f"/api/v1/disputes/{d['dispute_id']}/resolve", json={"resolution": "settled"})
        pack = client.get("/api/v1/parcels/PLT-001/evidence").json()
        assert pack["chain_valid"] is True
        types = [e["event_type"] for e in pack["entries"]]
        assert types == ["parcel_registered", "consent_recorded",
                         "dispute_opened", "dispute_resolved"]

    def test_tamper_detected(self, client):
        _register(client)
        client.post("/api/v1/parcels/PLT-001/consents",
                    json={"party_name": "Emeka Okafor", "confirmed": True})
        pack = client.get("/api/v1/parcels/PLT-001/evidence").json()
        tampered = [dict(e) for e in pack["entries"]]
        tampered[0]["event_type"] = "parcel_stolen"  # alter history
        assert verify_chain(tampered, "PLT-001") is False

    def test_removal_detected(self, client):
        _register(client)
        client.post("/api/v1/parcels/PLT-001/consents",
                    json={"party_name": "Emeka Okafor", "confirmed": True})
        pack = client.get("/api/v1/parcels/PLT-001/evidence").json()
        assert verify_chain(pack["entries"][1:], "PLT-001") is False


# ---------------------------------------------------------------------------
# Composite due diligence
# ---------------------------------------------------------------------------

class TestDueDiligence:
    @staticmethod
    def _seed_registry(store, cert="SYN-CERT-001", owner="SYNTHETIC Landowner One"):
        store.execute(
            "INSERT INTO lands_registry_records (tenant_id, state, certificate_number, owner_name)"
            " VALUES ('default', 'lagos', :c, :o)", {"c": cert, "o": owner})

    def test_clear_verdict_on_clean_parcel(self, client, store):
        self._seed_registry(store)
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "certificate_number": "SYN-CERT-001",
                              "claimed_owner": "SYNTHETIC Landowner One"})
        assert r.status_code == 200
        assert r.json()["verdict"] == "clear"
        assert r.json()["signals"]["registry"]["status"] == "found"

    def test_owner_mismatch_high_risk(self, client, store):
        self._seed_registry(store)
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "certificate_number": "SYN-CERT-001",
                              "claimed_owner": "Chief Fraudster"})
        assert r.json()["verdict"] == "high_risk"
        assert any(x["code"] == "owner_mismatch" for x in r.json()["reasons"])

    def test_registry_not_found_high_risk(self, client):
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "certificate_number": "CERT-GHOST"})
        assert r.json()["verdict"] == "high_risk"
        assert any(x["code"] == "registry_not_found" for x in r.json()["reasons"])

    def test_consent_gap_caution(self, client, store):
        store.execute(
            "INSERT INTO lands_registry_records (tenant_id, state, certificate_number, owner_name)"
            " VALUES ('default', 'lagos', 'CERT-452', 'Chief Adewale Okafor')")
        _register(client)
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "certificate_number": "CERT-452",
                              "claimed_owner": "Chief Adewale Okafor", "parcel_ref": "PLT-001"})
        assert r.json()["verdict"] == "caution"
        assert any(x["code"] == "consent_incomplete" for x in r.json()["reasons"])

    def test_uncompensated_revocation_high_risk(self, client, store):
        store.execute(
            "INSERT INTO lands_registry_records (tenant_id, state, certificate_number, owner_name)"
            " VALUES ('default', 'lagos', 'CERT-452', 'Chief Adewale Okafor')")
        _register(client)
        client.post("/api/v1/parcels/PLT-001/revocations", json={})
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "certificate_number": "CERT-452",
                              "claimed_owner": "Chief Adewale Okafor", "parcel_ref": "PLT-001"})
        assert r.json()["verdict"] == "high_risk"
        assert any(x["code"] == "uncompensated_revocation" for x in r.json()["reasons"])

    def test_multiple_claimants_high_risk(self, client, store):
        store.execute(
            "INSERT INTO lands_registry_records (tenant_id, state, certificate_number, owner_name)"
            " VALUES ('default', 'lagos', 'CERT-452', 'Chief Adewale Okafor')")
        for name in ("Family A", "Family B"):
            store.execute(
                "INSERT INTO parcel_claimants (tenant_id, state, certificate_number, claimant_name)"
                " VALUES ('default', 'lagos', 'CERT-452', :n)", {"n": name})
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "certificate_number": "CERT-452"})
        assert r.json()["verdict"] == "high_risk"
        assert any(x["code"] == "multiple_claimants" for x in r.json()["reasons"])

    def test_title_hash_stable_and_pii_free(self, client):
        r = client.post("/api/v1/due-diligence",
                        json={"state": "Lagos", "certificate_number": "SYN-CERT-001"})
        assert len(r.json()["title_sha256"]) == 64
