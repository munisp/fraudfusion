"""Land due-diligence SDK method tests (Round 12) — offline via MockTransport."""

from __future__ import annotations

import json

import httpx
import pytest

from fraudfusion import FraudFusionClient
from test_client import Recorder, json_response  # reuse the Round-9 harness


@pytest.fixture
def rec():
    return Recorder()


def test_land_due_diligence_payload(rec):
    client = rec.router({("POST", "/api/v1/due-diligence"): {"verdict": "clear"}})
    out = client.land_due_diligence(state="Lagos", certificate_number="CERT-4521",
                                    claimed_owner="Chief Seller")
    assert out["verdict"] == "clear"
    body = json.loads(rec.requests[0].content)
    assert body == {"state": "Lagos", "certificate_number": "CERT-4521",
                    "claimed_owner": "Chief Seller"}


def test_land_due_diligence_drops_none(rec):
    client = rec.router({("POST", "/api/v1/due-diligence"): {"verdict": "high_risk"}})
    client.land_due_diligence(state="Lagos", certificate_number="CERT-1")
    body = json.loads(rec.requests[0].content)
    assert "property_address" not in body and "parcel_ref" not in body


def test_land_register_parcel_payload_and_auto_idempotency(rec):
    client = rec.router({("POST", "/api/v1/parcels"):
                         ({"parcel_ref": "PLT-1", "status": "provisional"}, 201)})
    out = client.land_register_parcel(
        parcel_ref="PLT-1", state="Lagos", certificate_number="CERT-1",
        consent_required=["Party A"])
    assert out["status"] == "provisional"
    req = rec.requests[0]
    assert req.headers["Idempotency-Key"]
    body = json.loads(req.content)
    assert body["consent_required"] == ["Party A"]
    assert "lga" not in body


def test_land_register_conflict_raises(rec):
    from fraudfusion import ConflictError
    client = rec.router({("POST", "/api/v1/parcels"):
                         ({"detail": {"error": "parcel_conflict",
                                      "conflict_key": "parcel_ref:PLT-1"}}, 409)})
    with pytest.raises(ConflictError):
        client.land_register_parcel(parcel_ref="PLT-1", state="Lagos")


def test_land_consent(rec):
    client = rec.router({("POST", "/api/v1/parcels/PLT-1/consents"): {"status": "clear"}})
    out = client.land_record_consent("PLT-1", party_name="Party A", method="signature")
    assert out["status"] == "clear"
    body = json.loads(rec.requests[0].content)
    assert body == {"party_name": "Party A", "confirmed": True, "method": "signature"}


def test_land_deed_conformance(rec):
    client = rec.router({("POST", "/api/v1/deeds/conformance"): {"conformant": True}})
    out = client.land_deed_conformance("DEED TEXT", consent_parties=["Heir One"],
                                       parcel_ref="PLT-1")
    assert out["conformant"] is True
    body = json.loads(rec.requests[0].content)
    assert body["consent_parties"] == ["Heir One"]


def test_land_dispute_flow(rec):
    client = rec.router({
        ("POST", "/api/v1/parcels/PLT-1/disputes"):
            ({"dispute_id": "d1", "sla_days": 90}, 201),
        ("POST", "/api/v1/disputes/d1/resolve"): {"status": "resolved"},
        ("GET", "/api/v1/parcels/PLT-1/disputes"): {"open": 0, "disputes": []},
    })
    d = client.land_open_dispute("PLT-1", case_number="LD/1/2026")
    assert d["sla_days"] == 90
    assert client.land_resolve_dispute("d1", resolution="settled")["status"] == "resolved"
    assert client.land_list_disputes("PLT-1")["open"] == 0


def test_land_revocation_flow(rec):
    client = rec.router({
        ("POST", "/api/v1/parcels/PLT-1/revocations"):
            ({"revocation_id": "r1", "acquisition_lawful": False}, 201),
        ("POST", "/api/v1/revocations/r1/documents"): {"status": "documents_collected"},
        ("POST", "/api/v1/revocations/r1/compensate"): {"acquisition_lawful": True},
    })
    r = client.land_open_revocation("PLT-1", notice_ref="GOV-1")
    assert r["acquisition_lawful"] is False
    client.land_revocation_documents("r1")
    assert client.land_compensate_revocation("r1", amount=5_000_000, method="transfer")[
        "acquisition_lawful"] is True
    body = json.loads(rec.requests[-1].content)
    assert body == {"amount": 5_000_000, "method": "transfer"}


def test_land_evidence_pack(rec):
    client = rec.router({("GET", "/api/v1/parcels/PLT-1/evidence"):
                         {"chain_valid": True, "entry_count": 3}})
    out = client.land_evidence_pack("PLT-1")
    assert out["chain_valid"] is True
