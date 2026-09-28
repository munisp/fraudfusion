"""Tests for land-verification-service remediation.

- State machine: site_inspection is no longer a dead end (inspection_report
  -> completed/rejected); illegal transitions raise.
- OCR adapters: tesseract (real binary), HTTP adapter fail-closed, honest
  'ocr: unavailable' when nothing is configured.
- Lands registry adapters: file-import fallback with provenance, HTTP
  fail-closed.
- Journey endpoint contracts: the exact response shapes the
  temporal-orchestrator journeys 34/37 unmarshal (Go struct field names).

Run: python3 -m pytest tests/ -q   (from services/land-verification-service)
"""

from __future__ import annotations

import base64
import sys
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.data_store import LandDataStore, reset_land_store_for_tests  # noqa: E402
from api.main import create_app  # noqa: E402
from api.ocr import HttpOcrAdapter, TesseractAdapter  # noqa: E402
from api.registry_adapters import (  # noqa: E402
    FileImportLandsRegistryAdapter,
    HttpLandsRegistryAdapter,
)
from api.verification_workflow import (  # noqa: E402
    StateTransitionError,
    VerificationStore,
    VerificationWorkflow,
)
from models.schemas import ALLOWED_TRANSITIONS, VerificationStatus  # noqa: E402

DOC = b"""PLOT: PLT-9921
PLAN: SP-2210
CERT: CERT-XYZ-1
LGA: Eti-Osa
ASSIGNOR: Chief Seller
ASSIGNEE: Buyer One
BEACONS: 6.45N 3.40E, 6.46N 3.41E
"""


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("LAND_VERIFY_DB", str(tmp_path / "wf.db"))
    s = LandDataStore(database_url="", sqlite_path=str(tmp_path / "land.db"))
    yield s
    reset_land_store_for_tests(None)


@pytest.fixture()
def workflow(tmp_path, monkeypatch):
    monkeypatch.setenv("LAND_VERIFY_DB", str(tmp_path / "wf.db"))
    import api.verification_workflow as vw

    monkeypatch.setattr(vw, "DEFAULT_SQLITE_PATH", str(tmp_path / "wf.db"))
    return VerificationWorkflow(store=VerificationStore(database_url=""))


def make_client(store):
    import api.verification_workflow as vw

    app = create_app()
    app.dependency_overrides[svc_get_land_store()] = lambda: store
    return app


def svc_get_land_store():
    from api.extended import get_land_store

    return get_land_store


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class TestStateMachine:
    def test_legal_inspection_path(self, workflow):
        vid = "v-1"
        store = workflow.store
        store.record_transition(vid, None, VerificationStatus.RECEIVED)
        store.record_transition(vid, VerificationStatus.RECEIVED,
                                VerificationStatus.DOCUMENT_ANALYSIS)
        store.record_transition(vid, VerificationStatus.DOCUMENT_ANALYSIS,
                                VerificationStatus.REGISTRY_LOOKUP)
        store.record_transition(vid, VerificationStatus.REGISTRY_LOOKUP,
                                VerificationStatus.SITE_INSPECTION)
        workflow.record_inspection_report(vid, {"findings": "beacons present"},
                                          actor="insp-1")
        assert workflow.get_status(vid) == VerificationStatus.INSPECTION_REPORT
        workflow.complete_inspection(vid, VerificationStatus.COMPLETED,
                                     "all clear", actor="insp-1")
        assert workflow.get_status(vid) == VerificationStatus.COMPLETED
        history = workflow.get_history(vid)
        assert [h["to_status"] for h in history] == [
            "received", "document_analysis", "registry_lookup",
            "site_inspection", "inspection_report", "completed",
        ]

    def test_illegal_transitions_raise(self, workflow):
        vid = "v-2"
        store = workflow.store
        store.record_transition(vid, None, VerificationStatus.RECEIVED)
        # skipping ahead to completed is illegal
        with pytest.raises(StateTransitionError):
            store.record_transition(vid, VerificationStatus.RECEIVED,
                                    VerificationStatus.COMPLETED)
        # site_inspection -> completed now illegal: must file a report first
        with pytest.raises(StateTransitionError):
            store.record_transition(vid, VerificationStatus.SITE_INSPECTION,
                                    VerificationStatus.COMPLETED)
        # decision without a report is rejected by the workflow-level guard
        store.record_transition(vid, VerificationStatus.RECEIVED,
                                VerificationStatus.DOCUMENT_ANALYSIS)
        with pytest.raises(StateTransitionError):
            workflow.complete_inspection(vid, VerificationStatus.COMPLETED)

    def test_terminal_states_have_no_outgoing(self):
        assert ALLOWED_TRANSITIONS[VerificationStatus.COMPLETED] == set()
        assert ALLOWED_TRANSITIONS[VerificationStatus.REJECTED] == set()
        assert VerificationStatus.INSPECTION_REPORT in ALLOWED_TRANSITIONS[
            VerificationStatus.SITE_INSPECTION]

    def test_full_flow_registry_miss_lands_in_inspection(self, workflow):
        import asyncio
        from models.schemas import DocumentType, DocumentUploadRequest, VerificationRequest
        from models.schemas import State

        req = VerificationRequest(
            verification_id="v-flow",
            document_upload=DocumentUploadRequest(
                document_type=DocumentType.CERTIFICATE_OF_OCCUPANCY,
                file_name="c_of_o.txt", file_size=len(DOC),
                mime_type="text/plain", user_id="u-1", state=State.LAGOS,
            ),
            user_id="u-1",
        )
        result = asyncio.run(workflow.verify_document(DOC, req))
        assert result.status == VerificationStatus.SITE_INSPECTION
        # then the inspection path completes it
        workflow.record_inspection_report("v-flow", {"findings": "ok"})
        workflow.complete_inspection("v-flow", VerificationStatus.COMPLETED, "verified")
        assert workflow.get_status("v-flow") == VerificationStatus.COMPLETED


# ---------------------------------------------------------------------------
# OCR adapters
# ---------------------------------------------------------------------------

class TestOcrAdapters:
    def test_tesseract_real_ocr(self):
        if not TesseractAdapter.available():
            pytest.skip("tesseract binary not installed")
        from PIL import Image, ImageDraw, ImageFont

        img = Image.new("RGB", (900, 120), "white")
        draw = ImageDraw.Draw(img)
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 48)
        draw.text((10, 25), "PLOT 12345 LAGOS", fill="black", font=font)
        import io

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        result = TesseractAdapter().extract_text(buf.getvalue(), "image/png")
        assert result["status"] == "ok"
        assert "12345" in result["text"]
        assert result["confidence"] is None or result["confidence"] > 0.3

    def test_http_adapter_unreachable_is_unavailable(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down", request=request)

        adapter = HttpOcrAdapter("https://ocr.example.test",
                                 transport=httpx.MockTransport(handler))
        result = adapter.extract_text(b"\x89PNG fake")
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]

    def test_no_adapter_means_honest_unavailable(self, workflow, monkeypatch):
        import api.ocr as ocr_mod
        from models.schemas import DocumentType

        monkeypatch.setattr(ocr_mod, "OCR_SERVICE_URL", "")
        monkeypatch.setattr(ocr_mod.TesseractAdapter, "available", classmethod(lambda cls: False))
        extracted, conf = workflow._analyze_document_sync(
            b"\x89PNG\x0d\x0a binary", DocumentType.CERTIFICATE_OF_OCCUPANCY)
        # no text fabricated
        assert "plot_number" not in extracted
        assert extracted["ocr"] == "unavailable"
        assert conf == 0.0


# ---------------------------------------------------------------------------
# Lands registry adapters
# ---------------------------------------------------------------------------

class TestLandsRegistryAdapters:
    def test_file_import_owner_found_with_provenance(self, store):
        adapter = FileImportLandsRegistryAdapter(store)
        result = adapter.owner(state="Lagos", certificate_number="SYN-CERT-001")
        assert result["status"] == "found"
        assert result["name"] == "SYNTHETIC Landowner One"
        assert result["provenance"] == "seed-synthetic"

    def test_file_import_owner_not_found_honest(self, store):
        adapter = FileImportLandsRegistryAdapter(store)
        result = adapter.owner(state="Lagos", certificate_number="NOPE-1")
        assert result["status"] == "not_found"
        assert "import" in result["reason"]

    def test_http_adapter_fail_closed(self, store):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down", request=request)

        adapter = HttpLandsRegistryAdapter("https://lands.lagos.example.test",
                                           transport=httpx.MockTransport(handler))
        result = adapter.owner(state="Lagos", certificate_number="X")
        assert result["status"] == "unavailable"
        assert "unreachable" in result["reason"]


# ---------------------------------------------------------------------------
# Journey endpoint contracts (temporal-orchestrator journeys 34/37)
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(store, tmp_path, monkeypatch):
    import api.verification_workflow as vw
    from api.extended import get_land_store

    monkeypatch.setattr(vw, "DEFAULT_SQLITE_PATH", str(tmp_path / "wf.db"))
    vw._workflow = None
    app = create_app()
    app.dependency_overrides[get_land_store] = lambda: store
    yield TestClient(app, raise_server_exceptions=False)
    vw._workflow = None


class TestJourney34Contracts:
    def test_process_document_extracts_certificate_and_seller(self, client):
        resp = client.post("/api/v1/process-document",
                           json={"document_file": base64.b64encode(DOC).decode()})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # journey_34 reads extractedData["certificate_number"] and ["seller_name"]
        assert body["certificate_number"] == "CERT-XYZ-1"
        assert body["seller_name"] == "Chief Seller"
        assert body["plot_number"] == "PLT-9921"

    def test_detect_claimants_contract(self, client, store):
        store.execute(
            "INSERT INTO parcel_claimants (state, certificate_number, claimant_name,"
            " claim_date, document_type, document_ref, verified) VALUES"
            " ('Lagos', 'CERT-XYZ-1', 'Chief Seller', '2025-01-01T00:00:00', 'c_of_o', 'D1', 1)")
        store.execute(
            "INSERT INTO parcel_claimants (state, certificate_number, claimant_name,"
            " claim_date, document_type, document_ref, verified) VALUES"
            " ('Lagos', 'CERT-XYZ-1', 'Mister Fraudster', '2025-06-01T00:00:00', 'deed_of_assignment', 'D2', 0)")
        resp = client.post("/api/v1/detect-claimants",
                           json={"property_address": "1 SYNTHETIC Close, Ikoyi",
                                 "state": "Lagos", "certificate_number": "CERT-XYZ-1"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        claimants = body["claimants"]  # Go: response.Claimants []Claimant
        assert len(claimants) == 2
        # Go Claimant fields: name, claim_date, document_type, document_ref,
        # verified, conflicting
        for c in claimants:
            assert set(c) >= {"name", "claim_date", "document_type",
                              "document_ref", "verified", "conflicting"}
            assert c["conflicting"] is True  # two distinct claimants
        assert {c["name"] for c in claimants} == {"Chief Seller", "Mister Fraudster"}

    def test_court_disputes_contract(self, client, store):
        store.execute(
            "INSERT INTO court_disputes (case_number, state, property_address, parties,"
            " description, court_location, status, filed_date) VALUES"
            " ('LD/1234/2025', 'Lagos', '1 SYNTHETIC Close, Ikoyi',"
            " '[\"Chief Seller\", \"Mister Fraudster\"]', 'Ownership tussle',"
            " 'Lagos High Court', 'active', '2025-03-01T00:00:00')")
        resp = client.post("/api/v1/court-disputes",
                           json={"property_address": "1 SYNTHETIC Close, Ikoyi",
                                 "state": "Lagos", "parties": ["Chief Seller"]})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        disputes = body["disputes"]  # Go: response.Disputes []CourtDispute
        assert len(disputes) == 1
        d = disputes[0]
        # Go CourtDispute fields
        assert set(d) >= {"case_number", "filed_date", "status", "parties",
                          "description", "court_location"}
        assert d["case_number"] == "LD/1234/2025"
        assert d["parties"] == ["Chief Seller", "Mister Fraudster"]

    def test_registry_owner_and_history_contract(self, client):
        resp = client.post("/api/v1/registry/owner",
                           json={"certificate_number": "SYN-CERT-001", "state": "Lagos"})
        assert resp.status_code == 200, resp.text
        owner = resp.json()
        assert owner["name"] == "SYNTHETIC Landowner One"  # Go reads currentOwner["name"]

        resp = client.post("/api/v1/registry/history",
                           json={"property_address": "1 SYNTHETIC Close, Ikoyi",
                                 "state": "Lagos", "document_ref": "SYN-CERT-001"})
        assert resp.status_code == 200, resp.text
        history = resp.json()["ownership_history"]
        assert history and set(history[0]) >= {
            "owner", "start_date", "transfer_type", "document_ref", "verified"}

        missing = client.post("/api/v1/registry/owner",
                              json={"certificate_number": "NOPE", "state": "Lagos"})
        assert missing.status_code == 404  # journey records VERIFICATION_FAILED


class TestJourney37Contracts:
    def test_professional_search_contract(self, client):
        resp = client.post("/api/v1/professionals/search",
                           json={"professional_type": "lawyer", "state": "Lagos",
                                 "specialization": "Property Law", "min_rating": 4.0,
                                 "max_results": 10, "sort_by": "rating"})
        assert resp.status_code == 200, resp.text
        pros = resp.json()["professionals"]  # Go: response.Professionals []ProfessionalDetails
        assert len(pros) == 2
        pro = pros[0]
        # Go ProfessionalDetails fields (json tags)
        assert set(pro) >= {"id", "name", "type", "license", "license_verified",
                            "rating", "review_count", "specialization",
                            "years_experience", "state", "contact", "availability",
                            "consultation_fee", "languages", "profile_url"}
        # defensive re-filter in journey_37 requires exact match
        assert pro["type"] == "lawyer"
        assert pro["state"] == "Lagos"
        assert pro["rating"] >= 4.0
        assert set(pro["contact"]) >= {"phone", "email"}

    def test_availability_contract(self, client):
        tomorrow = (datetime.utcnow() + timedelta(days=1)).date().isoformat()
        resp = client.post("/api/v1/professionals/pro-syn-law-1/availability",
                           json={"professional_id": "pro-syn-law-1",
                                 "preferred_date": tomorrow,
                                 "preferred_time": "09:00",
                                 "consultation_type": "virtual",
                                 "date_range_days": 7})
        assert resp.status_code == 200, resp.text
        slots = resp.json()["slots"]  # Go: response.Slots []AvailabilitySlot
        assert slots
        assert set(slots[0]) >= {"date", "start_time", "end_time", "type", "available"}
        assert any(s["available"] and s["type"] == "virtual" and s["date"] == tomorrow
                   for s in slots)

    def test_booking_and_notification_contract(self, client):
        tomorrow = (datetime.utcnow() + timedelta(days=1)).date().isoformat()
        booking = {
            "user_id": "user-1", "professional_id": "pro-syn-law-1",
            "date": tomorrow, "start_time": "09:00", "end_time": "10:00",
            "consultation_type": "virtual", "issue_description": "double allocation",
            "urgency_level": "high",
        }
        resp = client.post("/api/v1/bookings", json=booking)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["booking_id"]  # journey fails if booking_id missing
        assert body["meeting_link"]  # virtual consultation

        # double-booking the same slot is rejected
        clash = client.post("/api/v1/bookings", json=booking)
        assert clash.status_code == 409

        # the booked slot no longer shows as available
        avail = client.post("/api/v1/professionals/pro-syn-law-1/availability",
                            json={"professional_id": "pro-syn-law-1",
                                  "preferred_date": tomorrow,
                                  "consultation_type": "virtual"})
        slot = [s for s in avail.json()["slots"]
                if s["date"] == tomorrow and s["start_time"] == "09:00"]
        assert slot and slot[0]["available"] is False

        notif = client.post("/api/v1/notifications/send",
                            json={"booking_id": body["booking_id"], "user_id": "user-1",
                                  "professional_id": "pro-syn-law-1"})
        assert notif.status_code == 200, notif.text
        # journey requires a boolean "sent"
        assert notif.json()["sent"] is True
        assert notif.json()["delivery_status"] == "queued"

        unknown = client.post("/api/v1/notifications/send",
                              json={"booking_id": "bk-nope", "user_id": "u",
                                    "professional_id": "p"})
        assert unknown.status_code == 404


class TestInspectionEndpoints:
    def test_report_then_decision(self, client, store):
        # drive a verification into site_inspection via the store directly
        import api.verification_workflow as vw

        wf = vw.get_workflow()
        wf.store.record_transition("v-api", None, VerificationStatus.RECEIVED)
        wf.store.record_transition("v-api", VerificationStatus.RECEIVED,
                                   VerificationStatus.DOCUMENT_ANALYSIS)
        wf.store.record_transition("v-api", VerificationStatus.DOCUMENT_ANALYSIS,
                                   VerificationStatus.REGISTRY_LOOKUP)
        wf.store.record_transition("v-api", VerificationStatus.REGISTRY_LOOKUP,
                                   VerificationStatus.SITE_INSPECTION)
        resp = client.post("/api/v1/inspections/v-api/report",
                           json={"inspector": "insp-7", "findings": "beacons match survey"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "inspection_report"

        resp = client.post("/api/v1/inspections/v-api/decision",
                           json={"decision": "completed", "reason": "all clear"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "completed"

    def test_illegal_decision_without_report_409(self, client):
        import api.verification_workflow as vw

        wf = vw.get_workflow()
        wf.store.record_transition("v-api2", None, VerificationStatus.RECEIVED)
        resp = client.post("/api/v1/inspections/v-api2/decision",
                           json={"decision": "completed"})
        assert resp.status_code == 409

        missing = client.post("/api/v1/inspections/v-nope/report",
                              json={"inspector": "x", "findings": "y"})
        assert missing.status_code == 404
