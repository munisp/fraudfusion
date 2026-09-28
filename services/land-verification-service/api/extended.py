"""Journey-facing endpoints for the land-verification-service.

These are the exact paths the Temporal orchestrator calls (see
services/go/temporal-orchestrator/workflows/journey_34_double_allocation.go
and journey_37_professional_consultation.go):

  POST /api/v1/process-document                         (journey 34 step 1)
  POST /api/v1/registry/history                         (journey 34 step 2)
  POST /api/v1/detect-claimants                         (journey 34 step 3)
  POST /api/v1/court-disputes                           (journey 34 step 4)
  POST /api/v1/registry/owner                           (journey 34 step 5)
  POST /api/v1/professionals/search                     (journeys 34/37)
  POST /api/v1/professionals/{id}/availability          (journey 37 step 3)
  POST /api/v1/bookings                                 (journey 37 step 4; BOOKING_SERVICE_URL)
  POST /api/v1/notifications/send                       (journey 37 step 5; NOTIFICATION_SERVICE_URL)

Plus the site-inspection state machine completion:
  POST /api/v1/inspections/{verification_id}/report     (site_inspection -> inspection_report)
  POST /api/v1/inspections/{verification_id}/decision   (inspection_report -> completed|rejected)

These are internal service-to-service endpoints (the Temporal worker calls
them over the cluster network without user bearer tokens, like every other
activity target). All logic is DB-backed; nothing is fabricated.
"""

from __future__ import annotations

import base64
import binascii
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.data_store import LandDataStore, get_land_store
from api.ocr import get_ocr_adapter
from api.registry_adapters import get_lands_adapter
from api.verification_workflow import StateTransitionError, get_workflow
from models.schemas import VerificationStatus

logger = logging.getLogger(__name__)

router = APIRouter()

# Canonical state names as used by the temporal journeys (their booking
# validation accepts exactly these capitalizations).
CANONICAL_STATES = {
    "lagos": "Lagos", "abuja": "Abuja", "fct": "Abuja", "rivers": "Rivers",
    "ogun": "Ogun", "kano": "Kano",
}

DOCUMENT_MARKERS = {
    "PLOT:": "plot_number",
    "PLAN:": "survey_plan_number",
    "LGA:": "lga",
    "CAC:": "cac_number",
    "CERT:": "certificate_number",
    "ASSIGNOR:": "seller_name",
    "ASSIGNEE:": "assignee",
    "ADDRESS:": "property_address",
}


def _canonical_state(raw: str) -> str:
    state = CANONICAL_STATES.get((raw or "").strip().lower())
    if state is None:
        raise HTTPException(status_code=400, detail=f"unsupported state: {raw!r}")
    return state


def _extract_fields(text: str) -> dict[str, Any]:
    extracted: dict[str, Any] = {}
    # Marker files use one field per line; OCR text may be one long line, so
    # also split on marker boundaries.
    normalized = text
    for marker in DOCUMENT_MARKERS:
        normalized = normalized.replace(" " + marker, "\n" + marker)
    for marker, key in DOCUMENT_MARKERS.items():
        for line in normalized.splitlines():
            if line.startswith(marker):
                extracted[key] = line[len(marker):].strip()
    return extracted


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ProcessDocumentInput(BaseModel):
    document_file: str  # base64 (journey 34 contract)


class RegistryQueryInput(BaseModel):
    property_address: Optional[str] = None
    state: str
    document_ref: Optional[str] = None
    certificate_number: Optional[str] = None


class ClaimantsInput(BaseModel):
    property_address: Optional[str] = None
    state: str
    certificate_number: Optional[str] = None


class CourtDisputesInput(BaseModel):
    property_address: Optional[str] = None
    state: str
    parties: list[str] = []


class ProfessionalSearchInput(BaseModel):
    professional_type: str
    state: str
    specialization: Optional[str] = None
    min_rating: float = 0.0
    max_results: int = 10
    sort_by: str = "rating"


class AvailabilityInput(BaseModel):
    professional_id: Optional[str] = None
    preferred_date: Optional[str] = None
    preferred_time: Optional[str] = None
    consultation_type: Optional[str] = None
    date_range_days: int = 7


class BookingInput(BaseModel):
    user_id: str
    professional_id: str
    date: str
    start_time: str
    end_time: str
    consultation_type: str
    issue_description: Optional[str] = None
    urgency_level: Optional[str] = None


class NotificationInput(BaseModel):
    booking_id: str
    user_id: str
    professional_id: str
    appointment: Optional[dict[str, Any]] = None
    professional: Optional[dict[str, Any]] = None


class InspectionReportInput(BaseModel):
    inspector: str
    findings: str
    parcel_occupied: Optional[bool] = None
    boundary_marks_present: Optional[bool] = None
    photos: list[str] = []


class InspectionDecisionInput(BaseModel):
    decision: str  # completed | rejected
    reason: str = ""
    actor: str = "inspector"


# ---------------------------------------------------------------------------
# Serialization helpers (Go contract shapes)
# ---------------------------------------------------------------------------

def _iso(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace(" ", "T")


def _claimant_view(row: dict, conflicting: bool) -> dict[str, Any]:
    return {
        "name": row["claimant_name"],
        "claim_date": _iso(row["claim_date"]),
        "document_type": row.get("document_type") or "",
        "document_ref": row.get("document_ref") or "",
        "verified": bool(row.get("verified")),
        "conflicting": conflicting or bool(row.get("conflicting")),
    }


def _dispute_view(row: dict) -> dict[str, Any]:
    return {
        "case_number": row["case_number"],
        "filed_date": _iso(row["filed_date"]),
        "status": row["status"],
        "parties": LandDataStore.as_list(row.get("parties")),
        "description": row.get("description") or "",
        "court_location": row.get("court_location") or "",
    }


def _professional_view(row: dict) -> dict[str, Any]:
    contact = LandDataStore.as_dict(row.get("contact"))
    return {
        "id": row["id"],
        "name": row["name"],
        "type": row["professional_type"],
        "license": row.get("license_number") or "",
        "license_verified": bool(row.get("license_verified")),
        "rating": float(row.get("rating") or 0),
        "review_count": int(row.get("review_count") or 0),
        "specialization": row.get("specialization") or "",
        "years_experience": int(row.get("years_experience") or 0),
        "state": _canonical_state(row["state"]),
        "contact": {
            "phone": contact.get("phone", ""),
            "email": contact.get("email", ""),
            "whatsapp": contact.get("whatsapp", ""),
            "office": contact.get("office", ""),
            "website": contact.get("website", ""),
        },
        "availability": [],
        "consultation_fee": float(row.get("consultation_fee") or 0),
        "languages": LandDataStore.as_list(row.get("languages")),
        "success_rate": float(row["success_rate"]) if row.get("success_rate") is not None else 0.0,
        "cases_handled": int(row["cases_handled"]) if row.get("cases_handled") is not None else 0,
        "certifications": LandDataStore.as_list(row.get("certifications")),
        "profile_url": row.get("profile_url") or "",
    }


# ---------------------------------------------------------------------------
# Journey 34 endpoints
# ---------------------------------------------------------------------------

@router.post("/api/v1/process-document")
def process_document(payload: ProcessDocumentInput) -> dict[str, Any]:
    """Extract land details from a base64 document. Text marker files are
    parsed directly; binary images go through the configured OCR adapter.
    Never fabricates fields: whatever is extracted is what was read."""
    try:
        data = base64.b64decode(payload.document_file, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="document_file is not valid base64") from exc
    if not data.strip():
        raise HTTPException(status_code=422, detail="document_file decodes to empty content")

    text = data.decode("utf-8", errors="ignore")
    ocr_status = "not_required"
    if not text.strip():
        adapter = get_ocr_adapter()
        if adapter is None:
            raise HTTPException(
                status_code=503,
                detail="ocr: unavailable (no OCR_SERVICE_URL and no tesseract binary); "
                       "cannot extract from a binary document",
            )
        result = adapter.extract_text(data)
        ocr_status = result["status"]
        if result["status"] != "ok":
            raise HTTPException(status_code=503, detail=f"ocr failed: {result.get('reason')}")
        text = result["text"]

    extracted = _extract_fields(text)
    if not extracted:
        raise HTTPException(status_code=422,
                            detail="no extractable land fields found in document")
    extracted["document_sha256"] = __import__("hashlib").sha256(data).hexdigest()
    extracted["ocr_status"] = ocr_status
    return extracted


@router.post("/api/v1/registry/history")
def registry_history(payload: RegistryQueryInput,
                     store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    """Ownership history from the lands registry (HTTP when the state endpoint
    is configured; otherwise the provenance-tracked file-import table)."""
    state = _canonical_state(payload.state)
    adapter = get_lands_adapter(state, store)
    result = adapter.history(
        state=state,
        certificate_number=payload.certificate_number or payload.document_ref,
        property_address=payload.property_address,
    )
    if result.get("status") == "unavailable":
        raise HTTPException(status_code=503,
                            detail=result.get("reason", "lands registry unavailable"))
    return {"ownership_history": result.get("ownership_history", []),
            "source": result.get("source")}


@router.post("/api/v1/registry/owner")
def registry_owner(payload: RegistryQueryInput,
                   store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    state = _canonical_state(payload.state)
    adapter = get_lands_adapter(state, store)
    result = adapter.owner(
        state=state,
        certificate_number=payload.certificate_number or payload.document_ref,
        property_address=payload.property_address,
    )
    if result.get("status") == "unavailable":
        raise HTTPException(status_code=503,
                            detail=result.get("reason", "lands registry unavailable"))
    if result.get("status") != "found":
        raise HTTPException(status_code=404,
                            detail=result.get("reason", "no registered owner found"))
    return result


@router.post("/api/v1/detect-claimants")
def detect_claimants(payload: ClaimantsInput,
                     store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    """Claimant graph over parcels: every recorded claimant for the parcel
    (matched by certificate_number and/or address). Multiple distinct
    claimants are flagged conflicting."""
    state = _canonical_state(payload.state)
    rows: list[dict[str, Any]] = []
    if payload.certificate_number:
        rows = store.query(
            "SELECT * FROM parcel_claimants WHERE tenant_id = 'default'"
            " AND lower(state) = lower(:s) AND certificate_number = :c"
            " ORDER BY claim_date",
            {"s": state, "c": payload.certificate_number},
        )
    if not rows and payload.property_address:
        rows = store.query(
            "SELECT * FROM parcel_claimants WHERE tenant_id = 'default'"
            " AND lower(state) = lower(:s) AND lower(property_address) = lower(:a)"
            " ORDER BY claim_date",
            {"s": state, "a": payload.property_address},
        )
    distinct = {r["claimant_name"].strip().lower() for r in rows}
    conflicting = len(distinct) > 1
    return {
        "claimants": [_claimant_view(r, conflicting) for r in rows],
        "claimant_count": len(rows),
        "distinct_claimants": len(distinct),
    }


@router.post("/api/v1/court-disputes")
def court_disputes(payload: CourtDisputesInput,
                   store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    """Court dispute records for the parcel: matched by address, or by party
    overlap with the supplied claimant names."""
    state = _canonical_state(payload.state)
    rows: list[dict[str, Any]] = []
    seen: set[Any] = set()

    def _add(records):
        for r in records:
            if r["id"] not in seen:
                seen.add(r["id"])
                rows.append(r)

    if payload.property_address:
        _add(store.query(
            "SELECT * FROM court_disputes WHERE tenant_id = 'default'"
            " AND lower(state) = lower(:s) AND lower(property_address) = lower(:a)",
            {"s": state, "a": payload.property_address},
        ))
    for party in payload.parties or []:
        # parties stored as JSON array text (SQLite) or TEXT[] (Postgres);
        # a case-insensitive substring match on the serialized parties keeps
        # both dialects honest without dialect-specific SQL.
        _add([
            r for r in store.query(
                "SELECT * FROM court_disputes WHERE tenant_id = 'default'"
                " AND lower(state) = lower(:s)",
                {"s": state},
            )
            if party.strip().lower()
            in [p.strip().lower() for p in LandDataStore.as_list(r.get("parties"))]
        ])
    return {"disputes": [_dispute_view(r) for r in rows],
            "court_disputes": [_dispute_view(r) for r in rows],
            "dispute_count": len(rows)}


# ---------------------------------------------------------------------------
# Journey 37 endpoints (professional directory / bookings / notifications)
# ---------------------------------------------------------------------------

_SORT_COLUMNS = {"rating": "rating", "experience": "years_experience",
                 "success_rate": "success_rate"}


@router.post("/api/v1/professionals/search")
def search_professionals(payload: ProfessionalSearchInput,
                         store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    state = _canonical_state(payload.state)
    if payload.professional_type not in ("lawyer", "surveyor", "estate_agent"):
        raise HTTPException(status_code=400,
                            detail="professional_type must be lawyer|surveyor|estate_agent")
    sort_col = _SORT_COLUMNS.get(payload.sort_by, "rating")
    rows = store.query(
        f"SELECT * FROM professional_registry WHERE tenant_id = 'default'"
        f" AND professional_type = :t AND lower(state) = lower(:s) AND rating >= :r"
        + (" AND lower(specialization) = lower(:spec)" if payload.specialization else "")
        + f" ORDER BY {sort_col} DESC LIMIT :lim",
        {"t": payload.professional_type, "s": state, "r": payload.min_rating,
         "spec": payload.specialization, "lim": max(1, min(payload.max_results, 50))},
    )
    return {"professionals": [_professional_view(r) for r in rows],
            "count": len(rows)}


@router.post("/api/v1/professionals/{professional_id}/availability")
def professional_availability(professional_id: str, payload: AvailabilityInput,
                              store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    pro = store.query_one(
        "SELECT id FROM professional_registry WHERE id = :id", {"id": professional_id})
    if not pro:
        raise HTTPException(status_code=404, detail="professional not found")
    start = payload.preferred_date or datetime.utcnow().date().isoformat()
    try:
        start_date = datetime.strptime(start, "%Y-%m-%d").date()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="preferred_date must be YYYY-MM-DD") from exc
    days = max(1, min(payload.date_range_days or 7, 31))
    end_date = (start_date + timedelta(days=days)).isoformat()
    rows = store.query(
        "SELECT slot_date, start_time, end_time, slot_type, is_available"
        " FROM professional_availability WHERE professional_id = :p"
        " AND slot_date >= :d0 AND slot_date <= :d1 ORDER BY slot_date, start_time",
        {"p": professional_id, "d0": start_date.isoformat(), "d1": end_date},
    )
    booked = {
        (b["booking_date"], b["start_time"])
        for b in store.query(
            "SELECT booking_date, start_time FROM professional_bookings"
            " WHERE professional_id = :p AND status = 'confirmed'"
            " AND booking_date >= :d0 AND booking_date <= :d1",
            {"p": professional_id, "d0": start_date.isoformat(), "d1": end_date},
        )
    }
    slots = [
        {
            "date": str(r["slot_date"]),
            "start_time": r["start_time"],
            "end_time": r["end_time"],
            "type": r["slot_type"],
            "available": bool(r["is_available"])
            and (str(r["slot_date"]), r["start_time"]) not in booked
            and (not payload.consultation_type or True),
        }
        for r in rows
        if not payload.consultation_type or r["slot_type"] == payload.consultation_type
    ]
    return {"slots": slots, "professional_id": professional_id}


@router.post("/api/v1/bookings", status_code=201)
def create_booking(payload: BookingInput,
                   store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    """Create a consultation booking. Double-booking a confirmed slot is
    rejected 409 (enforced by the professional_bookings_slot_uidx index too)."""
    pro = store.query_one(
        "SELECT * FROM professional_registry WHERE id = :id", {"id": payload.professional_id})
    if not pro:
        raise HTTPException(status_code=404, detail="professional not found")
    if payload.consultation_type not in ("virtual", "in_person", "phone"):
        raise HTTPException(status_code=400, detail="invalid consultation_type")
    try:
        datetime.strptime(payload.date, "%Y-%m-%d")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="date must be YYYY-MM-DD") from exc

    clash = store.query_one(
        "SELECT id FROM professional_bookings WHERE professional_id = :p"
        " AND booking_date = :d AND start_time = :t AND status = 'confirmed'",
        {"p": payload.professional_id, "d": payload.date, "t": payload.start_time},
    )
    if clash:
        raise HTTPException(status_code=409, detail="slot already booked")

    booking_id = "bk-" + uuid.uuid4().hex[:16]
    contact = LandDataStore.as_dict(pro.get("contact"))
    meeting_link = location = instructions = None
    if payload.consultation_type == "virtual":
        meeting_link = f"https://meet.fraudfusion.io/{booking_id}"
        instructions = "Join the video call at the scheduled time."
    elif payload.consultation_type == "in_person":
        location = contact.get("office", "")
        instructions = "Bring a valid ID and all property documents."
    else:
        instructions = "The professional will call the phone number on your profile."

    try:
        store.execute(
            "INSERT INTO professional_bookings (id, user_id, professional_id, booking_date,"
            " start_time, end_time, consultation_type, issue_description, urgency_level, status,"
            " meeting_link, location, instructions) VALUES (:id, :u, :p, :d, :st, :et, :ct, :issue,"
            " :urg, 'confirmed', :ml, :loc, :ins)",
            {"id": booking_id, "u": payload.user_id, "p": payload.professional_id,
             "d": payload.date, "st": payload.start_time, "et": payload.end_time,
             "ct": payload.consultation_type, "issue": payload.issue_description,
             "urg": payload.urgency_level, "ml": meeting_link, "loc": location,
             "ins": instructions},
        )
    except Exception as exc:  # unique index race => honest 409
        if "UNIQUE" in str(exc).upper() or "unique" in str(exc):
            raise HTTPException(status_code=409, detail="slot already booked") from exc
        raise
    # Mark the availability slot taken (kept for audit; availability endpoint
    # also subtracts confirmed bookings).
    store.execute(
        "UPDATE professional_availability SET is_available = 0 WHERE professional_id = :p"
        " AND slot_date = :d AND start_time = :t" if not store._is_pg else
        "UPDATE professional_availability SET is_available = FALSE WHERE professional_id = :p"
        " AND slot_date = :d AND start_time = :t",
        {"p": payload.professional_id, "d": payload.date, "t": payload.start_time},
    )
    logger.info("booking created: %s user=%s pro=%s %s %s",
                booking_id, payload.user_id, payload.professional_id, payload.date,
                payload.start_time)
    return {
        "booking_id": booking_id,
        "status": "confirmed",
        "location": location or "",
        "meeting_link": meeting_link or "",
        "instructions": instructions or "",
        "cancellation_link": f"https://fraudfusion.io/bookings/{booking_id}/cancel",
    }


@router.post("/api/v1/notifications/send")
def send_notification(payload: NotificationInput,
                      store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    """Record a booking notification in the outbox (notification_requests).
    `sent` means the notification was accepted for delivery; the honest
    per-channel state is `delivery_status` (queued until a delivery worker
    picks it up)."""
    booking = store.query_one(
        "SELECT id FROM professional_bookings WHERE id = :id", {"id": payload.booking_id})
    if not booking:
        raise HTTPException(status_code=404, detail="booking not found")
    import json as _json

    cur = store.execute(
        "INSERT INTO notification_requests (booking_id, user_id, professional_id, payload,"
        " delivery_status) VALUES (:b, :u, :p, :pl, 'queued')",
        {"b": payload.booking_id, "u": payload.user_id, "p": payload.professional_id,
         "pl": _json.dumps({"appointment": payload.appointment or {},
                            "professional": payload.professional or {}})},
    )
    row = store.query_one(
        "SELECT id FROM notification_requests WHERE booking_id = :b ORDER BY id DESC LIMIT 1",
        {"b": payload.booking_id},
    )
    return {
        "sent": True,
        "delivery_status": "queued",
        "notification_id": row["id"] if row else None,
        "booking_id": payload.booking_id,
        "channels": ["email", "sms"],
    }


# ---------------------------------------------------------------------------
# Site-inspection state machine completion
# ---------------------------------------------------------------------------

@router.post("/api/v1/inspections/{verification_id}/report")
def submit_inspection_report(verification_id: str, payload: InspectionReportInput) -> dict[str, Any]:
    """File the site-inspection report: site_inspection -> inspection_report."""
    workflow = get_workflow()
    current = workflow.get_status(verification_id)
    if current is None:
        raise HTTPException(status_code=404, detail="verification not found")
    report = {
        "inspector": payload.inspector,
        "findings": payload.findings,
        "parcel_occupied": payload.parcel_occupied,
        "boundary_marks_present": payload.boundary_marks_present,
        "photos": payload.photos,
        "filed_at": datetime.utcnow().isoformat(),
    }
    try:
        workflow.record_inspection_report(verification_id, report, actor=payload.inspector)
    except StateTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"verification_id": verification_id, "status": VerificationStatus.INSPECTION_REPORT.value,
            "report": report}


@router.post("/api/v1/inspections/{verification_id}/decision")
def inspection_decision(verification_id: str, payload: InspectionDecisionInput) -> dict[str, Any]:
    """Decide after an inspection report: inspection_report -> completed|rejected."""
    workflow = get_workflow()
    current = workflow.get_status(verification_id)
    if current is None:
        raise HTTPException(status_code=404, detail="verification not found")
    target = {
        "completed": VerificationStatus.COMPLETED,
        "rejected": VerificationStatus.REJECTED,
    }.get(payload.decision)
    if target is None:
        raise HTTPException(status_code=400, detail="decision must be completed|rejected")
    try:
        workflow.complete_inspection(verification_id, target, payload.reason, actor=payload.actor)
    except StateTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"verification_id": verification_id, "status": target.value,
            "reason": payload.reason}
