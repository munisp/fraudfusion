"""Round 11 land due-diligence router.

Implements the buildable recommendations from the Channels TV land-fraud
interview (see docs/land-fraud-video-recommendations.md):

  * Parcel registration with first-wins conflict detection — the same parcel
    reference, certificate number, or survey-plan hash can only be registered
    once per tenant; a second registration is a recorded conflict (the
    "multiple sales of the same plot" pattern, caught at registration time
    rather than in court years later).
  * Family/consent-party tracking — every party whose consent is required
    (family members, community heads) must confirm before a parcel goes
    'clear' ("I bought from two families instead of seven").
  * Dispute cases with a 90-day SLA clock — mirrors the recommended
    dedicated land courts ("I know that I will get results in 90 days");
    overdue open cases are flagged sla_breached.
  * Revocation/compensation workflow — Land Use Act 1978: an acquisition is
    lawful only when compensation has been paid; the workflow enforces
    notice -> documents_collected -> compensated ordering.
  * Deed-of-assignment template conformance (api.deed_conformance).
  * Hash-chained evidence pack export per parcel (api.evidence).
  * Composite pre-purchase due-diligence verdict — registry owner cross-check
    (CTC equivalent), claimant conflicts, consent completeness, open
    disputes, revocation status -> clear | caution | high_risk | unavailable.

Endpoints follow the extended_router convention (service-to-service, DB-backed).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api import evidence, events
from api.data_store import LandDataStore, get_land_store
from api.deed_conformance import check_deed_conformance
from api.registry_adapters import get_lands_adapter

router = APIRouter()

DISPUTE_SLA_DAYS = int(os.getenv("LAND_DISPUTE_SLA_DAYS", "90"))


def _now() -> str:
    return datetime.utcnow().isoformat()


def _canonical_state(raw: str) -> str:
    s = (raw or "").strip().lower()
    if not s:
        raise HTTPException(status_code=422, detail="state is required")
    return s


def _parse_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return datetime.utcnow()


# ---------------------------------------------------------------------------
# Parcels — first-wins registration with conflict detection
# ---------------------------------------------------------------------------

class ParcelRegisterInput(BaseModel):
    parcel_ref: str = Field(min_length=1, max_length=128)
    state: str = Field(min_length=1)
    lga: Optional[str] = None
    property_address: Optional[str] = None
    certificate_number: Optional[str] = None
    survey_plan_hash: Optional[str] = None
    registered_by: Optional[str] = None
    consent_required: list[str] = []


class ConsentInput(BaseModel):
    party_name: str = Field(min_length=1, max_length=256)
    confirmed: bool = True
    method: Optional[str] = None  # e.g. "signature", "thumbprint", "video-attestation"


def _parcel_view(store: LandDataStore, row: dict[str, Any]) -> dict[str, Any]:
    consents = store.query(
        "SELECT party_name, confirmed, method, confirmed_at FROM parcel_consents"
        " WHERE tenant_id = :t AND parcel_ref = :p ORDER BY party_name",
        {"t": row["tenant_id"], "p": row["parcel_ref"]},
    )
    required = LandDataStore.as_list(row.get("consent_required"))
    confirmed = {c["party_name"].strip().lower() for c in consents if c["confirmed"]}
    outstanding = [p for p in required if p.strip().lower() not in confirmed]
    open_disputes = store.query(
        "SELECT id FROM dispute_cases WHERE tenant_id = :t AND parcel_ref = :p AND status = 'open'",
        {"t": row["tenant_id"], "p": row["parcel_ref"]},
    )
    return {
        "parcel_ref": row["parcel_ref"],
        "state": row["state"],
        "lga": row.get("lga"),
        "property_address": row.get("property_address"),
        "certificate_number": row.get("certificate_number"),
        "survey_plan_hash": row.get("survey_plan_hash"),
        "status": row["status"],
        "consent_required": required,
        "consents": consents,
        "consent_outstanding": outstanding,
        "consent_complete": not outstanding,
        "open_disputes": len(open_disputes),
        "created_at": row["created_at"],
    }


def _get_parcel(store: LandDataStore, parcel_ref: str) -> dict[str, Any]:
    row = store.query_one(
        "SELECT * FROM parcels WHERE tenant_id = 'default' AND parcel_ref = :p",
        {"p": parcel_ref},
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"parcel '{parcel_ref}' not registered")
    return row


@router.post("/api/v1/parcels", status_code=201)
def register_parcel(payload: ParcelRegisterInput,
                    store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    state = _canonical_state(payload.state)
    ref = payload.parcel_ref.strip()

    existing = store.query_one(
        "SELECT * FROM parcels WHERE tenant_id = 'default' AND parcel_ref = :p", {"p": ref})
    if existing:
        # First-wins: the original registration stands; the attempted
        # duplicate is recorded as a conflict (multiple-sale detection).
        store.execute(
            "INSERT INTO parcel_conflicts (tenant_id, parcel_ref, conflict_key, existing_ref, reason)"
            " VALUES ('default', :p, :k, :e, :r)",
            {"p": ref, "k": f"parcel_ref:{ref}", "e": existing["parcel_ref"],
             "r": "duplicate parcel_ref registration attempt"},
        )
        evidence.append_event(store, ref, "conflict_detected",
                              {"conflict_key": f"parcel_ref:{ref}", "reason": "duplicate_ref"})
        events.emit_event("parcel.conflict.detected", "default",
                          {"parcel_ref": ref, "conflict_key": f"parcel_ref:{ref}",
                           "existing_registered_at": existing["created_at"]})
        raise HTTPException(
            status_code=409,
            detail={"error": "parcel_conflict", "conflict_key": f"parcel_ref:{ref}",
                    "existing_ref": existing["parcel_ref"],
                    "registered_at": existing["created_at"]},
        )

    # Same certificate number or survey-plan hash under a different ref is
    # also a conflict (re-selling the same titled parcel under a new label).
    conflicts: list[dict[str, str]] = []
    for key, value in (("certificate_number", payload.certificate_number),
                       ("survey_plan_hash", payload.survey_plan_hash)):
        if not value:
            continue
        dup = store.query_one(
            f"SELECT parcel_ref FROM parcels WHERE tenant_id = 'default'"
            f" AND {key} = :v AND parcel_ref != :p",
            {"v": value, "p": ref},
        )
        if dup:
            conflicts.append({"conflict_key": f"{key}:{value}",
                              "existing_ref": dup["parcel_ref"],
                              "reason": f"{key} already registered to another parcel"})
            store.execute(
                "INSERT INTO parcel_conflicts (tenant_id, parcel_ref, conflict_key, existing_ref, reason)"
                " VALUES ('default', :p, :k, :e, :r)",
                {"p": ref, "k": f"{key}:{value}", "e": dup["parcel_ref"],
                 "r": f"{key} already registered to another parcel"},
            )

    status = "disputed" if conflicts else "provisional"
    store.execute(
        "INSERT INTO parcels (tenant_id, parcel_ref, state, lga, property_address,"
        " certificate_number, survey_plan_hash, registered_by, status, consent_required)"
        " VALUES ('default', :r, :s, :l, :a, :c, :h, :b, :st, :cr)",
        {"r": ref, "s": state, "l": payload.lga, "a": payload.property_address,
         "c": payload.certificate_number, "h": payload.survey_plan_hash,
         "b": payload.registered_by, "st": status,
         "cr": __import__("json").dumps([p.strip() for p in payload.consent_required if p.strip()])},
    )
    evidence.append_event(store, ref, "parcel_registered",
                          {"state": state, "certificate_number": payload.certificate_number,
                           "conflicts": conflicts})
    events.emit_event("parcel.registered", "default",
                      {"parcel_ref": ref, "state": state, "status": status})
    for c in conflicts:
        evidence.append_event(store, ref, "conflict_detected", c)
        events.emit_event("parcel.conflict.detected", "default",
                          {"parcel_ref": ref, "conflict_key": c["conflict_key"],
                           "existing_ref": c["existing_ref"]})
    row = _get_parcel(store, ref)
    view = _parcel_view(store, row)
    view["conflicts"] = conflicts
    return view


@router.get("/api/v1/parcels/{parcel_ref}")
def get_parcel(parcel_ref: str, store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    return _parcel_view(store, _get_parcel(store, parcel_ref))


@router.post("/api/v1/parcels/{parcel_ref}/consents")
def record_consent(parcel_ref: str, payload: ConsentInput,
                   store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    row = _get_parcel(store, parcel_ref)
    now = _now()
    store.execute(
        "INSERT INTO parcel_consents (tenant_id, parcel_ref, party_name, confirmed, method, confirmed_at)"
        " VALUES ('default', :p, :n, :c, :m, :t)"
        " ON CONFLICT (tenant_id, parcel_ref, party_name)"
        " DO UPDATE SET confirmed = :c, method = :m, confirmed_at = :t",
        {"p": parcel_ref, "n": payload.party_name.strip(), "c": payload.confirmed,
         "m": payload.method, "t": now if payload.confirmed else None},
    )
    evidence.append_event(store, parcel_ref, "consent_recorded",
                          {"party": payload.party_name.strip(), "confirmed": payload.confirmed,
                           "method": payload.method})

    view = _parcel_view(store, row)
    # Parcel only goes 'clear' when every required consent party confirmed
    # and there are no open conflicts — mirrors the video: buying from 2 of
    # 7 families is NOT consent.
    if view["consent_complete"] and row["status"] == "provisional":
        conflicts = store.query(
            "SELECT id FROM parcel_conflicts WHERE tenant_id = 'default' AND parcel_ref = :p",
            {"p": parcel_ref})
        if not conflicts:
            store.execute(
                "UPDATE parcels SET status = 'clear', updated_at = :t"
                " WHERE tenant_id = 'default' AND parcel_ref = :p",
                {"t": now, "p": parcel_ref})
            evidence.append_event(store, parcel_ref, "parcel_cleared", {})
            events.emit_event("parcel.cleared", "default", {"parcel_ref": parcel_ref})
            view["status"] = "clear"
    return view


# ---------------------------------------------------------------------------
# Deed template conformance
# ---------------------------------------------------------------------------

class DeedConformanceInput(BaseModel):
    deed_text: str = Field(min_length=1)
    consent_parties: list[str] = []
    parcel_ref: Optional[str] = None


@router.post("/api/v1/deeds/conformance")
def deed_conformance(payload: DeedConformanceInput,
                     store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    result = check_deed_conformance(payload.deed_text, payload.consent_parties)
    result["template"] = "fraudfusion-standard-deed-of-assignment/v1"
    if payload.parcel_ref:
        _get_parcel(store, payload.parcel_ref)
        evidence.append_event(
            store, payload.parcel_ref, "deed_conformance_checked",
            {"conformant": result["conformant"],
             "missing": [m["clause"] for m in result["missing"]],
             "consent_parties_missing": result["consent_parties_missing"]})
    return result


# ---------------------------------------------------------------------------
# Dispute cases — 90-day SLA clock (dedicated-land-courts recommendation)
# ---------------------------------------------------------------------------

class DisputeOpenInput(BaseModel):
    case_number: Optional[str] = None
    state: Optional[str] = None
    description: Optional[str] = None
    court_location: Optional[str] = None
    filed_at: Optional[str] = None  # ISO; defaults to now
    sla_days: Optional[int] = Field(default=None, ge=1, le=3650)


class DisputeResolveInput(BaseModel):
    resolution: str = Field(min_length=1, max_length=512)
    status: str = Field(default="resolved", pattern="^(resolved|withdrawn)$")


def _dispute_view(row: dict[str, Any]) -> dict[str, Any]:
    filed = _parse_dt(row["filed_at"])
    sla_days = int(row.get("sla_days") or DISPUTE_SLA_DAYS)
    deadline = filed + timedelta(days=sla_days)
    breached = row["status"] == "open" and datetime.utcnow() > deadline
    return {
        "dispute_id": row["id"],
        "parcel_ref": row["parcel_ref"],
        "case_number": row.get("case_number"),
        "status": row["status"],
        "filed_at": row["filed_at"],
        "resolved_at": row.get("resolved_at"),
        "resolution": row.get("resolution"),
        "sla_days": sla_days,
        "sla_deadline": deadline.isoformat(),
        "sla_breached": breached,
        "days_open": (datetime.utcnow() - filed).days if row["status"] == "open" else None,
    }


@router.post("/api/v1/parcels/{parcel_ref}/disputes", status_code=201)
def open_dispute(parcel_ref: str, payload: DisputeOpenInput,
                 store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    parcel = _get_parcel(store, parcel_ref)
    dispute_id = str(uuid.uuid4())
    filed_at = payload.filed_at or _now()
    sla = payload.sla_days or DISPUTE_SLA_DAYS
    store.execute(
        "INSERT INTO dispute_cases (id, tenant_id, parcel_ref, case_number, state, description,"
        " court_location, status, filed_at, sla_days)"
        " VALUES (:i, 'default', :p, :c, :s, :d, :l, 'open', :f, :sla)",
        {"i": dispute_id, "p": parcel_ref, "c": payload.case_number, "s": payload.state,
         "d": payload.description, "l": payload.court_location, "f": filed_at, "sla": sla},
    )
    if parcel["status"] in ("provisional", "clear"):
        store.execute(
            "UPDATE parcels SET status = 'disputed', updated_at = :t"
            " WHERE tenant_id = 'default' AND parcel_ref = :p",
            {"t": _now(), "p": parcel_ref})
    evidence.append_event(store, parcel_ref, "dispute_opened",
                          {"dispute_id": dispute_id, "case_number": payload.case_number,
                           "sla_days": sla})
    events.emit_event("dispute.opened", "default",
                      {"parcel_ref": parcel_ref, "dispute_id": dispute_id,
                       "sla_days": sla})
    row = store.query_one("SELECT * FROM dispute_cases WHERE id = :i", {"i": dispute_id})
    return _dispute_view(row)


@router.post("/api/v1/disputes/{dispute_id}/resolve")
def resolve_dispute(dispute_id: str, payload: DisputeResolveInput,
                    store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    row = store.query_one(
        "SELECT * FROM dispute_cases WHERE tenant_id = 'default' AND id = :i", {"i": dispute_id})
    if not row:
        raise HTTPException(status_code=404, detail=f"dispute '{dispute_id}' not found")
    if row["status"] != "open":
        raise HTTPException(status_code=409, detail=f"dispute already {row['status']}")
    now = _now()
    store.execute(
        "UPDATE dispute_cases SET status = :s, resolution = :r, resolved_at = :t, updated_at = :t"
        " WHERE tenant_id = 'default' AND id = :i",
        {"s": payload.status, "r": payload.resolution, "t": now, "i": dispute_id},
    )
    parcel_ref = row["parcel_ref"]
    evidence.append_event(store, parcel_ref, "dispute_resolved",
                          {"dispute_id": dispute_id, "resolution": payload.resolution,
                           "status": payload.status})
    events.emit_event("dispute.resolved", "default",
                      {"parcel_ref": parcel_ref, "dispute_id": dispute_id,
                       "status": payload.status})
    remaining = store.query(
        "SELECT id FROM dispute_cases WHERE tenant_id = 'default' AND parcel_ref = :p AND status = 'open'",
        {"p": parcel_ref})
    if not remaining:
        parcel = _get_parcel(store, parcel_ref)
        new_status = "clear" if _parcel_view(store, parcel)["consent_complete"] else "provisional"
        store.execute(
            "UPDATE parcels SET status = :s, updated_at = :t"
            " WHERE tenant_id = 'default' AND parcel_ref = :p",
            {"s": new_status, "t": now, "p": parcel_ref})
    updated = store.query_one("SELECT * FROM dispute_cases WHERE id = :i", {"i": dispute_id})
    return _dispute_view(updated)


@router.get("/api/v1/parcels/{parcel_ref}/disputes")
def list_disputes(parcel_ref: str, store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    _get_parcel(store, parcel_ref)
    rows = store.query(
        "SELECT * FROM dispute_cases WHERE tenant_id = 'default' AND parcel_ref = :p"
        " ORDER BY filed_at", {"p": parcel_ref})
    views = [_dispute_view(r) for r in rows]
    return {"parcel_ref": parcel_ref, "disputes": views,
            "open": sum(1 for v in views if v["status"] == "open"),
            "sla_breached": sum(1 for v in views if v["sla_breached"])}


@router.post("/internal/disputes/sweep")
def sweep_sla_breaches(store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    """SLA-breach sweeper (internal/cron): every open dispute past its SLA
    deadline that has NOT yet been notified is marked and emits exactly one
    `dispute.sla.breached` webhook. Time — not a request — is what breaches an
    SLA, so this must be swept periodically (e.g. hourly cron).
    breach_notified persists the exactly-once guarantee across restarts."""
    rows = store.query(
        "SELECT * FROM dispute_cases WHERE tenant_id = 'default' AND status = 'open'"
        " AND breach_notified = :f", {"f": False})
    breached = []
    for row in rows:
        view = _dispute_view(row)
        if not view["sla_breached"]:
            continue
        store.execute(
            "UPDATE dispute_cases SET breach_notified = :b, updated_at = :t"
            " WHERE tenant_id = 'default' AND id = :i",
            {"b": True, "t": _now(), "i": row["id"]})
        evidence.append_event(store, row["parcel_ref"], "dispute_sla_breached",
                              {"dispute_id": row["id"], "days_open": view["days_open"]})
        events.emit_event("dispute.sla.breached", "default",
                          {"parcel_ref": row["parcel_ref"], "dispute_id": row["id"],
                           "sla_days": view["sla_days"], "days_open": view["days_open"]})
        breached.append({"dispute_id": row["id"], "parcel_ref": row["parcel_ref"],
                         "days_open": view["days_open"]})
    return {"swept": len(breached), "breached": breached}


# ---------------------------------------------------------------------------
# Revocation / compensation — Land Use Act 1978 lawfulness guardrail
# ---------------------------------------------------------------------------

class RevocationOpenInput(BaseModel):
    notice_ref: Optional[str] = None
    reason: Optional[str] = None


class CompensationInput(BaseModel):
    amount: float = Field(gt=0)
    method: str = Field(min_length=1, max_length=128)


def _revocation_view(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "revocation_id": row["id"],
        "parcel_ref": row["parcel_ref"],
        "notice_ref": row.get("notice_ref"),
        "reason": row.get("reason"),
        "status": row["status"],
        # Land Use Act 1978: acquisition is lawful ONLY when compensation paid.
        "acquisition_lawful": row["status"] == "compensated",
        "compensation_amount": row.get("compensation_amount"),
        "compensation_method": row.get("compensation_method"),
        "compensated_at": row.get("compensated_at"),
        "created_at": row["created_at"],
    }


@router.post("/api/v1/parcels/{parcel_ref}/revocations", status_code=201)
def open_revocation(parcel_ref: str, payload: RevocationOpenInput,
                    store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    _get_parcel(store, parcel_ref)
    existing = store.query_one(
        "SELECT id FROM parcel_revocations WHERE tenant_id = 'default' AND parcel_ref = :p"
        " AND status != 'compensated'", {"p": parcel_ref})
    if existing:
        raise HTTPException(status_code=409, detail="an uncompensated revocation is already open")
    rid = str(uuid.uuid4())
    store.execute(
        "INSERT INTO parcel_revocations (id, tenant_id, parcel_ref, notice_ref, reason, status)"
        " VALUES (:i, 'default', :p, :n, :r, 'notice_served')",
        {"i": rid, "p": parcel_ref, "n": payload.notice_ref, "r": payload.reason},
    )
    store.execute(
        "UPDATE parcels SET status = 'revoked', updated_at = :t"
        " WHERE tenant_id = 'default' AND parcel_ref = :p",
        {"t": _now(), "p": parcel_ref})
    evidence.append_event(store, parcel_ref, "revocation_notice",
                          {"revocation_id": rid, "notice_ref": payload.notice_ref})
    events.emit_event("revocation.opened", "default",
                      {"parcel_ref": parcel_ref, "revocation_id": rid})
    row = store.query_one("SELECT * FROM parcel_revocations WHERE id = :i", {"i": rid})
    return _revocation_view(row)


@router.post("/api/v1/revocations/{revocation_id}/documents")
def revocation_documents(revocation_id: str,
                         store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    row = store.query_one(
        "SELECT * FROM parcel_revocations WHERE tenant_id = 'default' AND id = :i", {"i": revocation_id})
    if not row:
        raise HTTPException(status_code=404, detail=f"revocation '{revocation_id}' not found")
    if row["status"] != "notice_served":
        raise HTTPException(status_code=409, detail=f"revocation already {row['status']}")
    store.execute(
        "UPDATE parcel_revocations SET status = 'documents_collected', updated_at = :t"
        " WHERE tenant_id = 'default' AND id = :i",
        {"t": _now(), "i": revocation_id})
    evidence.append_event(store, row["parcel_ref"], "revocation_documents_collected",
                          {"revocation_id": revocation_id})
    updated = store.query_one("SELECT * FROM parcel_revocations WHERE id = :i", {"i": revocation_id})
    return _revocation_view(updated)


@router.post("/api/v1/revocations/{revocation_id}/compensate")
def revocation_compensate(revocation_id: str, payload: CompensationInput,
                          store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    row = store.query_one(
        "SELECT * FROM parcel_revocations WHERE tenant_id = 'default' AND id = :i", {"i": revocation_id})
    if not row:
        raise HTTPException(status_code=404, detail=f"revocation '{revocation_id}' not found")
    if row["status"] == "compensated":
        raise HTTPException(status_code=409, detail="revocation already compensated")
    # Compensation requires the claimant's documents to have been collected —
    # the video's independent-body workflow ("everybody bring your document.
    # Compensate them").
    if row["status"] != "documents_collected":
        raise HTTPException(
            status_code=409,
            detail="documents must be collected before compensation (Land Use Act workflow)")
    now = _now()
    store.execute(
        "UPDATE parcel_revocations SET status = 'compensated', compensation_amount = :a,"
        " compensation_method = :m, compensated_at = :t, updated_at = :t"
        " WHERE tenant_id = 'default' AND id = :i",
        {"a": payload.amount, "m": payload.method, "t": now, "i": revocation_id},
    )
    evidence.append_event(store, row["parcel_ref"], "revocation_compensated",
                          {"revocation_id": revocation_id, "amount": payload.amount})
    events.emit_event("revocation.compensated", "default",
                      {"parcel_ref": row["parcel_ref"], "revocation_id": revocation_id})
    updated = store.query_one("SELECT * FROM parcel_revocations WHERE id = :i", {"i": revocation_id})
    return _revocation_view(updated)


@router.get("/api/v1/parcels/{parcel_ref}/revocations")
def list_revocations(parcel_ref: str,
                     store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    _get_parcel(store, parcel_ref)
    rows = store.query(
        "SELECT * FROM parcel_revocations WHERE tenant_id = 'default' AND parcel_ref = :p"
        " ORDER BY created_at", {"p": parcel_ref})
    views = [_revocation_view(r) for r in rows]
    return {"parcel_ref": parcel_ref, "revocations": views,
            "uncompensated": sum(1 for v in views if not v["acquisition_lawful"])}


# ---------------------------------------------------------------------------
# Evidence pack export (court-admissible, hash-chained, hash-only payloads)
# ---------------------------------------------------------------------------

@router.get("/api/v1/parcels/{parcel_ref}/evidence")
def evidence_pack(parcel_ref: str, store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    _get_parcel(store, parcel_ref)
    entries = evidence.get_chain(store, parcel_ref)
    return {
        "parcel_ref": parcel_ref,
        "entries": entries,
        "entry_count": len(entries),
        "chain_valid": evidence.verify_chain(entries, parcel_ref),
        "format": "hash-chained evidence pack v1 (payloads hash-only, NDPA-aligned)",
    }


# ---------------------------------------------------------------------------
# Composite pre-purchase due diligence — "verify you actually have the right
# title" (CTC-check equivalent + every signal this module records)
# ---------------------------------------------------------------------------

class DueDiligenceInput(BaseModel):
    state: str = Field(min_length=1)
    certificate_number: Optional[str] = None
    property_address: Optional[str] = None
    parcel_ref: Optional[str] = None
    claimed_owner: Optional[str] = None  # seller's claimed name, for registry cross-check


@router.post("/api/v1/due-diligence")
def due_diligence(payload: DueDiligenceInput,
                  store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    state = _canonical_state(payload.state)
    reasons: list[dict[str, str]] = []
    signals: dict[str, Any] = {}

    # 1. Registry owner cross-check (CTC equivalent) — fail-closed honesty:
    #    an unreachable registry degrades the whole verdict to 'unavailable'.
    adapter = get_lands_adapter(state, store)
    owner = adapter.owner(state=state, certificate_number=payload.certificate_number,
                          property_address=payload.property_address)
    signals["registry"] = {"status": owner.get("status"), "source": owner.get("source")}
    if owner.get("status") == "unavailable":
        return {"verdict": "unavailable",
                "reason": owner.get("reason", "lands registry unavailable"),
                "signals": signals}
    if owner.get("status") != "found":
        reasons.append({"severity": "high", "code": "registry_not_found",
                        "detail": "no registered owner found for this certificate/address"})
    else:
        # File-import adapter reports "name"; the HTTP registry API reports
        # "owner_name" — accept either.
        owner_name = owner.get("owner_name") or owner.get("name") or ""
        registered_owner = owner_name.strip().lower()
        signals["registry"]["owner_name"] = owner_name
        if payload.claimed_owner and registered_owner:
            if payload.claimed_owner.strip().lower() != registered_owner:
                reasons.append({"severity": "high", "code": "owner_mismatch",
                                "detail": "seller is not the registered owner "
                                          f"(registry: {owner_name})"})

    # 2. Recorded claimants (double-allocation evidence).
    claimants = store.query(
        "SELECT claimant_name FROM parcel_claimants WHERE tenant_id = 'default'"
        " AND lower(state) = lower(:s) AND (certificate_number = :c OR (:c = '' AND lower(property_address) = lower(:a)))",
        {"s": state, "c": payload.certificate_number or "", "a": payload.property_address or ""},
    )
    distinct_claimants = {c["claimant_name"].strip().lower() for c in claimants}
    signals["claimants"] = {"count": len(claimants), "distinct": len(distinct_claimants)}
    if len(distinct_claimants) > 1:
        reasons.append({"severity": "high", "code": "multiple_claimants",
                        "detail": f"{len(distinct_claimants)} distinct claimants recorded"})

    # 3. Parcel-level signals when the parcel is registered with us.
    if payload.parcel_ref:
        parcel = store.query_one(
            "SELECT * FROM parcels WHERE tenant_id = 'default' AND parcel_ref = :p",
            {"p": payload.parcel_ref})
        if parcel:
            view = _parcel_view(store, parcel)
            signals["parcel"] = {"status": view["status"],
                                 "consent_complete": view["consent_complete"],
                                 "consent_outstanding": view["consent_outstanding"]}
            if not view["consent_complete"]:
                reasons.append({"severity": "medium", "code": "consent_incomplete",
                                "detail": "consent outstanding: "
                                          + ", ".join(view["consent_outstanding"])})
            open_d = store.query(
                "SELECT * FROM dispute_cases WHERE tenant_id = 'default' AND parcel_ref = :p AND status = 'open'",
                {"p": payload.parcel_ref})
            signals["disputes"] = {"open": len(open_d),
                                   "sla_breached": sum(1 for r in open_d if _dispute_view(r)["sla_breached"])}
            if open_d:
                reasons.append({"severity": "medium", "code": "open_dispute",
                                "detail": f"{len(open_d)} open dispute case(s)"})
            rev = store.query(
                "SELECT * FROM parcel_revocations WHERE tenant_id = 'default' AND parcel_ref = :p"
                " AND status != 'compensated'", {"p": payload.parcel_ref})
            signals["revocations"] = {"uncompensated": len(rev)}
            if rev:
                reasons.append({"severity": "high", "code": "uncompensated_revocation",
                                "detail": "revocation without compensation — acquisition not lawful "
                                          "under the Land Use Act 1978"})

    if any(r["severity"] == "high" for r in reasons):
        verdict = "high_risk"
    elif reasons:
        verdict = "caution"
    else:
        verdict = "clear"
    return {"verdict": verdict, "reasons": reasons, "signals": signals,
            "title_sha256": hashlib.sha256(
                f"{state}|{payload.certificate_number}|{payload.property_address}".encode()
            ).hexdigest()}
