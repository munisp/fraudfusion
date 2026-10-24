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

from api import evidence, events, geospatial, risk
from api import doc_intel
from api.data_store import LandDataStore, get_land_store
from api.deed_conformance import check_deed_conformance
from api.registry_adapters import get_lands_adapter
from api.title_chain import analyze_title_chain

router = APIRouter()

DISPUTE_SLA_DAYS = int(os.getenv("LAND_DISPUTE_SLA_DAYS", "90"))
NOTICE_PERIOD_DAYS = int(os.getenv("LAND_NOTICE_PERIOD_DAYS", "21"))
VELOCITY_DAYS = int(os.getenv("LAND_SELLER_VELOCITY_DAYS", "30"))
VELOCITY_MAX = int(os.getenv("LAND_SELLER_VELOCITY_MAX", "3"))
GEOHASH_PRECISION = int(os.getenv("LAND_GEOHASH_PRECISION", "6"))


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
    beacons: Optional[str] = None  # "6.45N 3.40E, ..." or JSON [[lat,lon],...]
    registered_by: Optional[str] = None
    consent_required: list[str] = []
    notice_period_days: Optional[int] = Field(default=None, ge=0, le=365)


class ConsentInput(BaseModel):
    party_name: str = Field(min_length=1, max_length=256)
    confirmed: bool = True
    method: Optional[str] = None  # "signature" | "thumbprint" | "liveness" | ...
    bvn_or_nin: Optional[str] = None   # 11 digits; stored HASH-ONLY
    liveness_challenge_id: Optional[str] = None  # required when method="liveness"


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
    open_objections = store.query(
        "SELECT id FROM parcel_objections WHERE tenant_id = :t AND parcel_ref = :p AND status = 'open'",
        {"t": row["tenant_id"], "p": row["parcel_ref"]},
    )
    notice_expires = row.get("notice_expires_at")
    notice_active = bool(notice_expires) and _parse_dt(notice_expires) > datetime.utcnow()
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
        "open_objections": len(open_objections),
        "notice_expires_at": notice_expires,
        "notice_active": notice_active,
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


def _seller_velocity(store: LandDataStore, registered_by: Optional[str]) -> int:
    """F4 — parcels registered by the same party within VELOCITY_DAYS.
    Serial land-grabbers register many plots in bursts; a count above
    VELOCITY_MAX is a serial-seller signal for due diligence."""
    if not registered_by:
        return 0
    cutoff = (datetime.utcnow() - timedelta(days=VELOCITY_DAYS)).isoformat()
    rows = store.query(
        "SELECT parcel_ref FROM parcels WHERE tenant_id = 'default'"
        " AND registered_by = :b AND created_at >= :c",
        {"b": registered_by, "c": cutoff})
    return len(rows)


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

    # Geospatial checks (Round 13): the GROUND is compared, not just labels.
    # Exact overlap (shared land) disputes the parcel; centroid geohash
    # proximity flags likely re-survey fraud for review without blocking.
    import json as _json
    new_poly = geospatial.parse_beacons(payload.beacons)
    beacons_json = _json.dumps(new_poly) if new_poly else None
    if new_poly:
        new_hash = geospatial.centroid_geohash(new_poly, GEOHASH_PRECISION)
        for other in store.query(
                "SELECT parcel_ref, beacons FROM parcels WHERE tenant_id = 'default'"
                " AND parcel_ref != :p AND beacons IS NOT NULL", {"p": ref}):
            other_poly = geospatial.parse_beacons(other.get("beacons"))
            if not other_poly:
                continue
            if geospatial.polygons_overlap(new_poly, other_poly):
                conflicts.append({"conflict_key": f"geospatial_overlap:{other['parcel_ref']}",
                                  "existing_ref": other["parcel_ref"],
                                  "reason": "beacon polygons overlap — the parcels share land"})
            elif (geospatial.centroid_geohash(other_poly, GEOHASH_PRECISION) == new_hash):
                conflicts.append({"conflict_key": f"resurvey_proximity:{other['parcel_ref']}",
                                  "existing_ref": other["parcel_ref"],
                                  "reason": "parcel centroids share a geohash cell — "
                                            "possible re-survey of the same plot"})
    hard_conflict = any(c["conflict_key"].startswith(
        ("certificate_number:", "survey_plan_hash:", "geospatial_overlap:"))
        for c in conflicts)
    status = "disputed" if hard_conflict else "provisional"
    notice_days = NOTICE_PERIOD_DAYS if payload.notice_period_days is None else payload.notice_period_days
    notice_expires = (datetime.utcnow() + timedelta(days=notice_days)).isoformat() if notice_days else None
    store.execute(
        "INSERT INTO parcels (tenant_id, parcel_ref, state, lga, property_address,"
        " certificate_number, survey_plan_hash, beacons, notice_expires_at,"
        " registered_by, status, consent_required)"
        " VALUES ('default', :r, :s, :l, :a, :c, :h, :bc, :ne, :b, :st, :cr)",
        {"r": ref, "s": state, "l": payload.lga, "a": payload.property_address,
         "c": payload.certificate_number, "h": payload.survey_plan_hash,
         "bc": beacons_json, "ne": notice_expires,
         "b": payload.registered_by, "st": status,
         "cr": _json.dumps([p.strip() for p in payload.consent_required if p.strip()])},
    )
    evidence.append_event(store, ref, "parcel_registered",
                          {"state": state, "certificate_number": payload.certificate_number,
                           "conflicts": conflicts})
    events.emit_event("parcel.registered", "default",
                      {"parcel_ref": ref, "state": state, "status": status})
    for c in conflicts:
        store.execute(
            "INSERT INTO parcel_conflicts (tenant_id, parcel_ref, conflict_key, existing_ref, reason)"
            " VALUES ('default', :p, :k, :e, :r)",
            {"p": ref, "k": c["conflict_key"], "e": c["existing_ref"], "r": c["reason"]})
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
    # F8 — consent identity binding: a NAME is not an identity. Consent fraud
    # routinely impersonates family members, so BVN/NIN is validated and
    # stored HASH-ONLY (NDPA data-minimisation), and liveness consent must
    # reference a verified kyc-api challenge.
    identity_hash = None
    if payload.bvn_or_nin:
        digits = payload.bvn_or_nin.strip()
        if not (digits.isdigit() and len(digits) == 11):
            raise HTTPException(status_code=422,
                                detail="bvn_or_nin must be exactly 11 digits")
        identity_hash = hashlib.sha256(digits.encode()).hexdigest()
    if (payload.method or "").strip().lower() == "liveness" and not payload.liveness_challenge_id:
        raise HTTPException(
            status_code=422,
            detail="liveness consent requires liveness_challenge_id from a verified kyc-api challenge")
    store.execute(
        "INSERT INTO parcel_consents (tenant_id, parcel_ref, party_name, confirmed, method,"
        " confirmed_at, identity_hash, liveness_challenge_id)"
        " VALUES ('default', :p, :n, :c, :m, :t, :ih, :lc)"
        " ON CONFLICT (tenant_id, parcel_ref, party_name)"
        " DO UPDATE SET confirmed = :c, method = :m, confirmed_at = :t,"
        " identity_hash = :ih, liveness_challenge_id = :lc",
        {"p": parcel_ref, "n": payload.party_name.strip(), "c": payload.confirmed,
         "m": payload.method, "t": now if payload.confirmed else None,
         "ih": identity_hash, "lc": payload.liveness_challenge_id},
    )
    evidence.append_event(store, parcel_ref, "consent_recorded",
                          {"party": payload.party_name.strip(), "confirmed": payload.confirmed,
                           "method": payload.method,
                           "identity_bound": bool(identity_hash)})

    view = _parcel_view(store, row)
    # Parcel only goes 'clear' when every required consent party confirmed,
    # there are no open conflicts/objections AND the public notice period
    # has expired (F5) — mirrors the video: buying from 2 of 7 families is
    # NOT consent, and a sale announced yesterday is not safe to complete.
    if (view["consent_complete"] and row["status"] == "provisional"
            and not view["notice_active"] and not view["open_objections"]):
        conflicts = store.query(
            "SELECT id FROM parcel_conflicts WHERE tenant_id = 'default' AND parcel_ref = :p"
            " AND (conflict_key LIKE 'parcel_ref:%' OR conflict_key LIKE 'certificate_number:%'"
            " OR conflict_key LIKE 'survey_plan_hash:%' OR conflict_key LIKE 'geospatial_overlap:%')",
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
    # F7 — professional attestation cross-check
    witness_names: list[str] = []
    surveyor_name: Optional[str] = None
    surveyor_license: Optional[str] = None
    # Round 14 — authenticate the deed SCAN itself (pixel/PDF forensics,
    # fingerprint registry). Text clauses prove structure; only the engine
    # proves the document wasn't fabricated.
    deed_document_base64: Optional[str] = None
    deed_document_kind: str = Field(default="image", pattern="^(image|pdf)$")


def _attestation_check(payload: DeedConformanceInput) -> dict[str, Any]:
    """F7: an unattested deed is a forgery vector — but a name typed into a
    deed proves nothing. We verify (1) each claimed professional is actually
    mentioned on an execution/attestation line of THIS deed, and (2) report
    license-verification status honestly: no live professional-registry
    (COREN/SURCON/NBA) adapter is wired yet, so `license_verified` is None
    (manual verification required), never silently True."""
    text_lower = payload.deed_text.lower()
    lines = [ln.strip().lower() for ln in payload.deed_text.splitlines() if ln.strip()]

    def _on_signature_line(name: str) -> bool:
        n = name.strip().lower()
        return any(n in ln and any(k in ln for k in
                   ("sign", "witness", "attest", "executed", "seal", "thumbprint"))
                   for ln in lines)

    witnesses = [{"name": w, "attested_in_deed": _on_signature_line(w)}
                 for w in payload.witness_names if w.strip()]
    surveyor = None
    if payload.surveyor_name or payload.surveyor_license:
        mentioned = (payload.surveyor_name or "").strip().lower() in text_lower \
            if payload.surveyor_name else False
        surveyor = {
            "name": payload.surveyor_name,
            "license": payload.surveyor_license,
            "mentioned_in_deed": mentioned,
            "license_format_plausible": bool(payload.surveyor_license
                                             and len(payload.surveyor_license.strip()) >= 4),
            "license_verified": None,
            "note": "no live professional-registry adapter configured — "
                    "verify the surveyor's SURCON license manually before reliance",
        }
    unattested = [w["name"] for w in witnesses if not w["attested_in_deed"]]
    return {"witnesses": witnesses, "surveyor": surveyor,
            "unattested_witnesses": unattested,
            "all_attested": not unattested and bool(witnesses)}


@router.post("/api/v1/deeds/conformance")
def deed_conformance(payload: DeedConformanceInput,
                     store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    result = check_deed_conformance(payload.deed_text, payload.consent_parties)
    result["template"] = "fraudfusion-standard-deed-of-assignment/v1"
    if payload.witness_names or payload.surveyor_name or payload.surveyor_license:
        result["professional_attestation"] = _attestation_check(payload)
        if result["professional_attestation"]["unattested_witnesses"]:
            result["conformant"] = False
    if payload.deed_document_base64:
        import base64 as _b64
        try:
            raw = _b64.b64decode(payload.deed_document_base64)
        except Exception:
            raise HTTPException(status_code=422,
                                detail="deed_document_base64 is not valid base64")
        auth = doc_intel.analyze_document(raw, payload.deed_document_kind,
                                          "deed_of_assignment",
                                          reference=payload.parcel_ref)
        result["document_authenticity"] = auth
        if auth.get("engine_performed") and auth["band"] == "forgery_suspected":
            result["conformant"] = False
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
    reasons: list[dict[str, str]] = []   # legacy severity list (back-compat)
    factors: list[dict[str, Any]] = []   # F6 explainable scoring
    signals: dict[str, Any] = {}

    def _factor(code: str, detail: str, severity: str = "medium",
                penalty: Optional[int] = None) -> None:
        f: dict[str, Any] = {"code": code, "detail": detail}
        if penalty is not None:
            f["penalty"] = penalty
        factors.append(f)
        reasons.append({"severity": severity, "code": code, "detail": detail})

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
        _factor("registry_not_found",
                "no registered owner found for this certificate/address", "high")
    else:
        # File-import adapter reports "name"; the HTTP registry API reports
        # "owner_name" — accept either.
        owner_name = owner.get("owner_name") or owner.get("name") or ""
        registered_owner = owner_name.strip().lower()
        signals["registry"]["owner_name"] = owner_name
        if payload.claimed_owner and registered_owner:
            if payload.claimed_owner.strip().lower() != registered_owner:
                _factor("owner_mismatch",
                        "seller is not the registered owner "
                        f"(registry: {owner_name})", "high")

    # 2. Recorded claimants (double-allocation evidence).
    claimants = store.query(
        "SELECT claimant_name FROM parcel_claimants WHERE tenant_id = 'default'"
        " AND lower(state) = lower(:s) AND (certificate_number = :c OR (:c = '' AND lower(property_address) = lower(:a)))",
        {"s": state, "c": payload.certificate_number or "", "a": payload.property_address or ""},
    )
    distinct_claimants = {c["claimant_name"].strip().lower() for c in claimants}
    signals["claimants"] = {"count": len(claimants), "distinct": len(distinct_claimants)}
    if len(distinct_claimants) > 1:
        _factor("multiple_claimants",
                f"{len(distinct_claimants)} distinct claimants recorded", "high")

    # 3. Parcel-level signals when the parcel is registered with us.
    if payload.parcel_ref:
        parcel = store.query_one(
            "SELECT * FROM parcels WHERE tenant_id = 'default' AND parcel_ref = :p",
            {"p": payload.parcel_ref})
        if parcel:
            view = _parcel_view(store, parcel)
            signals["parcel"] = {"status": view["status"],
                                 "consent_complete": view["consent_complete"],
                                 "consent_outstanding": view["consent_outstanding"],
                                 "notice_active": view["notice_active"],
                                 "open_objections": view["open_objections"]}
            conflict_rows = store.query(
                "SELECT conflict_key FROM parcel_conflicts WHERE tenant_id = 'default'"
                " AND parcel_ref = :p", {"p": payload.parcel_ref})
            overlaps = [c["conflict_key"] for c in conflict_rows
                        if str(c["conflict_key"]).startswith("geospatial_overlap:")]
            signals["conflicts"] = {"total": len(conflict_rows),
                                    "geospatial_overlaps": len(overlaps)}
            if overlaps:
                _factor("geospatial_overlap",
                        f"beacon polygon overlaps {len(overlaps)} registered parcel(s): "
                        + ", ".join(k.split(":", 1)[1] for k in overlaps), "high")
            if not view["consent_complete"]:
                _factor("consent_incomplete",
                        "consent outstanding: " + ", ".join(view["consent_outstanding"]))
            if view["open_objections"]:
                _factor("objection_open",
                        f"{view['open_objections']} open public objection(s)", "high")
            if view["notice_active"]:
                _factor("notice_period_active",
                        "public notice period still running — objections may yet be filed",
                        "low")
            velocity = _seller_velocity(store, parcel.get("registered_by"))
            signals["seller_velocity"] = {"registered_by": parcel.get("registered_by"),
                                          "parcels_in_window": velocity,
                                          "window_days": VELOCITY_DAYS}
            if velocity > VELOCITY_MAX:
                _factor("serial_seller",
                        f"{velocity} parcels registered by the same party in "
                        f"{VELOCITY_DAYS} days (>{VELOCITY_MAX}) — serial-grab pattern", "high")
            open_d = store.query(
                "SELECT * FROM dispute_cases WHERE tenant_id = 'default' AND parcel_ref = :p AND status = 'open'",
                {"p": payload.parcel_ref})
            breached = sum(1 for r in open_d if _dispute_view(r)["sla_breached"])
            signals["disputes"] = {"open": len(open_d), "sla_breached": breached}
            if open_d:
                _factor("open_dispute", f"{len(open_d)} open dispute case(s)")
            if breached:
                _factor("sla_breached",
                        f"{breached} dispute(s) past their {DISPUTE_SLA_DAYS}-day SLA")
            rev = store.query(
                "SELECT * FROM parcel_revocations WHERE tenant_id = 'default' AND parcel_ref = :p"
                " AND status != 'compensated'", {"p": payload.parcel_ref})
            signals["revocations"] = {"uncompensated": len(rev)}
            if rev:
                _factor("uncompensated_revocation",
                        "revocation without compensation — acquisition not lawful "
                        "under the Land Use Act 1978", "high")

    # 4. Root-of-title chain analysis (F3) from the registry history —
    #    advisory: history gaps must never fail-closed the verdict.
    chain: dict[str, Any] = {"chain_depth": 0, "issues": [], "score_penalty": 0}
    try:
        history = adapter.history(state=state,
                                  certificate_number=payload.certificate_number,
                                  property_address=payload.property_address)
        records = (history or {}).get("ownership_history") or []
        if records:
            chain = analyze_title_chain(records)
            if chain["score_penalty"]:
                _factor("title_chain",
                        "; ".join(i["code"] for i in chain["issues"]),
                        "medium", penalty=chain["score_penalty"])
    except Exception:
        signals["title_chain_unavailable"] = True
    signals["title_chain"] = chain

    scored = risk.score_factors(factors)
    # Back-compat: the legacy severity verdict and the score band are both
    # reported; the headline verdict is the STRICTER of the two so existing
    # integrators never see a downgrade silently.
    legacy = ("high_risk" if any(r["severity"] == "high" for r in reasons)
              else ("caution" if reasons else "clear"))
    rank = {"clear": 0, "caution": 1, "high_risk": 2}
    verdict = legacy if rank[legacy] >= rank[scored["band"]] else scored["band"]
    return {"verdict": verdict, "risk_score": scored["risk_score"],
            "band": scored["band"], "factors": scored["factors"],
            "reasons": reasons, "signals": signals,
            "title_sha256": hashlib.sha256(
                f"{state}|{payload.certificate_number}|{payload.property_address}".encode()
            ).hexdigest()}


# ---------------------------------------------------------------------------
# Public objections (F5) — anyone may object during/after the notice period;
# an open objection disputes the parcel until resolved
# ---------------------------------------------------------------------------

class ObjectionInput(BaseModel):
    objector_name: str = Field(min_length=1, max_length=256)
    objector_id: Optional[str] = None  # BVN/NIN or ref; stored HASH-ONLY
    grounds: str = Field(min_length=1, max_length=2048)


class ObjectionResolveInput(BaseModel):
    status: str = Field(default="resolved", pattern="^(resolved|dismissed)$")
    resolution: str = Field(min_length=1, max_length=512)


def _objection_view(row: dict[str, Any]) -> dict[str, Any]:
    return {"objection_id": row["id"], "parcel_ref": row["parcel_ref"],
            "objector_name": row["objector_name"], "grounds": row["grounds"],
            "status": row["status"], "resolution": row.get("resolution"),
            "created_at": row["created_at"], "resolved_at": row.get("resolved_at")}


@router.post("/api/v1/parcels/{parcel_ref}/objections", status_code=201)
def raise_objection(parcel_ref: str, payload: ObjectionInput,
                    store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    parcel = _get_parcel(store, parcel_ref)
    oid = str(uuid.uuid4())
    id_hash = (hashlib.sha256(payload.objector_id.strip().encode()).hexdigest()
               if payload.objector_id else None)
    store.execute(
        "INSERT INTO parcel_objections (id, tenant_id, parcel_ref, objector_name,"
        " objector_id_hash, grounds, status, created_at)"
        " VALUES (:i, 'default', :p, :n, :h, :g, 'open', :t)",
        {"i": oid, "p": parcel_ref, "n": payload.objector_name.strip(),
         "h": id_hash, "g": payload.grounds, "t": _now()},
    )
    if parcel["status"] in ("provisional", "clear"):
        store.execute(
            "UPDATE parcels SET status = 'disputed', updated_at = :t"
            " WHERE tenant_id = 'default' AND parcel_ref = :p",
            {"t": _now(), "p": parcel_ref})
    evidence.append_event(store, parcel_ref, "objection_raised",
                          {"objection_id": oid, "grounds_hash":
                           hashlib.sha256(payload.grounds.encode()).hexdigest()})
    events.emit_event("parcel.objection.raised", "default",
                      {"parcel_ref": parcel_ref, "objection_id": oid})
    row = store.query_one("SELECT * FROM parcel_objections WHERE id = :i", {"i": oid})
    return _objection_view(row)


@router.get("/api/v1/parcels/{parcel_ref}/objections")
def list_objections(parcel_ref: str,
                    store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    _get_parcel(store, parcel_ref)
    rows = store.query(
        "SELECT * FROM parcel_objections WHERE tenant_id = 'default' AND parcel_ref = :p"
        " ORDER BY created_at", {"p": parcel_ref})
    views = [_objection_view(r) for r in rows]
    return {"parcel_ref": parcel_ref, "objections": views,
            "open": sum(1 for v in views if v["status"] == "open")}


@router.post("/api/v1/objections/{objection_id}/resolve")
def resolve_objection(objection_id: str, payload: ObjectionResolveInput,
                      store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    row = store.query_one(
        "SELECT * FROM parcel_objections WHERE tenant_id = 'default' AND id = :i",
        {"i": objection_id})
    if not row:
        raise HTTPException(status_code=404, detail=f"objection '{objection_id}' not found")
    if row["status"] != "open":
        raise HTTPException(status_code=409, detail=f"objection already {row['status']}")
    now = _now()
    store.execute(
        "UPDATE parcel_objections SET status = :s, resolution = :r, resolved_at = :t"
        " WHERE tenant_id = 'default' AND id = :i",
        {"s": payload.status, "r": payload.resolution, "t": now, "i": objection_id})
    parcel_ref = row["parcel_ref"]
    evidence.append_event(store, parcel_ref, "objection_resolved",
                          {"objection_id": objection_id, "status": payload.status})
    # Restore the parcel when nothing else blocks it.
    parcel = _get_parcel(store, parcel_ref)
    if parcel["status"] == "disputed":
        blocks = store.query(
            "SELECT id FROM dispute_cases WHERE tenant_id = 'default'"
            " AND parcel_ref = :p AND status = 'open'", {"p": parcel_ref})
        objections = store.query(
            "SELECT id FROM parcel_objections WHERE tenant_id = 'default'"
            " AND parcel_ref = :p AND status = 'open'", {"p": parcel_ref})
        conflicts = store.query(
            "SELECT id FROM parcel_conflicts WHERE tenant_id = 'default'"
            " AND parcel_ref = :p AND (conflict_key LIKE 'certificate_number:%'"
            " OR conflict_key LIKE 'geospatial_overlap:%')", {"p": parcel_ref})
        if not blocks and not objections and not conflicts:
            view = _parcel_view(store, parcel)
            new_status = ("clear" if view["consent_complete"] and not view["notice_active"]
                          else "provisional")
            store.execute(
                "UPDATE parcels SET status = :s, updated_at = :t"
                " WHERE tenant_id = 'default' AND parcel_ref = :p",
                {"s": new_status, "t": now, "p": parcel_ref})
    updated = store.query_one("SELECT * FROM parcel_objections WHERE id = :i",
                              {"i": objection_id})
    return _objection_view(updated)


# ---------------------------------------------------------------------------
# Evidence-chain Merkle anchor (F9) — the hash chain is self-referential
# (anyone rewriting history recomputes the chain), so periodically anchor the
# Merkle root of all entry hashes as an evidence event; an external notary
# can pin the returned root without seeing any payload (hash-only, NDPA-safe)
# ---------------------------------------------------------------------------

def _merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return hashlib.sha256(b"EMPTY").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest()
                 for i in range(0, len(level), 2)]
    return level[0]


@router.get("/api/v1/parcels/{parcel_ref}/evidence/anchor")
def evidence_anchor(parcel_ref: str,
                    store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    _get_parcel(store, parcel_ref)
    entries = evidence.get_chain(store, parcel_ref)
    leaves = [e["entry_hash"] for e in entries]
    return {"parcel_ref": parcel_ref,
            "merkle_root": _merkle_root(leaves),
            "leaf_count": len(leaves),
            "algorithm": "sha256-pairwise merkle over entry_hash leaves (v1)",
            "chain_valid": evidence.verify_chain(entries, parcel_ref)}


@router.post("/api/v1/parcels/{parcel_ref}/evidence/anchor", status_code=201)
def record_evidence_anchor(parcel_ref: str,
                           store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    anchor = evidence_anchor(parcel_ref, store)
    evidence.append_event(store, parcel_ref, "evidence_anchored",
                          {"merkle_root": anchor["merkle_root"],
                           "leaf_count": anchor["leaf_count"]})
    events.emit_event("parcel.evidence.anchored", "default",
                      {"parcel_ref": parcel_ref, "merkle_root": anchor["merkle_root"]})
    return anchor


# ---------------------------------------------------------------------------
# Fraud-typology analytics (F10) — aggregate conflict/dispute/objection
# classes so registries and partners see WHICH fraud patterns dominate a state
# ---------------------------------------------------------------------------

@router.get("/api/v1/analytics/fraud-typologies")
def fraud_typologies(state: Optional[str] = None,
                     store: LandDataStore = Depends(get_land_store)) -> dict[str, Any]:
    state_filter = (state or "").strip().lower()
    conflict_rows = store.query(
        "SELECT c.conflict_key FROM parcel_conflicts c JOIN parcels p"
        " ON p.tenant_id = c.tenant_id AND p.parcel_ref = c.parcel_ref"
        " WHERE c.tenant_id = 'default' AND (:s = '' OR lower(p.state) = :s)",
        {"s": state_filter})
    typologies: dict[str, int] = {}
    for r in conflict_rows:
        cls = str(r["conflict_key"]).split(":", 1)[0]
        typologies[cls] = typologies.get(cls, 0) + 1
    disputes = store.query(
        "SELECT d.status FROM dispute_cases d JOIN parcels p"
        " ON p.tenant_id = d.tenant_id AND p.parcel_ref = d.parcel_ref"
        " WHERE d.tenant_id = 'default' AND (:s = '' OR lower(p.state) = :s)",
        {"s": state_filter})
    objections = store.query(
        "SELECT o.status FROM parcel_objections o JOIN parcels p"
        " ON p.tenant_id = o.tenant_id AND p.parcel_ref = o.parcel_ref"
        " WHERE o.tenant_id = 'default' AND (:s = '' OR lower(p.state) = :s)",
        {"s": state_filter})
    sellers = store.query(
        "SELECT registered_by, COUNT(*) AS n FROM parcels"
        " WHERE tenant_id = 'default' AND registered_by IS NOT NULL"
        " AND (:s = '' OR lower(state) = :s) GROUP BY registered_by"
        " HAVING COUNT(*) > :m ORDER BY n DESC",
        {"s": state_filter, "m": VELOCITY_MAX})
    return {"state": state_filter or None,
            "typologies": typologies,
            "totals": {
                "conflicts": len(conflict_rows),
                "disputes_open": sum(1 for d in disputes if d["status"] == "open"),
                "disputes_total": len(disputes),
                "objections_open": sum(1 for o in objections if o["status"] == "open"),
                "objections_total": len(objections),
            },
            "serial_sellers": [{"registered_by": s["registered_by"],
                                "parcels_registered": s["n"]} for s in sellers],
            "window_days": VELOCITY_DAYS,
            "velocity_threshold": VELOCITY_MAX}
