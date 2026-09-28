"""FraudFusion KYC API.

Backend for kyc-frontend (frontend/kyc-frontend/src/services/api.ts):
  /api/v1/kyc/verify/{basic,enhanced,premium}, /api/v1/kyc/status/{id},
  /api/v1/biometric/*, /api/v1/document/*, /api/v1/screening/*,
  /api/v1/credit-bureau/*, /api/v1/risk/*.

Backed by:
  - CBN Tier 1/2/3 state machine with encoded + enforced limits (app/tiers.py)
  - PEP screening: local pep_list table, fuzzy name match (app/screening.py)
  - Sanctions screening: local watchlist (DB table or JSON seed file)
  - BVN/NIN: format + luhn-style validation; registries reported unavailable
  - Credit bureau: adapter interface; default adapter reports unavailable
  - Document verification: layered engine in services/python/doc-verification
    (wired via app/docverification.py) — real local cv2 forensics (blur/glare/
    moire FFT/border/texture) always run for image payloads; PaddleOCR,
    docling, and an ollama vision model are lazy OPTIONAL backends; every
    layer reports ran/unavailable provenance, nothing is fabricated
  - Biometric: OpenKYC-compatible remote IDV (IDV_SERVER_URL) performs real
    face-match/liveness when configured; otherwise honest not-performed

Auth: fail-closed Keycloak introspection (app/auth.py).
Schema: database/20260827_pep_kyb_merchant.sql (pep_list, watchlist);
SQLite mirror in app/db.py for local dev/tests.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status

from app import bureau, counterparty, docverification, identity, phone_tenure, screening, tiers
from app.auth import Principal, get_current_principal
from app.db import Database, get_db
from app.schemas import (
    AppealDecisionRequest,
    AppealRequest,
    BasicKYCRequest,
    BehavioralAnalysisRequest,
    BiometricVerifyRequest,
    CounterpartyRigorEntry,
    CreditBureauRequest,
    EnhancedKYCRequest,
    FraudCheckRequest,
    KYCResponse,
    PremiumKYCRequest,
    RekycRequest,
    ScreeningRequest,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("kyc-api")

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10MB per document/image

# Periodic re-verification cadence by CBN tier (higher tiers review more often).
REVIEW_INTERVAL_DAYS = {"tier_1": 365, "tier_2": 180, "tier_3": 90}
DEFAULT_REKYC_DEADLINE_DAYS = 30
# Address re-verification reviews are due within this many days of the trigger.
ADDRESS_REVIEW_DEADLINE_DAYS = 30

IMAGE_MAGIC = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"%PDF": "pdf",
    b"GIF8": "gif",
    b"RIFF": "webp",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sniff_type(data: bytes) -> str:
    for magic, kind in IMAGE_MAGIC.items():
        if data.startswith(magic):
            if kind == "webp" and data[8:12] != b"WEBP":
                continue
            return kind
    return "unknown"


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.5:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# KYC verification flow
# ---------------------------------------------------------------------------

def _run_verification(db: Database, principal: Principal, level: str,
                      payload: BasicKYCRequest) -> KYCResponse:
    started = time.perf_counter()
    results: dict = {"level": level}
    risk = 0.10

    bvn_result = identity.validate_bvn(payload.bvn)
    nin_result = identity.validate_nin(payload.nin)
    results["bvn"] = bvn_result
    results["nin"] = nin_result

    # Recycled-number risk: a telco-recycled MSISDN can still be tied to a
    # previous owner's identity/bank accounts. Fail-closed: when the tenure
    # feed is absent the state is honestly 'unverified' (+0.05), never a
    # silent pass. Recycled within the window (+0.15, plus +0.10 when prior
    # owner account links persist) sets the recycled_number_risk flag.
    tenure = phone_tenure.assess_recycled_number(payload.phone)
    results["phone_tenure"] = tenure
    risk += tenure["risk_contribution"]

    id_ok = (bvn_result.get("provided") and bvn_result["format_valid"]) or (
        nin_result.get("provided") and nin_result["format_valid"]
    )
    id_invalid = (bvn_result.get("provided") and not bvn_result["format_valid"]) or (
        nin_result.get("provided") and not nin_result["format_valid"]
    )

    # Tier assignment with evidence enforcement (CBN Tier 1/2/3).
    check_pep = getattr(payload, "check_pep", False)
    check_sanctions = getattr(payload, "check_sanctions", False)
    evidence = {
        "bvn_or_nin": id_ok,
        # Tier 2+: a verified ID number stands in for the document evidence
        # at this verification stage (document capture is a separate flow).
        "id_document": id_ok and payload.date_of_birth is not None,
        "enhanced_due_diligence": check_pep and check_sanctions,
    }
    try:
        tier_limits = tiers.assign_tier(level, evidence)
    except tiers.TierAssignmentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    results["tier"] = tier_limits.tier
    results["tier_limits_ngn"] = {
        "single_transaction": tier_limits.single_transaction_ngn,
        "daily": tier_limits.daily_ngn,
        "requirements": list(tier_limits.requirements),
    }

    # Address-verification evidence: method + recency are tracked explicitly
    # (CBN quarterly physical-contact cadence). Stale evidence (>90d) or
    # electronic-only evidence at Tier 2+ schedules a 'triggered' address
    # re-verification review — surfaced in the response, never silent.
    addr_input = getattr(payload, "address_evidence", None)
    addr_method = addr_verified_at = None
    if addr_input is not None:
        try:
            record = tiers.validate_address_evidence(addr_input.method,
                                                     addr_input.verified_at)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        addr_method, addr_verified_at = record["method"], record["verified_at"]
    addr_review = tiers.address_review_required(
        tier_limits.tier, addr_method, addr_verified_at)
    results["address_verification"] = addr_review
    if addr_review["required"]:
        _schedule_address_review(db, payload.customer_id, tier_limits.tier,
                                 addr_review["reasons"])

    full_name = f"{payload.first_name} {payload.last_name}"
    nationality = getattr(payload, "nationality", None)

    pep = sanctions = None
    if level in ("enhanced", "premium") and check_pep:
        pep = screening.screen_pep(db, full_name, payload.date_of_birth, nationality)
        results["pep_screening"] = pep
        if pep["is_pep"]:
            risk += 0.45
    if level in ("enhanced", "premium") and check_sanctions:
        sanctions = screening.screen_sanctions(db, full_name, payload.date_of_birth,
                                               nationality)
        results["sanctions_screening"] = sanctions
        if sanctions["is_sanctioned"]:
            risk += 0.85

    if level == "premium":
        check_bureau = getattr(payload, "check_credit_bureau", False)
        provider = getattr(payload, "credit_bureau_provider", "crc")
        if check_bureau:
            adapter = bureau.get_adapter()
            bureau_result = adapter.check(payload.bvn or "", payload.first_name,
                                          payload.last_name, provider=provider)
            results["credit_bureau"] = bureau_result
            if bureau_result.get("status") == "unavailable":
                # Honest degradation: bureau outage never blocks a tier-3
                # decision, but it is surfaced and never fabricates a score.
                risk += 0.05

    if id_invalid:
        risk += 0.5
    risk = round(min(risk, 1.0), 3)

    if sanctions and sanctions["is_sanctioned"]:
        decision = "rejected"
    elif id_invalid:
        decision = "rejected"
    elif (pep and pep["is_pep"]) or risk >= 0.5:
        decision = "manual_review"
    else:
        decision = "approved"

    request_id = uuid.uuid4().hex
    now = _now()
    db.execute(
        "INSERT INTO kyc_requests (id, customer_id, level, tier, status, decision,"
        " risk_score, risk_level, results_json, actor_sub,"
        " address_verification_method, address_verified_at, created_at, updated_at)"
        " VALUES (:id, :cid, :level, :tier, 'completed', :decision, :score, :rl,"
        " :results, :actor, :addrm, :addrv, :now, :now)",
        {
            "id": request_id, "cid": payload.customer_id, "level": level,
            "tier": tier_limits.tier, "decision": decision, "score": risk,
            "rl": _risk_level(risk), "results": json.dumps(results),
            "actor": principal.sub, "addrm": addr_method, "addrv": addr_verified_at,
            "now": now,
        },
    )
    _schedule_periodic_review(db, payload.customer_id, tier_limits.tier)
    logger.info("kyc verification: id=%s level=%s decision=%s risk=%.2f by=%s",
                request_id, level, decision, risk, principal.sub)
    return KYCResponse(
        request_id=request_id,
        customer_id=payload.customer_id,
        status="completed",
        verification_level=level,
        risk_score=risk,
        risk_level=_risk_level(risk),
        decision=decision,
        verification_results=results,
        timestamp=now,
        processing_time_ms=round((time.perf_counter() - started) * 1000, 2),
    )


def _schedule_periodic_review(db: Database, customer_id: str, tier: str) -> None:
    """Periodic review scheduler: every completed verification enrolls the
    customer for their tier's next periodic review (tier_1: 12mo, tier_2: 6mo,
    tier_3: 3mo). Idempotent per (customer, type, due date)."""
    days = REVIEW_INTERVAL_DAYS.get(tier, 365)
    due = datetime.now(timezone.utc).timestamp() + days * 86400
    due_iso = datetime.fromtimestamp(due, timezone.utc).isoformat()
    db.execute(
        ("INSERT OR IGNORE INTO kyc_review_schedule (customer_id, review_type, tier, due_at)"
         " VALUES (:cid, 'periodic', :tier, :due)" if not db._is_pg else
         "INSERT INTO kyc_review_schedule (customer_id, review_type, tier, due_at)"
         " VALUES (:cid, 'periodic', :tier, :due) ON CONFLICT DO NOTHING"),
        {"cid": customer_id, "tier": tier, "due": due_iso},
    )


def _schedule_address_review(db: Database, customer_id: str, tier: str,
                             reasons: list[str]) -> None:
    """Address re-verification scheduler: stale (>90d) or electronic-only
    address evidence enrolls a 'triggered' review item due in
    ADDRESS_REVIEW_DEADLINE_DAYS. The due date is truncated to the day so
    repeated verifications on the same day are idempotent per
    (customer, type, due date)."""
    now = datetime.now(timezone.utc)
    due = (now.date() + timedelta(days=ADDRESS_REVIEW_DEADLINE_DAYS)).isoformat()
    db.execute(
        ("INSERT OR IGNORE INTO kyc_review_schedule (customer_id, review_type, tier, due_at,"
         " reason) VALUES (:cid, 'triggered', :tier, :due, :reason)" if not db._is_pg else
         "INSERT INTO kyc_review_schedule (customer_id, review_type, tier, due_at, reason)"
         " VALUES (:cid, 'triggered', :tier, :due, :reason) ON CONFLICT DO NOTHING"),
        {"cid": customer_id, "tier": tier, "due": due,
         "reason": "address_reverification: " + "; ".join(reasons)},
    )


def _latest_request(db: Database, customer_id: str) -> dict | None:
    return db.query_one(
        "SELECT * FROM kyc_requests WHERE customer_id = :cid ORDER BY created_at DESC LIMIT 1",
        {"cid": customer_id},
    )


async def _read_upload(upload: UploadFile) -> bytes:
    data = await upload.read()
    if not data:
        raise HTTPException(status_code=422, detail="uploaded file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="upload exceeds 10MB limit")
    return data


def _decode_base64_image(value: str, field: str) -> bytes:
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{field} is not valid base64") from exc
    if not data:
        raise HTTPException(status_code=422, detail=f"{field} decodes to empty content")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"{field} exceeds 10MB limit")
    return data


def _idv_payload(call_result: dict) -> dict | None:
    """Extract the first result object from an OpenKYC-compatible call
    response (the Gradio shape returns a list of outputs)."""
    result = call_result.get("result")
    if isinstance(result, list) and result and isinstance(result[0], dict):
        return result[0]
    if isinstance(result, dict):
        return result
    return None


def _idv_liveness_result(call_result: dict) -> dict:
    """Map an OpenKYC-compatible face_liveness_base64 response onto the
    kyc-api liveness schema. Unknown remote schemas are surfaced raw with an
    explicit note — never guessed."""
    base = {"adapter": call_result.get("adapter"),
            "source": call_result.get("source")}
    if call_result.get("status") != "ok":
        return {"performed": False, "result": "not_evaluated",
                "reason": call_result.get("reason",
                                          "remote liveness call failed"), **base}
    payload = _idv_payload(call_result)
    if payload is None:
        return {"performed": True, "result": "evaluated",
                "raw_result": call_result.get("result"),
                "reason": "remote response schema not mapped; raw result "
                          "included for manual review", **base}
    score = payload.get("liveness_score", payload.get("score",
                        payload.get("confidence")))
    is_live = payload.get("is_live", payload.get("liveness"))
    if isinstance(is_live, str):
        is_live = is_live.strip().lower() in ("live", "real", "true")
    result = ("live" if is_live else "spoof") if is_live is not None else "evaluated"
    return {"performed": True, "result": result,
            "score": score, "raw_result": payload, **base}


def _idv_face_match_result(call_result: dict) -> dict:
    """Map an OpenKYC-compatible compare_face_base64 response onto the
    kyc-api face_match schema."""
    base = {"adapter": call_result.get("adapter"),
            "source": call_result.get("source")}
    if call_result.get("status") != "ok":
        return {"performed": False, "score": None, "match": None,
                "reason": call_result.get("reason",
                                          "remote face-match call failed"), **base}
    payload = _idv_payload(call_result)
    if payload is None:
        return {"performed": True, "score": None, "match": None,
                "raw_result": call_result.get("result"),
                "reason": "remote response schema not mapped; raw result "
                          "included for manual review", **base}
    score = payload.get("similarity", payload.get("score",
                        payload.get("confidence")))
    match = payload.get("match", payload.get("is_same_person"))
    return {"performed": True, "score": score, "match": match,
            "raw_result": payload, **base}


def _biometric_response(selfie: bytes, reference: bytes | None, check_liveness: bool) -> dict:
    """Biometric verification: when an OpenKYC-compatible IDV server is
    configured (IDV_SERVER_URL) the face-match/liveness probes are REALLY
    performed remotely and carry adapter/source provenance. Without one,
    nothing is fabricated — every probe reports its true status and the
    capture routes to manual review."""
    selfie_kind = _sniff_type(selfie)
    results = {
        "verification_id": uuid.uuid4().hex,
        "status": "manual_review",
        "selfie_format": selfie_kind,
        "face_match": {
            "performed": False,
            "score": None,
            "match": None,
            "reason": "face-match model not configured (no biometric embedding "
                      "service wired); routed to manual review",
        },
        "liveness": {
            "performed": False,
            "result": "not_evaluated",
            "reason": "liveness detection model not configured",
        }
        if check_liveness
        else {"performed": False, "result": "skipped", "reason": "check_liveness=false"},
        "timestamp": _now(),
    }
    if selfie_kind == "unknown":
        results["status"] = "rejected"
        results["rejection_reason"] = "selfie is not a recognizable image format"
        return results
    if reference is not None:
        results["reference_format"] = _sniff_type(reference)

    idv = (docverification.get_idv_adapter()
           if docverification.DOCVERIFICATION_AVAILABLE else None)
    if idv is None or not idv.available:
        return results

    # Liveness probe on the selfie.
    if check_liveness:
        results["liveness"] = _idv_liveness_result(
            idv.face_liveness_base64(selfie))
    # Face match against the reference document portrait.
    if reference is not None:
        results["face_match"] = _idv_face_match_result(
            idv.compare_face_base64(selfie, reference))

    liveness = results["liveness"]
    face_match = results["face_match"]
    if liveness.get("performed") and liveness.get("result") == "spoof":
        results["status"] = "rejected"
        results["rejection_reason"] = "liveness probe reported a spoof"
    elif face_match.get("performed") and face_match.get("match") is False:
        results["status"] = "rejected"
        results["rejection_reason"] = "face does not match the reference portrait"
    elif (face_match.get("performed") and face_match.get("match") is True
          and (not check_liveness or liveness.get("result") == "live")):
        results["status"] = "verified"
    return results


def _is_image_kind(kind: str) -> bool:
    return kind in ("jpeg", "png", "gif", "webp")


def _cv_forgery_analysis(data: bytes, kind: str) -> dict | None:
    """Run the local cv2 integrity layer on image payloads. Returns None when
    the payload is not an image or the engine is unavailable — callers keep
    the honest structural-only response in that case."""
    if not (_is_image_kind(kind) and docverification.DOCVERIFICATION_AVAILABLE):
        return None
    return docverification.local_cv.analyze_document_image(data)


def _document_checks(data: bytes, document_type: str, check_forgery: bool) -> dict:
    kind = _sniff_type(data)
    checks = [
        {"check": "non_empty", "passed": len(data) > 0},
        {"check": "size_within_limit", "passed": len(data) <= MAX_UPLOAD_BYTES},
        {"check": "recognized_format", "passed": kind != "unknown"},
    ]
    forgery = {
        "performed": check_forgery,
        "forgery_detected": False,
        "confidence": None,
        "reason": "automated forgery model not configured; structural checks "
                  "only — document routed to manual review",
        "structural_checks": checks,
    } if check_forgery else {"performed": False, "reason": "check_forgery=false"}

    if check_forgery:
        analysis = _cv_forgery_analysis(data, kind)
        if analysis is not None and analysis["decode_ok"]:
            # Real cv2 integrity analysis ran: moire (screen-replay), border
            # and texture signals. confidence = screen-replay integrity —
            # i.e. confidence that this is NOT a photograph of a screen.
            replay = analysis["screen_replay_integrity"]
            forgery = {
                "performed": True,
                "forgery_detected": replay is not None
                and replay < docverification.pipeline.SCREEN_REPLAY_REJECT_THRESHOLD,
                "confidence": replay,
                "reason": "local cv2 integrity analysis (moire FFT, border, "
                          "colour texture) performed; deep ML forgery model "
                          "not configured",
                "cv_analysis": analysis,
                "structural_checks": checks,
            }
        elif analysis is not None:
            forgery["reason"] = ("document bytes could not be decoded as an "
                                 "image; structural checks only")
    return {
        "document_type": document_type,
        "detected_format": kind,
        "size_bytes": len(data),
        "checks": checks,
        "forgery": forgery,
        "structurally_valid": all(c["passed"] for c in checks),
    }


def _persist_document_verdict(db: Database, result: dict, data: bytes,
                              principal: Principal) -> None:
    """Audit-trail persistence for document verdicts (canonical PG schema:
    database/20260929_doc_verification.sql). Hash-only: the raw document is
    NEVER stored, just its SHA-256, the verdict status, and the per-layer
    provenance so a reviewer can see exactly which layers ran."""
    try:
        pipeline_verdict = result.get("pipeline") or {}
        db.execute(
            "INSERT INTO document_verifications (id, actor_sub, document_type,"
            " detected_format, sha256, size_bytes, status, quality,"
            " screen_replay_integrity, printed_cutout_integrity,"
            " provenance_json, reasons_json, created_at)"
            " VALUES (:id, :actor, :dt, :fmt, :sha, :sz, :st, :q, :sri, :pci,"
            " :prov, :reasons, :now)",
            {
                "id": result["verification_id"], "actor": principal.sub,
                "dt": result["document_type"], "fmt": result["detected_format"],
                "sha": hashlib.sha256(data).hexdigest(),
                "sz": result["size_bytes"], "st": result["status"],
                "q": pipeline_verdict.get("quality"),
                "sri": (pipeline_verdict.get("authenticity") or {}).get(
                    "screen_replay_integrity"),
                "pci": (pipeline_verdict.get("authenticity") or {}).get(
                    "printed_cutout_integrity"),
                "prov": json.dumps(pipeline_verdict.get("provenance", [])),
                "reasons": json.dumps(pipeline_verdict.get("reasons", [])),
                "now": result["timestamp"],
            },
        )
    except Exception as exc:  # persistence must never break verification
        logger.error("document verdict persistence failed (id=%s): %s",
                     result.get("verification_id"), exc)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(title="FraudFusion KYC API", version="1.0.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "healthy", "service": "kyc-api", "timestamp": _now()}

    # ------------------------- KYC verification ----------------------------

    @app.post("/api/v1/kyc/verify/basic", response_model=KYCResponse)
    def verify_basic(payload: BasicKYCRequest,
                     principal: Principal = Depends(get_current_principal),
                     db: Database = Depends(get_db)) -> KYCResponse:
        return _run_verification(db, principal, "basic", payload)

    @app.post("/api/v1/kyc/verify/enhanced", response_model=KYCResponse)
    def verify_enhanced(payload: EnhancedKYCRequest,
                        principal: Principal = Depends(get_current_principal),
                        db: Database = Depends(get_db)) -> KYCResponse:
        return _run_verification(db, principal, "enhanced", payload)

    @app.post("/api/v1/kyc/verify/premium", response_model=KYCResponse)
    def verify_premium(payload: PremiumKYCRequest,
                       principal: Principal = Depends(get_current_principal),
                       db: Database = Depends(get_db)) -> KYCResponse:
        return _run_verification(db, principal, "premium", payload)

    @app.get("/api/v1/kyc/status/{request_id}")
    def kyc_status(request_id: str,
                   principal: Principal = Depends(get_current_principal),
                   db: Database = Depends(get_db)) -> dict:
        row = db.query_one("SELECT * FROM kyc_requests WHERE id = :id", {"id": request_id})
        if not row:
            raise HTTPException(status_code=404, detail="kyc request not found")
        # Address-verification recency is customer-level: latest request with
        # address evidence wins, regardless of which request this status is for.
        addr_row = db.query_one(
            "SELECT address_verification_method, address_verified_at FROM kyc_requests"
            " WHERE customer_id = :cid AND address_verified_at IS NOT NULL"
            " ORDER BY address_verified_at DESC LIMIT 1",
            {"cid": row["customer_id"]},
        )
        address_verification = tiers.address_review_required(
            row["tier"],
            addr_row["address_verification_method"] if addr_row else None,
            addr_row["address_verified_at"] if addr_row else None,
        )
        return {
            "request_id": row["id"],
            "customer_id": row["customer_id"],
            "status": row["status"],
            "verification_level": row["level"],
            "tier": row["tier"],
            "decision": row["decision"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "verification_results": json.loads(row["results_json"]),
            "address_verification": address_verification,
            "timestamp": str(row.get("updated_at") or ""),
        }

    # ------------------------- counterparty rigor registry -----------------

    def _require_kyc_admin(principal: Principal) -> None:
        if "kyc_admin" not in principal.roles:
            raise HTTPException(status_code=403, detail="kyc_admin role required")

    @app.post("/api/v1/kyc/admin/counterparty-rigor", status_code=201)
    def upsert_counterparty_rigor(payload: CounterpartyRigorEntry,
                                  principal: Principal = Depends(get_current_principal),
                                  db: Database = Depends(get_db)) -> dict:
        """Admin-managed registry upsert: record an institution's onboarding
        verification rigor with a source note (auditability)."""
        _require_kyc_admin(principal)
        code = payload.institution_code.strip()
        db.execute(
            "INSERT INTO counterparty_rigor_registry (institution_code, institution_name,"
            " rigor_level, source_note, updated_at) VALUES (:c, :n, :r, :s, :now)"
            " ON CONFLICT (institution_code) DO UPDATE SET institution_name = :n,"
            " rigor_level = :r, source_note = :s, updated_at = :now",
            {"c": code, "n": payload.institution_name.strip(),
             "r": payload.rigor_level, "s": payload.source_note, "now": _now()},
        )
        logger.info("counterparty rigor upserted: %s -> %s by=%s",
                    code, payload.rigor_level, principal.sub)
        return counterparty.lookup_rigor(db, code)

    @app.get("/api/v1/kyc/counterparty-rigor/{institution_code}")
    def get_counterparty_rigor(institution_code: str,
                               principal: Principal = Depends(get_current_principal),
                               db: Database = Depends(get_db)) -> dict:
        """Look up rigor by institution code. Fail-closed: no entry -> rigor
        'unknown' with an explicit reason, never silently strong."""
        return counterparty.lookup_rigor(db, institution_code)

    # ------------------------- re-KYC / periodic review / appeals ---------

    @app.get("/api/v1/kyc/reviews/due")
    def reviews_due(limit: int = 100,
                    principal: Principal = Depends(get_current_principal),
                    db: Database = Depends(get_db)) -> dict:
        """Periodic review scheduler read path: pending reviews whose due date
        has arrived. Overdue pending rows are marked 'overdue' (loudly, so a
        missed SLA is visible rather than silently pending forever)."""
        now = _now()
        db.execute(
            "UPDATE kyc_review_schedule SET status = 'overdue' WHERE status = 'pending'"
            " AND due_at < :now",
            {"now": now},
        )
        rows = db.query(
            "SELECT * FROM kyc_review_schedule WHERE status IN ('pending', 'overdue')"
            " AND due_at <= :now ORDER BY due_at LIMIT :lim",
            {"now": now, "lim": max(1, min(limit, 500))},
        )
        return {
            "due": [
                {
                    "id": r["id"], "customer_id": r["customer_id"],
                    "review_type": r["review_type"], "tier": r.get("tier"),
                    "due_at": str(r["due_at"]), "status": r["status"],
                    "reason": r.get("reason"),
                }
                for r in rows
            ],
            "count": len(rows),
            "as_of": now,
        }

    @app.post("/api/v1/kyc/{customer_id}/rekyc", status_code=201)
    def trigger_rekyc(customer_id: str, payload: RekycRequest,
                      principal: Principal = Depends(get_current_principal),
                      db: Database = Depends(get_db)) -> dict:
        """Trigger a re-KYC: the customer's current verification is superseded
        (a new request row in 'received'/'pending' state with a deadline) and
        a 'rekyc' review is scheduled at the deadline."""
        original = _latest_request(db, customer_id)
        if not original:
            raise HTTPException(status_code=404, detail="no existing kyc request for customer")
        now = _now()
        deadline = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() + payload.deadline_days * 86400,
            timezone.utc,
        ).isoformat()
        rekyc_id = uuid.uuid4().hex
        db.execute(
            "INSERT INTO kyc_requests (id, customer_id, level, tier, status, decision,"
            " risk_score, risk_level, results_json, actor_sub, rekyc_of, rekyc_reason,"
            " rekyc_deadline, created_at, updated_at)"
            " VALUES (:id, :cid, :level, :tier, 'received', 'pending', 0, 'low', '{}', :actor,"
            " :of, :reason, :deadline, :now, :now)",
            {"id": rekyc_id, "cid": customer_id, "level": original["level"],
             "tier": original["tier"], "actor": principal.sub, "of": original["id"],
             "reason": payload.reason, "deadline": deadline, "now": now},
        )
        db.execute(
            ("INSERT OR IGNORE INTO kyc_review_schedule (customer_id, review_type, tier, due_at,"
             " reason) VALUES (:cid, 'rekyc', :tier, :due, :reason)" if not db._is_pg else
             "INSERT INTO kyc_review_schedule (customer_id, review_type, tier, due_at, reason)"
             " VALUES (:cid, 'rekyc', :tier, :due, :reason) ON CONFLICT DO NOTHING"),
            {"cid": customer_id, "tier": original["tier"], "due": deadline,
             "reason": payload.reason},
        )
        logger.info("rekyc triggered: customer=%s rekyc=%s of=%s by=%s deadline=%s",
                    customer_id, rekyc_id, original["id"], principal.sub, deadline)
        return {
            "rekyc_id": rekyc_id,
            "customer_id": customer_id,
            "supersedes": original["id"],
            "status": "pending",
            "tier": original["tier"],
            "reason": payload.reason,
            "deadline": deadline,
            "timestamp": now,
        }

    # ------------------------- appeals (independent reviewer) --------------

    def _appeal_view(row: dict) -> dict:
        return {
            "appeal_id": row["id"],
            "customer_id": row["customer_id"],
            "kyc_request_id": row.get("kyc_request_id"),
            "grounds": row["grounds"],
            "status": row["status"],
            "submitted_by": row["submitted_by"],
            "original_reviewer": row.get("original_reviewer"),
            "decided_by": row.get("decided_by"),
            "decision_reason": row.get("decision_reason"),
            "created_at": str(row.get("created_at") or ""),
            "updated_at": str(row.get("updated_at") or ""),
        }

    @app.post("/api/v1/kyc/{customer_id}/appeals", status_code=201)
    def submit_appeal(customer_id: str, payload: AppealRequest,
                      principal: Principal = Depends(get_current_principal),
                      db: Database = Depends(get_db)) -> dict:
        target = None
        if payload.kyc_request_id:
            target = db.query_one(
                "SELECT * FROM kyc_requests WHERE id = :id AND customer_id = :cid",
                {"id": payload.kyc_request_id, "cid": customer_id},
            )
        else:
            target = _latest_request(db, customer_id)
        if not target:
            raise HTTPException(status_code=404, detail="no kyc request to appeal")
        if target["decision"] not in ("rejected", "manual_review"):
            raise HTTPException(
                status_code=409,
                detail=f"only rejected/manual_review decisions can be appealed (current: {target['decision']})",
            )
        appeal_id = uuid.uuid4().hex
        db.execute(
            "INSERT INTO kyc_appeals (id, customer_id, kyc_request_id, grounds, submitted_by,"
            " original_reviewer, status, created_at, updated_at)"
            " VALUES (:id, :cid, :rid, :grounds, :by, :orig, 'pending', :now, :now)",
            {"id": appeal_id, "cid": customer_id, "rid": target["id"],
             "grounds": payload.grounds, "by": principal.sub,
             "orig": target.get("actor_sub") or None, "now": _now()},
        )
        logger.info("appeal submitted: id=%s customer=%s request=%s by=%s",
                    appeal_id, customer_id, target["id"], principal.sub)
        return _appeal_view(db.query_one("SELECT * FROM kyc_appeals WHERE id = :id",
                                         {"id": appeal_id}))

    @app.get("/api/v1/kyc/appeals/{appeal_id}")
    def get_appeal(appeal_id: str,
                   principal: Principal = Depends(get_current_principal),
                   db: Database = Depends(get_db)) -> dict:
        row = db.query_one("SELECT * FROM kyc_appeals WHERE id = :id", {"id": appeal_id})
        if not row:
            raise HTTPException(status_code=404, detail="appeal not found")
        return _appeal_view(row)

    @app.post("/api/v1/kyc/appeals/{appeal_id}/decision")
    def decide_appeal(appeal_id: str, payload: AppealDecisionRequest,
                      principal: Principal = Depends(get_current_principal),
                      db: Database = Depends(get_db)) -> dict:
        """Decide an appeal. Independence rule (also enforced by the
        kyc_appeals_independence_guard Postgres trigger): the decider can
        never be the reviewer who made the original decision."""
        row = db.query_one("SELECT * FROM kyc_appeals WHERE id = :id", {"id": appeal_id})
        if not row:
            raise HTTPException(status_code=404, detail="appeal not found")
        if row["status"] not in ("pending", "under_review"):
            raise HTTPException(status_code=409, detail=f"appeal already {row['status']}")
        if row.get("original_reviewer") and principal.sub == row["original_reviewer"]:
            raise HTTPException(
                status_code=409,
                detail="appeal independence: the original reviewer cannot decide this appeal",
            )
        db.execute(
            "UPDATE kyc_appeals SET status = :st, decision_reason = :reason,"
            " decided_by = :by, updated_at = :now WHERE id = :id",
            {"st": payload.decision, "reason": payload.reason, "by": principal.sub,
             "now": _now(), "id": appeal_id},
        )
        if payload.decision == "overturned" and row.get("kyc_request_id"):
            # The original adverse decision no longer stands; route the
            # customer back to manual review for a fresh decision.
            db.execute(
                "UPDATE kyc_requests SET decision = 'manual_review', updated_at = :now"
                " WHERE id = :rid",
                {"now": _now(), "rid": row["kyc_request_id"]},
            )
        logger.info("appeal decided: id=%s decision=%s by=%s", appeal_id,
                    payload.decision, principal.sub)
        return _appeal_view(db.query_one("SELECT * FROM kyc_appeals WHERE id = :id",
                                         {"id": appeal_id}))

    # ------------------------- Biometric ----------------------------------

    @app.post("/api/v1/biometric/verify")
    def biometric_verify(payload: BiometricVerifyRequest,
                         principal: Principal = Depends(get_current_principal)) -> dict:
        selfie = _decode_base64_image(payload.selfie_image_base64, "selfie_image_base64")
        reference = (
            _decode_base64_image(payload.reference_image_base64, "reference_image_base64")
            if payload.reference_image_base64
            else None
        )
        return _biometric_response(selfie, reference, payload.check_liveness)

    @app.post("/api/v1/biometric/verify/upload")
    async def biometric_verify_upload(
        selfie: UploadFile = File(...),
        reference: UploadFile | None = File(default=None),
        check_liveness: bool = Form(default=True),
        principal: Principal = Depends(get_current_principal),
    ) -> dict:
        selfie_data = await _read_upload(selfie)
        reference_data = await _read_upload(reference) if reference else None
        return _biometric_response(selfie_data, reference_data, check_liveness)

    @app.post("/api/v1/biometric/liveness")
    async def biometric_liveness(
        image: UploadFile = File(...),
        principal: Principal = Depends(get_current_principal),
    ) -> dict:
        data = await _read_upload(image)
        response = {
            "check_id": uuid.uuid4().hex,
            "image_format": _sniff_type(data),
            "performed": False,
            "result": "not_evaluated",
            "reason": "liveness detection model not configured; capture routed "
                      "to manual review",
            "timestamp": _now(),
        }
        idv = (docverification.get_idv_adapter()
               if docverification.DOCVERIFICATION_AVAILABLE else None)
        if idv is not None and idv.available:
            response.update(_idv_liveness_result(idv.face_liveness_base64(data)))
        return response

    @app.post("/api/v1/biometric/face-match")
    async def biometric_face_match(
        image1: UploadFile = File(...),
        image2: UploadFile = File(...),
        principal: Principal = Depends(get_current_principal),
    ) -> dict:
        data1 = await _read_upload(image1)
        data2 = await _read_upload(image2)
        response = {
            "match_id": uuid.uuid4().hex,
            "performed": False,
            "match": None,
            "score": None,
            "image1_format": _sniff_type(data1),
            "image2_format": _sniff_type(data2),
            "reason": "face-match model not configured (no biometric embedding "
                      "service wired); routed to manual review",
            "timestamp": _now(),
        }
        idv = (docverification.get_idv_adapter()
               if docverification.DOCVERIFICATION_AVAILABLE else None)
        if idv is not None and idv.available:
            response.update(_idv_face_match_result(
                idv.compare_face_base64(data1, data2)))
        return response

    # ------------------------- Document ------------------------------------

    @app.post("/api/v1/document/verify")
    async def document_verify(
        document: UploadFile = File(...),
        document_type: str = Form(...),
        check_forgery: bool = Form(default=True),
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        data = await _read_upload(document)
        result = _document_checks(data, document_type, check_forgery)
        result["verification_id"] = uuid.uuid4().hex
        kind = result["detected_format"]
        if _is_image_kind(kind) and docverification.DOCVERIFICATION_AVAILABLE:
            # Full layered pipeline: local cv2 forensics -> OCR (when
            # available) -> VLM structured extraction (when available), with
            # per-layer provenance. The pipeline status drives the verdict.
            verdict = docverification.pipeline.verify_document(
                data, document_type, docverification.build_backends())
            result["pipeline"] = verdict
            result["status"] = verdict["status"]
        else:
            result["status"] = (
                "manual_review" if result["structurally_valid"] else "rejected"
            )
        result["timestamp"] = _now()
        _persist_document_verdict(db, result, data, principal)
        return result

    @app.post("/api/v1/document/ocr")
    async def document_ocr(
        document: UploadFile = File(...),
        document_type: str = Form(...),
        principal: Principal = Depends(get_current_principal),
    ) -> dict:
        data = await _read_upload(document)
        kind = _sniff_type(data)
        response = {
            "document_type": document_type,
            "detected_format": kind,
            "status": "unavailable",
            "extracted_fields": {},
            "reason": "OCR engine not configured (no Tesseract/OCR service "
                      "wired for this deployment)",
            "timestamp": _now(),
        }
        if not docverification.DOCVERIFICATION_AVAILABLE:
            response["reason"] = docverification.DOCVERIFICATION_UNAVAILABLE_REASON
            return response

        backends = docverification.build_backends()
        if kind == "pdf":
            parsed = docverification.pipeline.verify_pdf(data, backends)
            response["provenance"] = parsed["provenance"]
            if parsed["status"] == "ok":
                response.update(status="ok", reason=None,
                                text_blocks=parsed.get("blocks", []),
                                tables=parsed.get("tables", []))
            else:
                response["reason"] = parsed.get("reason")
            return response

        if _is_image_kind(kind):
            reasons = []
            if backends.ocr.available:
                ocr_result = backends.ocr.ocr(data)
                if ocr_result["status"] == "ok":
                    response.update(status="ok", reason=None,
                                    text_lines=ocr_result["lines"],
                                    adapter=ocr_result["adapter"])
                    return response
                reasons.append(f"ocr: {ocr_result.get('reason')}")
            else:
                reasons.append(f"ocr: {backends.ocr.unavailable_reason}")
            if backends.vlm.available:
                vlm_result = backends.vlm.extract(data, document_type)
                if vlm_result["status"] == "ok":
                    response.update(status="ok", reason=None,
                                    extracted_fields=vlm_result["fields"],
                                    adapter=vlm_result["adapter"],
                                    model=vlm_result.get("model"))
                    return response
                reasons.append(f"vlm: {vlm_result.get('reason')}")
            else:
                reasons.append(f"vlm: {backends.vlm.unavailable_reason}")
            response["reason"] = "; ".join(reasons)
            return response

        response["reason"] = "payload is neither an image nor a PDF"
        return response

    @app.post("/api/v1/document/forgery-check")
    async def document_forgery_check(
        document: UploadFile = File(...),
        document_type: str = Form(...),
        principal: Principal = Depends(get_current_principal),
    ) -> dict:
        data = await _read_upload(document)
        result = _document_checks(data, document_type, check_forgery=True)
        return {"check_id": uuid.uuid4().hex, **result["forgery"],
                "detected_format": result["detected_format"],
                "timestamp": _now()}

    @app.post("/api/v1/document/quality-check")
    async def document_quality_check(
        document: UploadFile = File(...),
        principal: Principal = Depends(get_current_principal),
    ) -> dict:
        data = await _read_upload(document)
        kind = _sniff_type(data)
        issues = []
        if kind == "unknown":
            issues.append("unrecognized or corrupt file format")
        if len(data) < 1024:
            issues.append("file suspiciously small (<1KB) — likely unreadable scan")
        response = {
            "check_id": uuid.uuid4().hex,
            "detected_format": kind,
            "size_bytes": len(data),
            "quality": "poor" if issues else "acceptable",
            "issues": issues,
            "timestamp": _now(),
        }
        # Real cv2 quality scoring for image payloads: blur (Laplacian
        # variance), glare, resolution floor — the composite quality and the
        # per-signal scores are reported with provenance.
        analysis = _cv_forgery_analysis(data, kind)
        if analysis is not None and analysis["decode_ok"]:
            response["quality"] = analysis["quality"]
            response["issues"] = sorted(set(issues) |
                                        set(analysis["verdict_reasons"]))
            response["quality_scores"] = analysis["quality_scores"]
            response["screen_replay_integrity"] = \
                analysis["screen_replay_integrity"]
            response["analysis_layer"] = "local_cv"
        elif analysis is not None:
            response["quality"] = "poor"
            response["issues"] = sorted(set(issues) |
                                        set(analysis["verdict_reasons"]))
        return response

    # ------------------------- Screening -----------------------------------

    @app.post("/api/v1/screening/pep")
    def screen_pep(payload: ScreeningRequest,
                   principal: Principal = Depends(get_current_principal),
                   db: Database = Depends(get_db)) -> dict:
        result = screening.screen_pep(db, payload.full_name, payload.date_of_birth,
                                      payload.nationality)
        return {"screening_id": uuid.uuid4().hex, **result, "timestamp": _now()}

    @app.post("/api/v1/screening/sanctions")
    def screen_sanctions(payload: ScreeningRequest,
                         principal: Principal = Depends(get_current_principal),
                         db: Database = Depends(get_db)) -> dict:
        result = screening.screen_sanctions(db, payload.full_name, payload.date_of_birth,
                                            payload.nationality, payload.passport_number)
        return {"screening_id": uuid.uuid4().hex, **result, "timestamp": _now()}

    @app.post("/api/v1/screening/comprehensive")
    def screen_comprehensive(payload: ScreeningRequest,
                             principal: Principal = Depends(get_current_principal),
                             db: Database = Depends(get_db)) -> dict:
        result = screening.comprehensive_screening(db, payload.full_name,
                                                   payload.date_of_birth,
                                                   payload.nationality,
                                                   payload.passport_number)
        return {"screening_id": uuid.uuid4().hex, **result, "timestamp": _now()}

    # ------------------------- Credit bureau -------------------------------

    def _bureau_call(payload: CreditBureauRequest, score_only: bool) -> dict:
        id_check = identity.validate_bvn(payload.bvn)
        if not id_check["format_valid"]:
            raise HTTPException(status_code=422,
                                detail=id_check.get("reason", "invalid BVN"))
        try:
            provider = bureau.validate_provider(payload.provider)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        adapter = bureau.get_adapter()
        fn = adapter.score_only if score_only else adapter.check
        result = fn(payload.bvn, payload.first_name, payload.last_name, provider=provider)
        result["request_id"] = uuid.uuid4().hex
        result["timestamp"] = _now()
        return result

    @app.post("/api/v1/credit-bureau/check")
    def credit_bureau_check(payload: CreditBureauRequest,
                            principal: Principal = Depends(get_current_principal)) -> dict:
        return _bureau_call(payload, score_only=False)

    @app.post("/api/v1/credit-bureau/score-only")
    def credit_bureau_score(payload: CreditBureauRequest,
                            principal: Principal = Depends(get_current_principal)) -> dict:
        return _bureau_call(payload, score_only=True)

    # ------------------------- Risk ----------------------------------------

    @app.post("/api/v1/risk/assess")
    def risk_assess(payload: dict,
                    principal: Principal = Depends(get_current_principal),
                    db: Database = Depends(get_db)) -> dict:
        """Rule-based risk assessment (no ML model wired for this endpoint;
        the scoring basis is returned explicitly)."""
        score = 0.10
        factors = []
        amount = payload.get("amount_ngn") or payload.get("amount") or 0
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            amount = 0.0
        if amount >= 5_000_000:
            score += 0.35
            factors.append("amount>=5M NGN (+0.35)")
        elif amount >= 1_000_000:
            score += 0.20
            factors.append("amount>=1M NGN (+0.20)")
        if payload.get("pep_hit"):
            score += 0.40
            factors.append("pep_hit (+0.40)")
        if payload.get("sanctions_hit"):
            score += 0.85
            factors.append("sanctions_hit (+0.85)")
        country = (payload.get("country") or "").upper()
        if country and country not in ("NG",):
            score += 0.10
            factors.append(f"non-domestic country {country} (+0.10)")
        # Counterparty verification-rigor enrichment: institutions that skip
        # CBN biometric BVN verification ('unverified') or have no registry
        # entry ('unknown', fail-closed) contribute a documented gap flag.
        rigor = counterparty.lookup_rigor(db, payload.get("counterparty_institution"))
        gap = counterparty.risk_enrichment(rigor)
        if gap["flag"]:
            score += gap["contribution"]
            factors.append(gap["factor"])
        score = round(min(score, 1.0), 3)
        return {
            "assessment_id": uuid.uuid4().hex,
            "risk_score": score,
            "risk_level": _risk_level(score),
            "factors": factors,
            "counterparty_verification_gap": gap["flag"],
            "counterparty_rigor": rigor,
            "model": "rules",
            "timestamp": _now(),
        }

    @app.post("/api/v1/risk/fraud-check")
    def fraud_check(payload: FraudCheckRequest,
                    principal: Principal = Depends(get_current_principal),
                    db: Database = Depends(get_db)) -> dict:
        txn = payload.transaction_data or {}
        history = payload.historical_data or []
        score = 0.10
        factors = []
        try:
            amount = float(txn.get("amount_ngn") or txn.get("amount") or 0)
        except (TypeError, ValueError):
            amount = 0.0
        amounts = []
        for h in history:
            try:
                amounts.append(float(h.get("amount_ngn") or h.get("amount") or 0))
            except (TypeError, ValueError, AttributeError):
                continue
        if amounts:
            avg = sum(amounts) / len(amounts)
            if avg > 0 and amount > 5 * avg:
                score += 0.35
                factors.append(f"amount {amount:.0f} is >5x historical average (+0.35)")
        if len(history) >= 20:
            score += 0.20
            factors.append("high transaction velocity in history window (+0.20)")
        if txn.get("channel") == "card_not_present":
            score += 0.10
            factors.append("card-not-present channel (+0.10)")
        # Counterparty verification-rigor enrichment (same documented rule as
        # /risk/assess): 'unverified'/'unknown' counterparty institutions add
        # the counterparty_verification_gap contribution.
        rigor = counterparty.lookup_rigor(db, txn.get("counterparty_institution"))
        gap = counterparty.risk_enrichment(rigor)
        if gap["flag"]:
            score += gap["contribution"]
            factors.append(gap["factor"])
        score = round(min(score, 1.0), 3)
        return {
            "check_id": uuid.uuid4().hex,
            "customer_id": payload.customer_id,
            "fraud_score": score,
            "risk_level": _risk_level(score),
            "is_fraud_suspected": score >= 0.5,
            "factors": factors,
            "counterparty_verification_gap": gap["flag"],
            "counterparty_rigor": rigor,
            "model": "rules",
            "timestamp": _now(),
        }

    @app.post("/api/v1/risk/behavioral-analysis")
    def behavioral_analysis(payload: BehavioralAnalysisRequest,
                            principal: Principal = Depends(get_current_principal)) -> dict:
        data = payload.behavioral_data or {}
        score = 0.10
        factors = []
        failed_logins = int(data.get("failed_logins_24h") or 0)
        if failed_logins >= 5:
            score += 0.30
            factors.append(f"failed_logins_24h={failed_logins} (+0.30)")
        if data.get("new_device"):
            score += 0.15
            factors.append("new device (+0.15)")
        hour = data.get("login_hour")
        if isinstance(hour, int) and (hour < 6 or hour > 22):
            score += 0.10
            factors.append(f"off-hours activity hour={hour} (+0.10)")
        score = round(min(score, 1.0), 3)
        return {
            "analysis_id": uuid.uuid4().hex,
            "customer_id": payload.customer_id,
            "behavior_score": score,
            "risk_level": _risk_level(score),
            "anomalous": score >= 0.5,
            "factors": factors,
            "model": "rules",
            "timestamp": _now(),
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8086")))
