"""FraudFusion Backoffice API (:8087).

Implements the /api/v1/backoffice/* + /api/v1/auth/* contract consumed by the
backoffice UI (implementations/backoffice-ui/src/services/api.ts). All routes
are DB-backed (no mock fallbacks), tenant-scoped via the Keycloak `tenant_id`
claim, and every mutation is written to the hash-chained backoffice_audit_ledger.

Run: uvicorn app.main:app --host 0.0.0.0 --port 8087
"""

from __future__ import annotations

import csv
import io
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app import audit as audit_ledger
from app.auth import (
    KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET,
    KEYCLOAK_REALM,
    KEYCLOAK_URL,
    Principal,
    get_principal,
    require_ops,
)
from app.db import Database, get_db

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("backoffice-api")

SERVICE_NAME = "backoffice-api"

# State machines (enforced here; CHECK constraints backstop in the schema).
ALERT_TRANSITIONS = {
    "open": {"investigating", "false_positive"},
    "investigating": {"resolved", "false_positive"},
    "resolved": set(),
    "false_positive": set(),
}
REVIEW_TRANSITIONS = {
    "pending": {"in_review", "approved", "rejected", "escalated", "needs_info"},
    "in_review": {"approved", "rejected", "escalated", "needs_info"},
    "needs_info": {"in_review"},
    "escalated": {"in_review", "approved", "rejected"},
    "approved": set(),
    "rejected": set(),
}
JOURNEY_CANCELLABLE = {"running", "paused"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Request models (contract: backoffice-ui src/types/index.ts)
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    password: str


class ReviewDecisionRequest(BaseModel):
    review_id: str
    decision: str = Field(pattern="^(approved|rejected|needs_info|escalated)$")
    reason: str = Field(min_length=3, max_length=2000)
    notes: Optional[str] = None


class AssignRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=255)


class OverrideRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=3, max_length=2000)


class FraudAlertUpdate(BaseModel):
    status: str = Field(pattern="^(investigating|resolved|false_positive)$")
    note: Optional[str] = None
    assign_to: Optional[str] = None


class JourneyRetryRequest(BaseModel):
    step_number: int = Field(ge=1)


class CancelJourneyRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class RevokeSessionsRequest(BaseModel):
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Row -> UI view mappers (exact camelCase contract)
# ---------------------------------------------------------------------------

def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _review_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "document_id": row["document_id"],
        "type": row["document_type"],
        "status": row["status"],
        "customer_id": row.get("customer_id"),
        "customer_name": row.get("customer_name"),
        "submitted_at": _s(row.get("submitted_at")),
        "reviewed_at": _s(row.get("reviewed_at")) or None,
        "reviewer_id": row.get("reviewer_id"),
        "ocr_result": Database.as_dict(row.get("ocr_result")) or None,
        "fraud_indicators": Database.as_list(row.get("fraud_indicators")),
        "risk_score": row.get("risk_score", 0),
    }


def _kyc_view(row: dict) -> dict:
    results = Database.as_dict(row.get("results_json"))
    return {
        "id": row["id"],
        "customer_id": row["customer_id"],
        "customer_name": results.get("customer_name") or None,
        "status": row["decision"],
        "tier": row["tier"],
        "risk_score": row.get("risk_score", 0),
        "risk_level": row.get("risk_level", "low"),
        "submitted_at": _s(row.get("created_at")),
        "completed_at": _s(row.get("updated_at")) if row.get("status") == "completed" else None,
        "rejection_reason": row.get("override_reason") or results.get("reason"),
        "reviewed_by": row.get("override_by") or row.get("actor_sub") or None,
    }


def _alert_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "type": row["alert_type"],
        "severity": row["severity"],
        "status": row["status"],
        "customer_id": row.get("customer_id"),
        "customer_name": row.get("customer_name"),
        "description": row.get("description"),
        "amount": float(row["amount"]) if row.get("amount") is not None else None,
        "currency": row.get("currency"),
        "location": row.get("location"),
        "risk_score": row.get("risk_score", 0),
        "indicators": Database.as_list(row.get("indicators")),
        "created_at": _s(row.get("detected_at")),
        "assigned_to": row.get("assigned_to"),
    }


def _execution_view(row: dict, steps: list[dict] | None = None) -> dict:
    return {
        "id": row["id"],
        "journey_id": row["journey_id"],
        "journey_name": row["journey_name"],
        "customer_id": row.get("customer_id"),
        "status": row["status"],
        "started_at": _s(row.get("started_at")),
        "completed_at": _s(row.get("completed_at")) or None,
        "current_step": row.get("current_step", 0),
        "total_steps": row.get("total_steps", 0),
        "steps": [
            {
                "step_number": st["step_number"],
                "name": st["name"],
                "status": st["status"],
                "started_at": _s(st.get("started_at")) or None,
                "completed_at": _s(st.get("completed_at")) or None,
                "result": Database.as_dict(st.get("result")) or None,
                "error": st.get("error"),
            }
            for st in (steps or [])
        ],
        "final_decision": row.get("final_decision"),
        "risk_score": row.get("risk_score"),
    }


def _audit_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "timestamp": _s(row.get("created_at")),
        "event_type": row["event_type"],
        "severity": row["severity"],
        "actor_id": row.get("actor_id"),
        "actor_type": row.get("actor_type"),
        "ip_address": row.get("actor_ip"),
        "resource_type": row["resource_type"],
        "resource_id": row["resource_id"],
        "action": row["action"],
        "outcome": row["outcome"],
        "details": Database.as_dict(row.get("details")),
    }


def _page_params(page: int, limit: int) -> tuple[int, int, int]:
    page = max(1, page)
    limit = max(1, min(limit, 200))
    return page, limit, (page - 1) * limit


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _audit(db: Database, principal: Principal, request: Request, *,
           event_type: str, resource_type: str, resource_id: str, action: str,
           severity: str = "info", outcome: str = "success",
           details: dict | None = None) -> None:
    audit_ledger.append_event(
        db, tenant_id=principal.tenant_id, event_type=event_type, severity=severity,
        actor_id=principal.sub, actor_type="user", actor_ip=_client_ip(request),
        resource_type=resource_type, resource_id=resource_id, action=action,
        outcome=outcome, details=details or {},
    )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(title="FraudFusion Backoffice API", version="1.0.0")

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "healthy",
            "service": SERVICE_NAME,
            "auth": "keycloak-jwks" if KEYCLOAK_URL else "unconfigured (fail-closed)",
            "timestamp": _now(),
        }

    # --------------------------- /auth/* -----------------------------------

    @app.post("/api/v1/auth/login")
    def login(payload: LoginRequest, db: Database = Depends(get_db)) -> dict:
        """Keycloak password grant. Fail-closed: 503 when the IdP is not
        configured; 401 on rejected credentials. No mock sessions."""
        if not KEYCLOAK_URL:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="authentication provider not configured")
        try:
            resp = httpx.post(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": KEYCLOAK_CLIENT_ID,
                    "client_secret": KEYCLOAK_CLIENT_SECRET,
                    "username": payload.email,
                    "password": payload.password,
                },
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            logger.error("keycloak token endpoint unreachable: %s", exc)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="authentication provider unreachable")
        if resp.status_code != 200:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="invalid credentials")
        token = resp.json()["access_token"]
        # Decode without re-verification (we just minted it against the IdP)
        # to build the user view.
        import jwt as pyjwt

        claims = pyjwt.decode(token, options={"verify_signature": False})
        return {
            "token": token,
            "user": {
                "id": claims.get("sub", ""),
                "email": claims.get("email", payload.email),
                "name": claims.get("name", ""),
                "role": next(iter((claims.get("realm_access") or {}).get("roles") or []), ""),
            },
        }

    @app.post("/api/v1/auth/logout")
    def logout(request: Request, principal: Principal = Depends(get_principal),
               db: Database = Depends(get_db)) -> dict:
        """Revoke the current token's session (stateless JWT => jti tombstone
        checked by get_principal)."""
        if principal.jti:
            db.execute(
                ("INSERT OR IGNORE INTO backoffice_session_revocations"
                 " (tenant_id, jti, sub, revoked_by, reason) VALUES (:t, :j, :s, :by, :r)"
                 if not db._is_pg else
                 "INSERT INTO backoffice_session_revocations (tenant_id, jti, sub, revoked_by,"
                 " reason) VALUES (:t, :j, :s, :by, :r) ON CONFLICT DO NOTHING"),
                {"t": principal.tenant_id, "j": principal.jti, "s": principal.sub,
                 "by": principal.sub, "r": "logout"},
            )
            _audit(db, principal, request, event_type="auth.logout",
                   resource_type="session", resource_id=principal.jti, action="logout")
        return {"ok": True}

    @app.get("/api/v1/auth/me")
    def me(principal: Principal = Depends(get_principal)) -> dict:
        return {
            "id": principal.sub,
            "email": principal.email,
            "name": principal.name,
            "role": next(iter(sorted(principal.roles)), ""),
            "tenant_id": principal.tenant_id,
        }

    # --------------------------- dashboard ---------------------------------

    @app.get("/api/v1/backoffice/dashboard/stats")
    def dashboard_stats(principal: Principal = Depends(get_principal),
                        db: Database = Depends(get_db)) -> dict:
        t = principal.tenant_id
        kyc_total = db.query_one(
            "SELECT COUNT(*) c FROM kyc_requests WHERE tenant_id = :t", {"t": t})["c"]
        kyc_pending = db.query_one(
            "SELECT COUNT(*) c FROM kyc_requests WHERE tenant_id = :t AND decision = 'pending'",
            {"t": t})["c"]
        alerts_active = db.query_one(
            "SELECT COUNT(*) c FROM fraud_alerts WHERE tenant_id = :t"
            " AND status IN ('open', 'investigating')", {"t": t})["c"]
        decided = db.query_one(
            "SELECT COUNT(*) c FROM fraud_alerts WHERE tenant_id = :t"
            " AND status IN ('resolved', 'false_positive')", {"t": t})["c"]
        fraud_confirmed = db.query_one(
            "SELECT COUNT(*) c FROM fraud_alerts WHERE tenant_id = :t AND status = 'resolved'",
            {"t": t})["c"]
        docs_reviewed = db.query_one(
            "SELECT COUNT(*) c FROM document_reviews WHERE tenant_id = :t"
            " AND status IN ('approved', 'rejected')", {"t": t})["c"]
        docs_pending = db.query_one(
            "SELECT COUNT(*) c FROM document_reviews WHERE tenant_id = :t"
            " AND status IN ('pending', 'in_review')", {"t": t})["c"]
        journeys_active = db.query_one(
            "SELECT COUNT(*) c FROM journey_executions WHERE tenant_id = :t"
            " AND status = 'running'", {"t": t})["c"]
        if db._is_pg:
            journeys_failed = db.query_one(
                "SELECT COUNT(*) c FROM journey_executions WHERE tenant_id = :t"
                " AND status = 'failed' AND updated_at >= now() - INTERVAL '1 day'",
                {"t": t})["c"]
            avg = db.query_one(
                "SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at - created_at))), 0) a"
                " FROM kyc_requests WHERE tenant_id = :t AND status = 'completed'",
                {"t": t})["a"]
            trend = db.query(
                "SELECT to_char(detected_at, 'YYYY-MM-DD') d, COUNT(*) c FROM fraud_alerts"
                " WHERE tenant_id = :t AND detected_at >= now() - INTERVAL '7 days'"
                " GROUP BY 1 ORDER BY 1", {"t": t})
        else:
            journeys_failed = db.query_one(
                "SELECT COUNT(*) c FROM journey_executions WHERE tenant_id = :t"
                " AND status = 'failed'"
                " AND updated_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')",
                {"t": t})["c"]
            avg = db.query_one(
                "SELECT COALESCE(AVG((julianday(updated_at) - julianday(created_at)) * 86400.0), 0) a"
                " FROM kyc_requests WHERE tenant_id = :t AND status = 'completed'",
                {"t": t})["a"]
            trend = db.query(
                "SELECT substr(detected_at, 1, 10) d, COUNT(*) c FROM fraud_alerts"
                " WHERE tenant_id = :t"
                " AND detected_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-7 days')"
                " GROUP BY 1 ORDER BY 1", {"t": t})
        kyc_by_status = db.query(
            "SELECT decision s, COUNT(*) c FROM kyc_requests WHERE tenant_id = :t GROUP BY 1",
            {"t": t})
        fraud_by_type = db.query(
            "SELECT alert_type ty, COUNT(*) c FROM fraud_alerts WHERE tenant_id = :t GROUP BY 1",
            {"t": t})
        return {
            "total_kyc_verifications": kyc_total,
            "pending_kyc": kyc_pending,
            "active_fraud_alerts": alerts_active,
            "fraud_rate": round(fraud_confirmed / decided, 4) if decided else 0.0,
            "avg_processing_time": round(float(avg or 0), 1),
            "total_documents_reviewed": docs_reviewed,
            "pending_document_reviews": docs_pending,
            "active_journeys": journeys_active,
            "failed_journeys_24h": journeys_failed,
            "alerts_trend": [{"date": r["d"], "count": r["c"]} for r in trend],
            "kyc_by_status": [{"status": r["s"], "count": r["c"]} for r in kyc_by_status],
            "fraud_by_type": [{"type": r["ty"], "count": r["c"]} for r in fraud_by_type],
        }

    # --------------------------- document reviews --------------------------

    @app.get("/api/v1/backoffice/documents/reviews")
    def list_document_reviews(
        status_filter: Optional[str] = Query(default=None, alias="status"),
        page: int = 1, limit: int = 20,
        principal: Principal = Depends(get_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        page, limit, offset = _page_params(page, limit)
        where = " WHERE tenant_id = :t"
        params: dict[str, Any] = {"t": principal.tenant_id}
        if status_filter:
            where += " AND status = :st"
            params["st"] = status_filter
        total = db.query_one(f"SELECT COUNT(*) c FROM document_reviews{where}", params)["c"]
        rows = db.query(
            f"SELECT * FROM document_reviews{where} ORDER BY submitted_at DESC"
            f" LIMIT :lim OFFSET :off",
            {**params, "lim": limit, "off": offset})
        return {"reviews": [_review_view(r) for r in rows], "total": total,
                "page": page, "limit": limit,
                "total_pages": (total + limit - 1) // limit}

    @app.get("/api/v1/backoffice/documents/reviews/{review_id}")
    def get_document_review(review_id: str,
                            principal: Principal = Depends(get_principal),
                            db: Database = Depends(get_db)) -> dict:
        row = db.query_one(
            "SELECT * FROM document_reviews WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": review_id})
        if not row:
            raise HTTPException(status_code=404, detail="review not found")
        view = _review_view(row)
        view.update({
            "document_url": f"/backoffice/documents/{row['document_id']}/image"
            if db.query_one("SELECT 1 x FROM document_store WHERE document_id = :d",
                            {"d": row["document_id"]}) else None,
            "decision": row.get("decision"),
            "decision_reason": row.get("decision_reason"),
            "notes": row.get("notes"),
        })
        return view

    @app.get("/api/v1/backoffice/documents/{document_id}/image")
    def get_document_image(document_id: str,
                           principal: Principal = Depends(get_principal),
                           db: Database = Depends(get_db)):
        from fastapi.responses import Response

        row = db.query_one(
            "SELECT content, content_type FROM document_store WHERE tenant_id = :t"
            " AND document_id = :d",
            {"t": principal.tenant_id, "d": document_id})
        if not row:
            raise HTTPException(status_code=404, detail="document image not found")
        content = row["content"]
        return Response(content=bytes(content), media_type=row["content_type"])

    @app.post("/api/v1/backoffice/documents/reviews/decision")
    def decide_document_review(payload: ReviewDecisionRequest,
                               request: Request,
                               principal: Principal = Depends(get_principal),
                               db: Database = Depends(get_db)) -> dict:
        require_ops(principal)
        row = db.query_one(
            "SELECT * FROM document_reviews WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": payload.review_id})
        if not row:
            raise HTTPException(status_code=404, detail="review not found")
        if payload.decision not in REVIEW_TRANSITIONS[row["status"]]:
            raise HTTPException(
                status_code=409,
                detail=f"illegal review transition {row['status']} -> {payload.decision}")
        db.execute(
            "UPDATE document_reviews SET status = :st, decision = :dec,"
            " decision_reason = :reason, notes = :notes, reviewer_id = :rev,"
            " reviewed_at = :now, updated_at = :now WHERE id = :id",
            {"st": payload.decision, "dec": payload.decision, "reason": payload.reason,
             "notes": payload.notes, "rev": principal.sub, "now": _now(),
             "id": payload.review_id})
        _audit(db, principal, request, event_type="document_review.decision",
               resource_type="document_review", resource_id=payload.review_id,
               action=payload.decision,
               severity="warning" if payload.decision == "rejected" else "info",
               details={"reason": payload.reason, "previous_status": row["status"]})
        return _review_view(db.query_one(
            "SELECT * FROM document_reviews WHERE id = :id", {"id": payload.review_id}))

    @app.post("/api/v1/backoffice/documents/reviews/{review_id}/assign")
    def assign_document_review(review_id: str, payload: AssignRequest,
                               request: Request,
                               principal: Principal = Depends(get_principal),
                               db: Database = Depends(get_db)) -> dict:
        require_ops(principal)
        row = db.query_one(
            "SELECT * FROM document_reviews WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": review_id})
        if not row:
            raise HTTPException(status_code=404, detail="review not found")
        new_status = "in_review" if row["status"] == "pending" else row["status"]
        db.execute(
            "UPDATE document_reviews SET reviewer_id = :rev, status = :st,"
            " updated_at = :now WHERE id = :id",
            {"rev": payload.reviewer_id, "st": new_status, "now": _now(), "id": review_id})
        _audit(db, principal, request, event_type="document_review.assign",
               resource_type="document_review", resource_id=review_id,
               action="assign", details={"reviewer_id": payload.reviewer_id})
        return _review_view(db.query_one(
            "SELECT * FROM document_reviews WHERE id = :id", {"id": review_id}))

    # --------------------------- KYC verifications -------------------------

    @app.get("/api/v1/backoffice/kyc/verifications")
    def list_kyc_verifications(
        status_filter: Optional[str] = Query(default=None, alias="status"),
        risk_level: Optional[str] = None,
        page: int = 1, limit: int = 20,
        principal: Principal = Depends(get_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        page, limit, offset = _page_params(page, limit)
        where = " WHERE tenant_id = :t"
        params: dict[str, Any] = {"t": principal.tenant_id}
        if status_filter:
            where += " AND decision = :st"
            params["st"] = status_filter
        if risk_level:
            where += " AND risk_level = :rl"
            params["rl"] = risk_level
        total = db.query_one(f"SELECT COUNT(*) c FROM kyc_requests{where}", params)["c"]
        rows = db.query(
            f"SELECT * FROM kyc_requests{where} ORDER BY created_at DESC"
            f" LIMIT :lim OFFSET :off",
            {**params, "lim": limit, "off": offset})
        return {"verifications": [_kyc_view(r) for r in rows], "total": total,
                "page": page, "limit": limit,
                "total_pages": (total + limit - 1) // limit}

    @app.get("/api/v1/backoffice/kyc/verifications/{verification_id}")
    def get_kyc_verification(verification_id: str,
                             principal: Principal = Depends(get_principal),
                             db: Database = Depends(get_db)) -> dict:
        row = db.query_one(
            "SELECT * FROM kyc_requests WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": verification_id})
        if not row:
            raise HTTPException(status_code=404, detail="verification not found")
        view = _kyc_view(row)
        view["results"] = Database.as_dict(row.get("results_json"))
        return view

    @app.post("/api/v1/backoffice/kyc/verifications/{verification_id}/override")
    def override_kyc(verification_id: str, payload: OverrideRequest,
                     request: Request,
                     principal: Principal = Depends(get_principal),
                     db: Database = Depends(get_db)) -> dict:
        """Approve/reject a KYC verification with a reason. Dual control: the
        overriding approver can never be the original submitter (actor_sub)."""
        require_ops(principal)
        row = db.query_one(
            "SELECT * FROM kyc_requests WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": verification_id})
        if not row:
            raise HTTPException(status_code=404, detail="verification not found")
        if principal.sub == row.get("actor_sub"):
            raise HTTPException(
                status_code=409,
                detail="dual control: the submitter of a verification cannot override it")
        new_decision = "approved" if payload.decision == "approve" else "rejected"
        db.execute(
            "UPDATE kyc_requests SET decision = :dec, status = 'completed',"
            " override_by = :by, override_reason = :reason, override_at = :now,"
            " updated_at = :now WHERE id = :id",
            {"dec": new_decision, "by": principal.sub, "reason": payload.reason,
             "now": _now(), "id": verification_id})
        _audit(db, principal, request, event_type="kyc.override",
               resource_type="kyc_verification", resource_id=verification_id,
               action=f"override_{payload.decision}",
               severity="warning",
               details={"reason": payload.reason, "previous_decision": row["decision"]})
        return _kyc_view(db.query_one(
            "SELECT * FROM kyc_requests WHERE id = :id", {"id": verification_id}))

    # --------------------------- fraud alerts ------------------------------

    @app.get("/api/v1/backoffice/fraud/alerts")
    def list_fraud_alerts(
        severity: Optional[str] = None,
        status_filter: Optional[str] = Query(default=None, alias="status"),
        page: int = 1, limit: int = 20,
        principal: Principal = Depends(get_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        page, limit, offset = _page_params(page, limit)
        where = " WHERE tenant_id = :t"
        params: dict[str, Any] = {"t": principal.tenant_id}
        if severity:
            where += " AND severity = :sev"
            params["sev"] = severity
        if status_filter:
            where += " AND status = :st"
            params["st"] = status_filter
        total = db.query_one(f"SELECT COUNT(*) c FROM fraud_alerts{where}", params)["c"]
        rows = db.query(
            f"SELECT * FROM fraud_alerts{where} ORDER BY detected_at DESC"
            f" LIMIT :lim OFFSET :off",
            {**params, "lim": limit, "off": offset})
        return {"alerts": [_alert_view(r) for r in rows], "total": total,
                "page": page, "limit": limit,
                "total_pages": (total + limit - 1) // limit}

    @app.post("/api/v1/backoffice/fraud/alerts/{alert_id}/status")
    def update_fraud_alert(alert_id: str, payload: FraudAlertUpdate,
                           request: Request,
                           principal: Principal = Depends(get_principal),
                           db: Database = Depends(get_db)) -> dict:
        require_ops(principal)
        row = db.query_one(
            "SELECT * FROM fraud_alerts WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": alert_id})
        if not row:
            raise HTTPException(status_code=404, detail="alert not found")
        if payload.status not in ALERT_TRANSITIONS[row["status"]]:
            raise HTTPException(
                status_code=409,
                detail=f"illegal alert transition {row['status']} -> {payload.status}")
        assign_to = payload.assign_to or (
            principal.sub if payload.status == "investigating" else row.get("assigned_to"))
        resolved_at = _now() if payload.status in ("resolved", "false_positive") else None
        db.execute(
            "UPDATE fraud_alerts SET status = :st, assigned_to = :assign,"
            " resolution_note = COALESCE(:note, resolution_note),"
            " resolved_at = COALESCE(:resolved, resolved_at), updated_at = :now"
            " WHERE id = :id",
            {"st": payload.status, "assign": assign_to, "note": payload.note,
             "resolved": resolved_at, "now": _now(), "id": alert_id})
        _audit(db, principal, request, event_type="fraud_alert.status",
               resource_type="fraud_alert", resource_id=alert_id,
               action=payload.status,
               severity="critical" if payload.status == "resolved" else "info",
               details={"note": payload.note, "previous_status": row["status"]})
        return _alert_view(db.query_one(
            "SELECT * FROM fraud_alerts WHERE id = :id", {"id": alert_id}))

    # --------------------------- journeys ----------------------------------

    @app.get("/api/v1/backoffice/journeys/executions")
    def list_journeys(
        status_filter: Optional[str] = Query(default=None, alias="status"),
        journey_id: Optional[int] = None,
        page: int = 1, limit: int = 20,
        principal: Principal = Depends(get_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        page, limit, offset = _page_params(page, limit)
        where = " WHERE tenant_id = :t"
        params: dict[str, Any] = {"t": principal.tenant_id}
        if status_filter:
            where += " AND status = :st"
            params["st"] = status_filter
        if journey_id is not None:
            where += " AND journey_id = :jid"
            params["jid"] = journey_id
        total = db.query_one(f"SELECT COUNT(*) c FROM journey_executions{where}", params)["c"]
        rows = db.query(
            f"SELECT * FROM journey_executions{where} ORDER BY started_at DESC"
            f" LIMIT :lim OFFSET :off",
            {**params, "lim": limit, "off": offset})
        return {"executions": [_execution_view(r) for r in rows], "total": total,
                "page": page, "limit": limit,
                "total_pages": (total + limit - 1) // limit}

    @app.get("/api/v1/backoffice/journeys/executions/{execution_id}")
    def get_journey(execution_id: str,
                    principal: Principal = Depends(get_principal),
                    db: Database = Depends(get_db)) -> dict:
        row = db.query_one(
            "SELECT * FROM journey_executions WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": execution_id})
        if not row:
            raise HTTPException(status_code=404, detail="execution not found")
        steps = db.query(
            "SELECT * FROM journey_steps WHERE execution_id = :id ORDER BY step_number",
            {"id": execution_id})
        return _execution_view(row, steps)

    @app.post("/api/v1/backoffice/journeys/executions/{execution_id}/retry")
    def retry_journey_step(execution_id: str, payload: JourneyRetryRequest,
                           request: Request,
                           principal: Principal = Depends(get_principal),
                           db: Database = Depends(get_db)) -> dict:
        require_ops(principal)
        row = db.query_one(
            "SELECT * FROM journey_executions WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": execution_id})
        if not row:
            raise HTTPException(status_code=404, detail="execution not found")
        step = db.query_one(
            "SELECT * FROM journey_steps WHERE execution_id = :id AND step_number = :n",
            {"id": execution_id, "n": payload.step_number})
        if not step:
            raise HTTPException(status_code=404, detail="step not found")
        if step["status"] != "failed":
            raise HTTPException(status_code=409,
                                detail="only failed steps can be retried")
        db.execute(
            "UPDATE journey_steps SET status = 'pending', error = NULL WHERE id = :sid",
            {"sid": step["id"]})
        if row["status"] == "failed":
            db.execute(
                "UPDATE journey_executions SET status = 'running', updated_at = :now"
                " WHERE id = :id",
                {"now": _now(), "id": execution_id})
        _audit(db, principal, request, event_type="journey.retry",
               resource_type="journey_execution", resource_id=execution_id,
               action="retry_step", details={"step_number": payload.step_number})
        steps = db.query(
            "SELECT * FROM journey_steps WHERE execution_id = :id ORDER BY step_number",
            {"id": execution_id})
        return _execution_view(db.query_one(
            "SELECT * FROM journey_executions WHERE id = :id", {"id": execution_id}), steps)

    @app.post("/api/v1/backoffice/journeys/executions/{execution_id}/cancel")
    def cancel_journey(execution_id: str, payload: CancelJourneyRequest,
                       request: Request,
                       principal: Principal = Depends(get_principal),
                       db: Database = Depends(get_db)) -> dict:
        require_ops(principal)
        row = db.query_one(
            "SELECT * FROM journey_executions WHERE tenant_id = :t AND id = :id",
            {"t": principal.tenant_id, "id": execution_id})
        if not row:
            raise HTTPException(status_code=404, detail="execution not found")
        if row["status"] not in JOURNEY_CANCELLABLE:
            raise HTTPException(
                status_code=409,
                detail=f"cannot cancel a journey in status {row['status']}")
        db.execute(
            "UPDATE journey_executions SET status = 'cancelled', cancel_reason = :r,"
            " completed_at = :now, updated_at = :now WHERE id = :id",
            {"r": payload.reason, "now": _now(), "id": execution_id})
        _audit(db, principal, request, event_type="journey.cancel",
               resource_type="journey_execution", resource_id=execution_id,
               action="cancel", severity="warning", details={"reason": payload.reason})
        steps = db.query(
            "SELECT * FROM journey_steps WHERE execution_id = :id ORDER BY step_number",
            {"id": execution_id})
        return _execution_view(db.query_one(
            "SELECT * FROM journey_executions WHERE id = :id", {"id": execution_id}), steps)

    # --------------------------- audit logs --------------------------------

    def _audit_where(principal: Principal, event_type, severity, actor_id,
                     resource_type, start_date, end_date) -> tuple[str, dict]:
        where = " WHERE tenant_id = :t"
        params: dict[str, Any] = {"t": principal.tenant_id}
        if event_type:
            where += " AND event_type = :et"
            params["et"] = event_type
        if severity:
            where += " AND severity = :sev"
            params["sev"] = severity
        if actor_id:
            where += " AND actor_id = :aid"
            params["aid"] = actor_id
        if resource_type:
            where += " AND resource_type = :rt"
            params["rt"] = resource_type
        if start_date:
            where += " AND created_at >= :sd"
            params["sd"] = start_date
        if end_date:
            where += " AND created_at <= :ed"
            params["ed"] = end_date
        return where, params

    @app.get("/api/v1/backoffice/audit/logs")
    def list_audit_logs(
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        page: int = 1, limit: int = 50,
        principal: Principal = Depends(get_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        page, limit, offset = _page_params(page, limit)
        where, params = _audit_where(principal, event_type, severity, actor_id,
                                     resource_type, start_date, end_date)
        total = db.query_one(
            f"SELECT COUNT(*) c FROM backoffice_audit_ledger{where}", params)["c"]
        rows = db.query(
            f"SELECT * FROM backoffice_audit_ledger{where} ORDER BY id DESC"
            f" LIMIT :lim OFFSET :off",
            {**params, "lim": limit, "off": offset})
        return {"logs": [_audit_view(r) for r in rows], "total": total,
                "page": page, "limit": limit,
                "total_pages": (total + limit - 1) // limit}

    @app.get("/api/v1/backoffice/audit/logs/export")
    def export_audit_logs(
        format: str = Query(default="csv", pattern="^(csv|json)$"),
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        principal: Principal = Depends(get_principal),
        db: Database = Depends(get_db),
    ):
        import json as _json

        from fastapi.responses import Response

        where, params = _audit_where(principal, None, None, None, None,
                                     start_date, end_date)
        rows = db.query(
            f"SELECT * FROM backoffice_audit_ledger{where} ORDER BY id LIMIT 10000",
            params)
        logs = [_audit_view(r) for r in rows]
        if format == "json":
            return Response(content=_json.dumps(logs, indent=2, default=str),
                            media_type="application/json",
                            headers={"Content-Disposition":
                                     "attachment; filename=audit_logs.json"})
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "id", "timestamp", "event_type", "severity", "actor_id", "actor_type",
            "ip_address", "resource_type", "resource_id", "action", "outcome", "details",
        ])
        writer.writeheader()
        for entry in logs:
            entry = dict(entry)
            entry["details"] = _json.dumps(entry["details"], default=str)
            writer.writerow(entry)
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=audit_logs.csv"})

    @app.get("/api/v1/backoffice/audit/verify")
    def verify_audit_chain(principal: Principal = Depends(get_principal),
                           db: Database = Depends(get_db)) -> dict:
        return audit_ledger.verify_chain(db, principal.tenant_id)

    # --------------------------- user/session admin ------------------------

    @app.get("/api/v1/backoffice/users")
    def list_users(principal: Principal = Depends(get_principal),
                   db: Database = Depends(get_db)) -> dict:
        """Distinct backoffice principals seen in the audit ledger (the
        service's honest source of who has acted) + revocation state."""
        require_ops(principal)
        rows = db.query(
            "SELECT actor_id, MAX(created_at) last_seen FROM backoffice_audit_ledger"
            " WHERE tenant_id = :t AND actor_id IS NOT NULL GROUP BY actor_id",
            {"t": principal.tenant_id})
        revoked = {
            r["sub"]: _s(r["revoked_at"])
            for r in db.query(
                "SELECT sub, MAX(revoked_at) revoked_at FROM backoffice_session_revocations"
                " WHERE tenant_id = :t AND jti = '*' GROUP BY sub",
                {"t": principal.tenant_id})
        }
        return {"users": [
            {"sub": r["actor_id"], "last_seen": _s(r["last_seen"]),
             "sessions_revoked_at": revoked.get(r["actor_id"])}
            for r in rows
        ]}

    @app.post("/api/v1/backoffice/users/{sub}/sessions/revoke")
    def revoke_user_sessions(sub: str, payload: RevokeSessionsRequest,
                             request: Request,
                             principal: Principal = Depends(get_principal),
                             db: Database = Depends(get_db)) -> dict:
        """Revoke ALL sessions for a user (jti='*' tombstone; get_principal
        rejects tokens issued before revoked_at)."""
        require_ops(principal)
        db.execute(
            ("INSERT OR IGNORE INTO backoffice_session_revocations"
             " (tenant_id, jti, sub, revoked_by, reason) VALUES (:t, '*', :s, :by, :r)"
             if not db._is_pg else
             "INSERT INTO backoffice_session_revocations (tenant_id, jti, sub, revoked_by,"
             " reason) VALUES (:t, '*', :s, :by, :r)"
             " ON CONFLICT (tenant_id, jti) DO UPDATE SET revoked_at = now(),"
             " revoked_by = EXCLUDED.revoked_by, reason = EXCLUDED.reason"),
            {"t": principal.tenant_id, "s": sub, "by": principal.sub,
             "r": payload.reason or "admin revocation"},
        )
        _audit(db, principal, request, event_type="admin.session_revoke",
               resource_type="user", resource_id=sub, action="revoke_sessions",
               severity="warning", details={"reason": payload.reason})
        return {"ok": True, "sub": sub}

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8087")))
