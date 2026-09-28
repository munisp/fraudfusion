"""CBN agent-banking agent onboarding (stakeholder with dual control).

Flow: submit -> screening (sanctions/PEP hook into kyc-api) -> admin review
-> admin approve (dual control: approver must differ from submitter AND
reviewer, enforced here and by the agent_applications_dual_control_guard
Postgres trigger) | reject.

BVN is captured by reference only: a per-agent random salt is generated and
sha256(salt || bvn) is stored; the plaintext BVN never touches the database.

Screening hook: calls kyc-api's /api/v1/screening/comprehensive when
KYC_API_URL is configured (service token via KYC_SERVICE_TOKEN). When the KYC
service is not configured or unreachable, screening_status is 'unavailable'
and approval is blocked (fail closed — an unscreened agent is never
approvable).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import Principal, get_current_principal, require_admin
from app.db import Database, get_db
from app.schemas import AgentApplicationPage, AgentApplicationView, AgentSubmission, ApprovalDecision

logger = logging.getLogger(__name__)

router = APIRouter()

KYC_API_URL = os.getenv("KYC_API_URL", "").rstrip("/")
KYC_SERVICE_TOKEN = os.getenv("KYC_SERVICE_TOKEN", "")
SCREENING_TIMEOUT = float(os.getenv("KYC_SCREENING_TIMEOUT_SECONDS", "10"))

# Legal status transitions for agent_applications.
TRANSITIONS = {
    "submitted": {"screening", "rejected"},
    "screening": {"pending_approval", "rejected"},
    "pending_approval": {"approved", "rejected"},
    "approved": {"suspended"},
    "rejected": set(),
    "suspended": set(),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_bvn(bvn: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Salted SHA-256 of the BVN (reference-only capture)."""
    salt = salt or secrets.token_hex(16)
    return hashlib.sha256((salt + bvn).encode("utf-8")).hexdigest(), salt


def _agent_view(row: dict) -> AgentApplicationView:
    return AgentApplicationView(
        id=row["id"],
        agent_code=row["agent_code"],
        full_name=row["full_name"],
        principal_fintech=row["principal_fintech"],
        principal_reference=row["principal_reference"],
        float_account_number=row["float_account_number"],
        float_account_bank=row["float_account_bank"],
        latitude=row["latitude"],
        longitude=row["longitude"],
        cbn_tier=row["cbn_tier"],
        status=row["status"],
        screening_status=row["screening_status"],
        submitted_by=row["submitted_by"],
        reviewed_by=row.get("reviewed_by"),
        approved_by=row.get("approved_by"),
        created_at=str(row.get("created_at") or ""),
        updated_at=str(row.get("updated_at") or ""),
    )


def _get_agent(db: Database, agent_id: str) -> dict:
    row = db.query_one("SELECT * FROM agent_applications WHERE id = :id", {"id": agent_id})
    if not row:
        raise HTTPException(status_code=404, detail="agent application not found")
    return row


def _transition(db: Database, agent_id: str, target: str, **fields) -> dict:
    row = _get_agent(db, agent_id)
    if target not in TRANSITIONS[row["status"]]:
        raise HTTPException(
            status_code=409,
            detail=f"illegal agent status transition {row['status']} -> {target}",
        )
    assignments = ", ".join(f"{k} = :{k}" for k in fields)
    db.execute(
        f"UPDATE agent_applications SET status = :target, updated_at = :now"
        + (f", {assignments}" if fields else "")
        + " WHERE id = :id",
        {"target": target, "now": _now(), "id": agent_id, **fields},
    )
    return _get_agent(db, agent_id)


def run_screening(db: Database, agent_id: str) -> dict:
    """Sanctions/PEP screening hook into kyc-api. Fail-closed: any problem
    leaves screening_status 'unavailable', which blocks approval."""
    row = _get_agent(db, agent_id)
    if not KYC_API_URL:
        db.execute(
            "UPDATE agent_applications SET screening_status = 'unavailable',"
            " screening_result = :res, updated_at = :now WHERE id = :id",
            {"res": '{"error": "KYC_API_URL not configured"}', "now": _now(), "id": agent_id},
        )
        return _get_agent(db, agent_id)
    headers = {"Authorization": f"Bearer {KYC_SERVICE_TOKEN}"} if KYC_SERVICE_TOKEN else {}
    try:
        resp = httpx.post(
            f"{KYC_API_URL}/api/v1/screening/comprehensive",
            json={"full_name": row["full_name"], "date_of_birth": "", "nationality": "NG"},
            headers=headers, timeout=SCREENING_TIMEOUT,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"kyc-api returned HTTP {resp.status_code}")
        body = resp.json()
    except Exception as exc:  # noqa: BLE001 - fail closed, record reason
        logger.error("agent screening hook failed for %s: %s", agent_id, exc)
        db.execute(
            "UPDATE agent_applications SET screening_status = 'unavailable',"
            " screening_result = :res, updated_at = :now WHERE id = :id",
            {"res": f'{{"error": "{exc.__class__.__name__}"}}', "now": _now(), "id": agent_id},
        )
        return _get_agent(db, agent_id)

    import json as _json

    status = body.get("status", "")
    screening_status = "clear" if status == "clean" else ("hit" if status else "unavailable")
    db.execute(
        "UPDATE agent_applications SET screening_status = :st, screening_result = :res,"
        " updated_at = :now WHERE id = :id",
        {"st": screening_status, "res": _json.dumps(body), "now": _now(), "id": agent_id},
    )
    return _get_agent(db, agent_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/v1/onboarding/agents", response_model=AgentApplicationView,
             status_code=201, response_model_by_alias=True)
def submit_agent(
    payload: AgentSubmission,
    principal: Principal = Depends(get_current_principal),
    db: Database = Depends(get_db),
) -> AgentApplicationView:
    bvn_digest, bvn_salt = hash_bvn(payload.bvn)
    agent_id = uuid.uuid4().hex
    now = _now()
    try:
        db.execute(
            "INSERT INTO agent_applications (id, agent_code, full_name, principal_fintech,"
            " principal_reference, bvn_hash, bvn_salt, float_account_number, float_account_bank,"
            " latitude, longitude, cbn_tier, status, screening_status, submitted_by,"
            " created_at, updated_at)"
            " VALUES (:id, :code, :name, :fintech, :pref, :bvnh, :bvns, :facct, :fbank,"
            " :lat, :lng, :tier, 'screening', 'pending', :sub, :now, :now)",
            {"id": agent_id, "code": payload.agent_code, "name": payload.full_name,
             "fintech": payload.principal_fintech, "pref": payload.principal_reference,
             "bvnh": bvn_digest, "bvns": bvn_salt, "facct": payload.float_account_number,
             "fbank": payload.float_account_bank, "lat": payload.latitude,
             "lng": payload.longitude, "tier": payload.cbn_tier, "sub": principal.sub,
             "now": now},
        )
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(status_code=409,
                                detail="agent_code already registered") from exc
        raise
    row = run_screening(db, agent_id)
    logger.info("agent onboarding submitted: id=%s code=%s fintech=%s by=%s screening=%s",
                agent_id, payload.agent_code, payload.principal_fintech, principal.sub,
                row["screening_status"])
    return _agent_view(row)


@router.get("/api/v1/onboarding/agents", response_model=AgentApplicationPage,
            response_model_by_alias=True)
def list_agents(
    limit: int = Query(default=50, ge=1, le=500),
    principal: Principal = Depends(get_current_principal),
    db: Database = Depends(get_db),
) -> dict:
    if principal.is_admin:
        rows = db.query(
            "SELECT * FROM agent_applications ORDER BY created_at DESC, id DESC LIMIT :lim",
            {"lim": limit},
        )
    else:
        rows = db.query(
            "SELECT * FROM agent_applications WHERE submitted_by = :sub"
            " ORDER BY created_at DESC, id DESC LIMIT :lim",
            {"sub": principal.sub, "lim": limit},
        )
    return {"items": [_agent_view(r) for r in rows], "next_cursor": None}


@router.get("/api/v1/onboarding/agents/{agent_id}", response_model=AgentApplicationView,
            response_model_by_alias=True)
def get_agent(agent_id: str,
              principal: Principal = Depends(get_current_principal),
              db: Database = Depends(get_db)) -> AgentApplicationView:
    row = _get_agent(db, agent_id)
    if row["submitted_by"] != principal.sub and not principal.is_admin:
        raise HTTPException(status_code=404, detail="agent application not found")
    return _agent_view(row)


@router.post("/api/v1/onboarding/agents/{agent_id}/rescreen",
             response_model=AgentApplicationView, response_model_by_alias=True)
def rescreen_agent(agent_id: str,
                   principal: Principal = Depends(get_current_principal),
                   db: Database = Depends(get_db)) -> AgentApplicationView:
    row = _get_agent(db, agent_id)
    if row["submitted_by"] != principal.sub and not principal.is_admin:
        raise HTTPException(status_code=404, detail="agent application not found")
    if row["status"] not in ("screening", "pending_approval"):
        raise HTTPException(status_code=409,
                            detail=f"cannot rescreen an agent in status {row['status']}")
    return _agent_view(run_screening(db, agent_id))


@router.post("/api/v1/onboarding/admin/agents/{agent_id}/review",
             response_model=AgentApplicationView, response_model_by_alias=True)
def review_agent(agent_id: str,
                 principal: Principal = Depends(get_current_principal),
                 db: Database = Depends(get_db)) -> AgentApplicationView:
    require_admin(principal)
    row = _get_agent(db, agent_id)
    if row["submitted_by"] == principal.sub:
        raise HTTPException(status_code=409,
                            detail="dual control: submitter cannot review their own agent")
    return _agent_view(_transition(db, agent_id, "pending_approval",
                                   reviewed_by=principal.sub))


@router.post("/api/v1/onboarding/admin/agents/{agent_id}/approve",
             response_model=AgentApplicationView, response_model_by_alias=True)
def approve_agent(agent_id: str,
                  principal: Principal = Depends(get_current_principal),
                  db: Database = Depends(get_db)) -> AgentApplicationView:
    require_admin(principal)
    row = _get_agent(db, agent_id)
    # Dual control (also enforced by the PG trigger): approver must be a
    # third principal, distinct from both submitter and reviewer.
    if principal.sub == row["submitted_by"]:
        raise HTTPException(status_code=409,
                            detail="dual control: approver cannot be the submitter")
    if row.get("reviewed_by") and principal.sub == row["reviewed_by"]:
        raise HTTPException(status_code=409,
                            detail="dual control: approver cannot be the reviewer")
    if row["screening_status"] != "clear":
        raise HTTPException(
            status_code=409,
            detail=f"sanctions/PEP screening must be clear before approval "
                   f"(currently: {row['screening_status']})",
        )
    return _agent_view(_transition(db, agent_id, "approved", approved_by=principal.sub))


@router.post("/api/v1/onboarding/admin/agents/{agent_id}/reject",
             response_model=AgentApplicationView, response_model_by_alias=True)
def reject_agent(agent_id: str, payload: ApprovalDecision,
                 principal: Principal = Depends(get_current_principal),
                 db: Database = Depends(get_db)) -> AgentApplicationView:
    require_admin(principal)
    return _agent_view(_transition(db, agent_id, "rejected",
                                   rejection_reason=payload.reason))


@router.post("/api/v1/onboarding/admin/agents/{agent_id}/suspend",
             response_model=AgentApplicationView, response_model_by_alias=True)
def suspend_agent(agent_id: str, payload: ApprovalDecision,
                  principal: Principal = Depends(get_current_principal),
                  db: Database = Depends(get_db)) -> AgentApplicationView:
    require_admin(principal)
    return _agent_view(_transition(db, agent_id, "suspended",
                                   rejection_reason=payload.reason))
