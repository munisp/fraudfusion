"""FraudFusion tenant onboarding service.

Backend for ml-onboarding-portal (/api/v1/onboarding/*) plus the staff
approval workflow (/api/v1/onboarding/admin/*).

- Tenants self-serve: request an API key, pick a KYC tier, track the
  integration checklist. Tenant state moves in_progress -> pending_review
  once an API key has been requested.
- Staff (Keycloak realm role "onboarding_admin" or "admin") approve key
  requests under dual control: one staff member reviews, a *different* one
  approves. The plaintext key is returned to the tenant exactly once, at
  approval time; only its SHA-256 hash + a non-secret prefix are persisted.
- Auth is fail-closed Keycloak token introspection (see app/auth.py).

Schema: database/20260826_tenants_onboarding.sql (PostgreSQL; SQLite mirror
in app/db.py for local dev/tests).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Path, status

from app.auth import Principal, get_current_principal, require_admin
from app.db import Database, get_db
from app.schemas import (
    ApiKeyGrant,
    ApiKeyRequest,
    ApiKeyRequestView,
    ApprovalDecision,
    ChecklistItem,
    ChecklistUpdate,
    KycTierSelection,
    OnboardingStatus,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("onboarding-service")

# Default integration checklist seeded for every new tenant. item ids are
# stable API identifiers consumed by ml-onboarding-portal.
DEFAULT_CHECKLIST: list[tuple[str, str, bool]] = [
    ("request-api-key", "Request a sandbox API key", True),
    ("select-kyc-tier", "Select your KYC tier (basic/enhanced/premium)", True),
    ("integrate-auth", "Integrate Keycloak OIDC authentication", True),
    ("send-test-transaction", "Send a test transaction through the sandbox", True),
    ("configure-webhooks", "Configure fraud-alert webhooks", False),
    ("go-live-review", "Pass the go-live review with FraudFusion staff", True),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _new_api_key() -> tuple[str, str, str]:
    """Return (plaintext, sha256 hex, non-secret prefix)."""
    plaintext = "ffk_" + secrets.token_urlsafe(32)
    return plaintext, _hash_key(plaintext), plaintext[:12]


# ---------------------------------------------------------------------------
# Tenant helpers
# ---------------------------------------------------------------------------

def _tenant_to_status(db: Database, tenant: dict) -> OnboardingStatus:
    items = db.query(
        "SELECT item_id AS id, label, done, required FROM onboarding_checklist_items"
        " WHERE tenant_id = :tid ORDER BY rowid" if not db._is_pg else
        "SELECT item_id AS id, label, done, required FROM onboarding_checklist_items"
        " WHERE tenant_id = :tid ORDER BY item_id",
        {"tid": tenant["id"]},
    )
    checklist = [
        ChecklistItem(id=i["id"], label=i["label"], done=bool(i["done"]), required=bool(i["required"]))
        for i in items
    ]
    approved = db.query_one(
        "SELECT id FROM tenant_api_keys WHERE tenant_id = :tid AND status = 'approved' LIMIT 1",
        {"tid": tenant["id"]},
    )
    return OnboardingStatus(
        tenantId=tenant["id"],
        tier=tenant["kyc_tier"],
        apiKeyIssued=approved is not None,
        checklist=checklist,
        state=tenant["state"],
        updatedAt=str(tenant.get("updated_at") or ""),
    )


def _get_owned_tenant(db: Database, principal: Principal, tenant_id: str | None = None) -> dict:
    """Resolve the caller's tenant (most recent by default). Admins may view
    any tenant; everyone else is restricted to tenants they own."""
    if tenant_id:
        tenant = db.query_one("SELECT * FROM tenants WHERE id = :id", {"id": tenant_id})
        if not tenant:
            raise HTTPException(status_code=404, detail="tenant not found")
        if tenant["owner_sub"] != principal.sub and not principal.is_admin:
            raise HTTPException(status_code=403, detail="not your tenant")
        return tenant
    tenant = db.query_one(
        "SELECT * FROM tenants WHERE owner_sub = :sub ORDER BY created_at DESC LIMIT 1",
        {"sub": principal.sub},
    )
    if not tenant:
        raise HTTPException(
            status_code=404,
            detail="no tenant yet; request an API key to start onboarding",
        )
    return tenant


def _seed_checklist(db: Database, tenant_id: str) -> None:
    for item_id, label, required in DEFAULT_CHECKLIST:
        db.execute(
            "INSERT OR IGNORE INTO onboarding_checklist_items (tenant_id, item_id, label, required)"
            " VALUES (:tid, :iid, :label, :req)" if not db._is_pg else
            "INSERT INTO onboarding_checklist_items (tenant_id, item_id, label, required)"
            " VALUES (:tid, :iid, :label, :req) ON CONFLICT DO NOTHING",
            {"tid": tenant_id, "iid": item_id, "label": label, "req": required},
        )


def _mark_checklist_done(db: Database, tenant_id: str, item_id: str) -> None:
    db.execute(
        "UPDATE onboarding_checklist_items SET done = 1, updated_at = :now"
        " WHERE tenant_id = :tid AND item_id = :iid" if not db._is_pg else
        "UPDATE onboarding_checklist_items SET done = TRUE, updated_at = :now"
        " WHERE tenant_id = :tid AND item_id = :iid",
        {"tid": tenant_id, "iid": item_id, "now": _now()},
    )


def _record_event(db: Database, api_key_id: str, action: str, actor_sub: str, detail: str = "") -> None:
    db.execute(
        "INSERT INTO onboarding_approval_events (id, api_key_id, action, actor_sub, detail)"
        " VALUES (:id, :kid, :action, :actor, :detail)",
        {"id": uuid.uuid4().hex, "kid": api_key_id, "action": action, "actor": actor_sub, "detail": detail},
    )


def _key_view(row: dict) -> ApiKeyRequestView:
    return ApiKeyRequestView(
        keyId=row["id"],
        tenantId=row["tenant_id"],
        organization=row.get("organization", ""),
        environment=row["environment"],
        status=row["status"],
        keyPrefix=row.get("key_prefix"),
        requestedBy=row["requested_by"],
        reviewedBy=row.get("reviewed_by"),
        approvedBy=row.get("approved_by"),
        rejectionReason=row.get("rejection_reason"),
        createdAt=str(row.get("created_at") or ""),
    )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(title="FraudFusion Onboarding Service", version="1.0.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "healthy", "service": "onboarding-service", "timestamp": _now()}

    # ------------------------- tenant self-serve --------------------------

    @app.post("/api/v1/onboarding/api-keys", response_model=ApiKeyGrant, status_code=201,
              response_model_by_alias=True)
    def request_api_key(
        payload: ApiKeyRequest,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> ApiKeyGrant:
        tenant = db.query_one(
            "SELECT * FROM tenants WHERE owner_sub = :sub AND organization = :org",
            {"sub": principal.sub, "org": payload.organization},
        )
        now = _now()
        if tenant is None:
            tenant_id = uuid.uuid4().hex
            db.execute(
                "INSERT INTO tenants (id, organization, contact_email, owner_sub, use_case,"
                " environment, state, created_at, updated_at)"
                " VALUES (:id, :org, :email, :sub, :use_case, :env, 'in_progress', :now, :now)",
                {
                    "id": tenant_id, "org": payload.organization, "email": payload.contact_email,
                    "sub": principal.sub, "use_case": payload.use_case, "env": payload.environment,
                    "now": now,
                },
            )
            _seed_checklist(db, tenant_id)
        else:
            tenant_id = tenant["id"]
            if tenant["state"] == "suspended":
                raise HTTPException(status_code=409, detail="tenant is suspended")
        key_id = uuid.uuid4().hex
        db.execute(
            "INSERT INTO tenant_api_keys (id, tenant_id, label, environment, status,"
            " requested_by, created_at, updated_at)"
            " VALUES (:id, :tid, :label, :env, 'pending', :sub, :now, :now)",
            {
                "id": key_id, "tid": tenant_id, "label": payload.label,
                "env": payload.environment, "sub": principal.sub, "now": now,
            },
        )
        db.execute(
            "UPDATE tenants SET state = 'pending_review', updated_at = :now WHERE id = :id"
            " AND state IN ('not_started', 'in_progress')",
            {"id": tenant_id, "now": now},
        )
        _record_event(db, key_id, "request", principal.sub, payload.use_case[:200])
        _mark_checklist_done(db, tenant_id, "request-api-key")
        logger.info("api key requested: key=%s tenant=%s by=%s", key_id, tenant_id, principal.sub)
        # Key material is only ever returned by the staff approval endpoint.
        return ApiKeyGrant(keyId=key_id, apiKey=None, environment=payload.environment, status="pending")

    @app.post("/api/v1/onboarding/kyc-tier", response_model=OnboardingStatus, response_model_by_alias=True)
    def select_kyc_tier(
        payload: KycTierSelection,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> OnboardingStatus:
        tenant = _get_owned_tenant(db, principal, payload.tenant_id)
        if tenant["state"] == "suspended":
            raise HTTPException(status_code=409, detail="tenant is suspended")
        db.execute(
            "UPDATE tenants SET kyc_tier = :tier, updated_at = :now WHERE id = :id",
            {"tier": payload.tier, "id": tenant["id"], "now": _now()},
        )
        _mark_checklist_done(db, tenant["id"], "select-kyc-tier")
        return _tenant_to_status(db, db.query_one("SELECT * FROM tenants WHERE id = :id", {"id": tenant["id"]}))

    @app.get("/api/v1/onboarding/checklist", response_model=dict)
    def get_checklist(
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        tenant = _get_owned_tenant(db, principal)
        return {"items": [i.model_dump() for i in _tenant_to_status(db, tenant).checklist]}

    @app.post("/api/v1/onboarding/checklist/{item_id}", response_model=ChecklistItem)
    def update_checklist_item(
        payload: ChecklistUpdate,
        item_id: str = Path(min_length=1, max_length=100),
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> ChecklistItem:
        tenant = _get_owned_tenant(db, principal)
        row = db.query_one(
            "SELECT * FROM onboarding_checklist_items WHERE tenant_id = :tid AND item_id = :iid",
            {"tid": tenant["id"], "iid": item_id},
        )
        if not row:
            raise HTTPException(status_code=404, detail="checklist item not found")
        db.execute(
            "UPDATE onboarding_checklist_items SET done = :done, updated_at = :now"
            " WHERE tenant_id = :tid AND item_id = :iid",
            {"done": payload.done if db._is_pg else int(payload.done),
             "now": _now(), "tid": tenant["id"], "iid": item_id},
        )
        return ChecklistItem(id=item_id, label=row["label"], done=payload.done, required=bool(row["required"]))

    @app.get("/api/v1/onboarding/status", response_model=OnboardingStatus, response_model_by_alias=True)
    def get_status(
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> OnboardingStatus:
        return _tenant_to_status(db, _get_owned_tenant(db, principal))

    # --------------------- staff approval (dual control) -------------------

    def _get_key(db: Database, key_id: str) -> dict:
        row = db.query_one(
            "SELECT k.*, t.organization FROM tenant_api_keys k"
            " JOIN tenants t ON t.id = k.tenant_id WHERE k.id = :id",
            {"id": key_id},
        )
        if not row:
            raise HTTPException(status_code=404, detail="api key request not found")
        return row

    @app.get("/api/v1/onboarding/admin/requests", response_model=list[ApiKeyRequestView],
             response_model_by_alias=True)
    def list_requests(
        status_filter: str = "pending",
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> list[ApiKeyRequestView]:
        require_admin(principal)
        rows = db.query(
            "SELECT k.*, t.organization FROM tenant_api_keys k JOIN tenants t ON t.id = k.tenant_id"
            " WHERE k.status = :st ORDER BY k.created_at",
            {"st": status_filter},
        )
        return [_key_view(r) for r in rows]

    @app.post("/api/v1/onboarding/admin/requests/{key_id}/review", response_model=ApiKeyRequestView,
              response_model_by_alias=True)
    def review_request(
        key_id: str,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> ApiKeyRequestView:
        require_admin(principal)
        row = _get_key(db, key_id)
        if row["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"request is {row['status']}, not pending")
        if row["requested_by"] == principal.sub:
            raise HTTPException(status_code=409, detail="requester cannot review their own request")
        db.execute(
            "UPDATE tenant_api_keys SET status = 'reviewed', reviewed_by = :by, updated_at = :now"
            " WHERE id = :id AND status = 'pending'",
            {"by": principal.sub, "now": _now(), "id": key_id},
        )
        _record_event(db, key_id, "review", principal.sub)
        return _key_view(_get_key(db, key_id))

    @app.post("/api/v1/onboarding/admin/requests/{key_id}/approve", response_model=ApiKeyGrant,
              response_model_by_alias=True)
    def approve_request(
        key_id: str,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> ApiKeyGrant:
        """Dual control: the approver must be a staff member other than both
        the requester and the reviewer. Returns the plaintext key once."""
        require_admin(principal)
        row = _get_key(db, key_id)
        if row["status"] == "pending":
            raise HTTPException(status_code=409, detail="request must be reviewed before approval")
        if row["status"] != "reviewed":
            raise HTTPException(status_code=409, detail=f"request is {row['status']}, not reviewed")
        if principal.sub in {row["requested_by"], row["reviewed_by"]}:
            raise HTTPException(
                status_code=409,
                detail="dual control: approver must differ from requester and reviewer",
            )
        plaintext, key_hash, prefix = _new_api_key()
        db.execute(
            "UPDATE tenant_api_keys SET status = 'approved', approved_by = :by, key_hash = :hash,"
            " key_prefix = :prefix, updated_at = :now WHERE id = :id AND status = 'reviewed'",
            {"by": principal.sub, "hash": key_hash, "prefix": prefix, "now": _now(), "id": key_id},
        )
        db.execute(
            "UPDATE tenants SET state = 'active', updated_at = :now WHERE id = :tid",
            {"tid": row["tenant_id"], "now": _now()},
        )
        _record_event(db, key_id, "approve", principal.sub)
        logger.info("api key approved: key=%s tenant=%s by=%s", key_id, row["tenant_id"], principal.sub)
        return ApiKeyGrant(keyId=key_id, apiKey=plaintext, environment=row["environment"], status="approved")

    @app.post("/api/v1/onboarding/admin/requests/{key_id}/reject", response_model=ApiKeyRequestView,
              response_model_by_alias=True)
    def reject_request(
        key_id: str,
        payload: ApprovalDecision,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> ApiKeyRequestView:
        require_admin(principal)
        row = _get_key(db, key_id)
        if row["status"] not in ("pending", "reviewed"):
            raise HTTPException(status_code=409, detail=f"request is {row['status']}; cannot reject")
        if row["requested_by"] == principal.sub:
            raise HTTPException(status_code=409, detail="requester cannot reject their own request")
        db.execute(
            "UPDATE tenant_api_keys SET status = 'rejected', rejection_reason = :reason,"
            " updated_at = :now WHERE id = :id",
            {"reason": payload.reason, "now": _now(), "id": key_id},
        )
        db.execute(
            "UPDATE tenants SET state = 'in_progress', updated_at = :now WHERE id = :tid"
            " AND state = 'pending_review'",
            {"tid": row["tenant_id"], "now": _now()},
        )
        _record_event(db, key_id, "reject", principal.sub, payload.reason[:200])
        return _key_view(_get_key(db, key_id))

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8085")))
