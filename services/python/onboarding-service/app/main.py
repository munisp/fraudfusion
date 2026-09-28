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

import base64
import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Path, Query, status

import json

from app import kyb_verification, webhook_emitter
from app.auth import Principal, get_current_principal, require_admin
from app.db import Database, get_db
from app.schemas import (
    ApiKeyGrant,
    ApiKeyRequest,
    ApiKeyRequestPage,
    ApiKeyRequestView,
    ApprovalDecision,
    ChecklistItem,
    ChecklistUpdate,
    KybApplicationPage,
    KybApplicationView,
    KybReverifyRequest,
    KybSubmission,
    KybVerificationSummary,
    KycTierSelection,
    MerchantApplicationPage,
    MerchantApplicationView,
    MerchantSubmission,
    OnboardingStatus,
    RegulatorAccessRequest,
    RegulatorAccessView,
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


# --------------------- Keyset pagination helpers ---------------------------
# Hot list endpoints page by (created_at, id) keyset instead of OFFSET: page
# cost stays O(limit) at any depth and concurrent inserts/deletes cannot
# duplicate or skip rows between pages. The cursor is an opaque
# base64("created_at|id") token; `next_cursor` is null on the last page.

def _encode_cursor(created_at, row_id: str) -> str:
    return base64.urlsafe_b64encode(f"{created_at}|{row_id}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at, row_id = raw.rsplit("|", 1)
        if not created_at or not row_id:
            raise ValueError("empty cursor component")
        return created_at, row_id
    except Exception:
        raise HTTPException(status_code=400, detail="invalid pagination cursor")


def _keyset_where(cursor: str | None, alias: str = "", descending: bool = True) -> tuple[str, dict]:
    """Return (sql_fragment, params) filtering rows strictly past the cursor.

    Pairs with ORDER BY created_at {DESC|ASC}, id {DESC|ASC}. Both SQLite
    (tests) and Postgres (psycopg sends the ISO string as an untyped literal,
    coerced to timestamptz) accept the comparison.
    """
    if not cursor:
        return "", {}
    col = f"{alias}created_at" if alias else "created_at"
    idcol = f"{alias}id" if alias else "id"
    op = "<" if descending else ">"
    cts, cid = _decode_cursor(cursor)
    return (
        f" AND ({col} {op} :cur_ts OR ({col} = :cur_ts AND {idcol} {op} :cur_id))",
        {"cur_ts": cts, "cur_id": cid},
    )


def _page(rows: list[dict], limit: int, view) -> dict:
    """Trim a limit+1 fetch to a page and derive next_cursor."""
    page_rows = rows[:limit]
    next_cursor = _encode_cursor(page_rows[-1]["created_at"], page_rows[-1]["id"]) if len(rows) > limit else None
    return {"items": [view(r) for r in page_rows], "next_cursor": next_cursor}


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
    from app.agents import router as agents_router

    app = FastAPI(title="FraudFusion Onboarding Service", version="1.0.0")
    app.include_router(agents_router)

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

    @app.get("/api/v1/onboarding/admin/requests", response_model=ApiKeyRequestPage,
             response_model_by_alias=True)
    def list_requests(
        status_filter: str = "pending",
        limit: int = Query(default=50, ge=1, le=500),
        cursor: str | None = None,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        require_admin(principal)
        # Keyset over (created_at, id), oldest-first (staff process the queue FIFO).
        where, cur_params = _keyset_where(cursor, alias="k.", descending=False)
        rows = db.query(
            "SELECT k.*, t.organization FROM tenant_api_keys k JOIN tenants t ON t.id = k.tenant_id"
            f" WHERE k.status = :st{where} ORDER BY k.created_at, k.id LIMIT :lim",
            {"st": status_filter, "lim": limit + 1, **cur_params},
        )
        return _page(rows, limit, _key_view)

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

    # --------------------- KYB submissions (dual control) -----------------

    def _parse_verdict(raw) -> dict | None:
        """verification_json is TEXT on SQLite (str) and JSONB on Postgres
        (psycopg hands back a dict) — accept both."""
        if not raw:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None

    def _kyb_verification_summary(row: dict) -> KybVerificationSummary | None:
        verdict = _parse_verdict(row.get("verification_json"))
        if verdict is None:
            return None
        verified_at = row.get("verified_at") or verdict.get("verified_at")
        return KybVerificationSummary(
            verdict=verdict.get("verdict", "unknown"),
            verifiedAt=str(verified_at) if verified_at else None,
            engines=verdict.get("provenance", {}).get("engines", []),
            documentsWithContent=verdict.get("documents_with_content", 0),
        )

    def _kyb_view(row: dict) -> KybApplicationView:
        return KybApplicationView(
            applicationId=row["id"], businessName=row["business_name"],
            cacNumber=row["cac_number"], businessType=row["business_type"],
            status=row["status"], submittedBy=row["submitted_by"],
            reviewedBy=row.get("reviewed_by"), approvedBy=row.get("approved_by"),
            rejectionReason=row.get("rejection_reason"),
            createdAt=str(row.get("created_at") or ""),
            verification=_kyb_verification_summary(row),
        )

    def _process_kyb_documents(documents) -> tuple[list[dict], list[dict]]:
        """Split submitted documents into (stored, verification) forms.

        Stored form keeps only type/reference/content_sha256 — document bytes
        are NEVER persisted or logged. Raises 413 over the 10MB cap (mirrors
        kyc-api's MAX_UPLOAD_BYTES convention)."""
        stored, for_verify = [], []
        for d in documents:
            sha = None
            if d.content is not None:
                data = base64.b64decode(d.content)  # base64 validated by schema
                if len(data) > kyb_verification.MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413,
                                        detail=f"{d.type} content exceeds 10MB limit")
                sha = hashlib.sha256(data).hexdigest()
            stored.append({"type": d.type, "reference": d.reference,
                           "content_sha256": sha})
            for_verify.append({"type": d.type, "reference": d.reference,
                               "content": d.content})
        return stored, for_verify

    def _run_kyb_verification(db: Database, app_id: str, documents,
                              business_name: str, cac_number: str) -> dict:
        """Verify document content and persist the verdict on the row."""
        verdict = kyb_verification.verify_kyb_documents(
            documents, business_name, cac_number)
        db.execute(
            # SQLite stores the verdict as plain TEXT; Postgres needs the
            # explicit cast because psycopg binds str as text and text->jsonb
            # has no implicit assignment cast.
            ("UPDATE kyb_applications SET verification_json = :v,"
             " verified_at = :t, updated_at = :t WHERE id = :id") if not db._is_pg else
            ("UPDATE kyb_applications SET verification_json = CAST(:v AS JSONB),"
             " verified_at = :t, updated_at = :t WHERE id = :id"),
            {"v": json.dumps(verdict), "t": verdict["verified_at"], "id": app_id},
        )
        logger.info("kyb verification: id=%s verdict=%s docs_with_content=%d",
                    app_id, verdict["verdict"], verdict["documents_with_content"])
        # Round-9 webhook contract: kyb.verification.completed carries the
        # application id, verdict and document sha256s ONLY — no PII (no
        # business name / CAC number / extracted fields). Fire-and-forget.
        row = db.query_one("SELECT tenant_id FROM kyb_applications WHERE id = :id",
                           {"id": app_id})
        webhook_emitter.emit_event(
            "kyb.verification.completed",
            (row or {}).get("tenant_id") or "default",
            {
                "application_id": app_id,
                "verdict": verdict["verdict"],
                "verified_at": verdict["verified_at"],
                "documents_with_content": verdict["documents_with_content"],
                "document_sha256s": [
                    d["content_sha256"] for d in verdict.get("documents", [])
                    if d.get("content_sha256")
                ],
            },
        )
        return verdict

    def _merchant_view(row: dict) -> MerchantApplicationView:
        return MerchantApplicationView(
            applicationId=row["id"], businessName=row["business_name"],
            merchantCategory=row["merchant_category"], status=row["status"],
            submittedBy=row["submitted_by"], reviewedBy=row.get("reviewed_by"),
            approvedBy=row.get("approved_by"), rejectionReason=row.get("rejection_reason"),
            createdAt=str(row.get("created_at") or ""),
        )

    def _current_tenant_id(db: Database, principal: Principal) -> str | None:
        tenant = db.query_one(
            "SELECT id FROM tenants WHERE owner_sub = :sub ORDER BY created_at DESC LIMIT 1",
            {"sub": principal.sub},
        )
        return tenant["id"] if tenant else None

    def _submit_application(db: Database, principal: Principal, table: str,
                            values: dict) -> dict:
        app_id = uuid.uuid4().hex
        now = _now()
        base = {
            "id": app_id, "tenant_id": _current_tenant_id(db, principal),
            "submitted_by": principal.sub, "now": now,
        }
        cols = ", ".join(["id", "tenant_id", *values.keys(), "submitted_by", "created_at", "updated_at"])
        binds = ", ".join([":id", ":tenant_id", *[f":{k}" for k in values], ":submitted_by", ":now", ":now"])
        db.execute(f"INSERT INTO {table} ({cols}) VALUES ({binds})", {**base, **values})
        return db.query_one(f"SELECT * FROM {table} WHERE id = :id", {"id": app_id})

    def _get_application(db: Database, table: str, app_id: str) -> dict:
        row = db.query_one(f"SELECT * FROM {table} WHERE id = :id", {"id": app_id})
        if not row:
            raise HTTPException(status_code=404, detail="application not found")
        return row

    def _review_application(db: Database, principal: Principal, table: str, app_id: str) -> dict:
        row = _get_application(db, table, app_id)
        if row["status"] != "submitted":
            raise HTTPException(status_code=409, detail=f"application is {row['status']}, not submitted")
        if row["submitted_by"] == principal.sub:
            raise HTTPException(status_code=409, detail="submitter cannot review their own application")
        db.execute(
            f"UPDATE {table} SET status = 'under_review', reviewed_by = :by, updated_at = :now"
            " WHERE id = :id AND status = 'submitted'",
            {"by": principal.sub, "now": _now(), "id": app_id},
        )
        logger.info("%s reviewed: id=%s by=%s", table, app_id, principal.sub)
        return _get_application(db, table, app_id)

    def _approve_application(db: Database, principal: Principal, table: str, app_id: str) -> dict:
        """Dual control: approver must differ from both submitter and reviewer."""
        row = _get_application(db, table, app_id)
        if row["status"] != "under_review":
            raise HTTPException(status_code=409,
                                detail=f"application is {row['status']}; must be under_review to approve")
        if principal.sub in {row["submitted_by"], row["reviewed_by"]}:
            raise HTTPException(
                status_code=409,
                detail="dual control: approver must differ from submitter and reviewer",
            )
        db.execute(
            f"UPDATE {table} SET status = 'approved', approved_by = :by, updated_at = :now"
            " WHERE id = :id AND status = 'under_review'",
            {"by": principal.sub, "now": _now(), "id": app_id},
        )
        logger.info("%s approved: id=%s by=%s", table, app_id, principal.sub)
        return _get_application(db, table, app_id)

    def _reject_application(db: Database, principal: Principal, table: str,
                            app_id: str, reason: str) -> dict:
        row = _get_application(db, table, app_id)
        if row["status"] not in ("submitted", "under_review"):
            raise HTTPException(status_code=409, detail=f"application is {row['status']}; cannot reject")
        if row["submitted_by"] == principal.sub:
            raise HTTPException(status_code=409, detail="submitter cannot reject their own application")
        db.execute(
            f"UPDATE {table} SET status = 'rejected', rejection_reason = :reason, updated_at = :now"
            " WHERE id = :id",
            {"reason": reason[:2000], "now": _now(), "id": app_id},
        )
        logger.info("%s rejected: id=%s by=%s", table, app_id, principal.sub)
        return _get_application(db, table, app_id)

    @app.post("/api/v1/onboarding/kyb", response_model=KybApplicationView, status_code=201,
              response_model_by_alias=True)
    def submit_kyb(
        payload: KybSubmission,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> KybApplicationView:
        stored_docs, verify_docs = _process_kyb_documents(payload.documents)
        row = _submit_application(db, principal, "kyb_applications", {
            "business_name": payload.business_name,
            "cac_number": payload.cac_number,
            "business_type": payload.business_type,
            "contact_email": payload.contact_email,
            "documents": json.dumps(stored_docs),
        })
        # Content verification runs only when at least one document carries
        # content; reference-only submissions keep the historical behaviour
        # (verification skipped honestly, no verdict row).
        if any(d["content"] is not None for d in verify_docs):
            _run_kyb_verification(db, row["id"], verify_docs,
                                  payload.business_name, payload.cac_number)
            row = _get_application(db, "kyb_applications", row["id"])
        logger.info("kyb submitted: id=%s business=%s by=%s", row["id"], row["business_name"], principal.sub)
        return _kyb_view(row)

    @app.get("/api/v1/onboarding/kyb", response_model=KybApplicationPage,
             response_model_by_alias=True)
    def list_kyb(
        limit: int = Query(default=50, ge=1, le=500),
        cursor: str | None = None,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        # Keyset over (created_at DESC, id DESC); scoped to the submitter
        # unless staff.
        where, cur_params = _keyset_where(cursor, descending=True)
        if principal.is_admin:
            rows = db.query(
                f"SELECT * FROM kyb_applications WHERE TRUE{where}"
                " ORDER BY created_at DESC, id DESC LIMIT :lim",
                {"lim": limit + 1, **cur_params},
            )
        else:
            rows = db.query(
                f"SELECT * FROM kyb_applications WHERE submitted_by = :sub{where}"
                " ORDER BY created_at DESC, id DESC LIMIT :lim",
                {"sub": principal.sub, "lim": limit + 1, **cur_params},
            )
        return _page(rows, limit, _kyb_view)

    @app.get("/api/v1/onboarding/kyb/{app_id}", response_model=KybApplicationView,
             response_model_by_alias=True)
    def get_kyb(
        app_id: str,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> KybApplicationView:
        row = _get_application(db, "kyb_applications", app_id)
        if row["submitted_by"] != principal.sub and not principal.is_admin:
            raise HTTPException(status_code=403, detail="not your application")
        return _kyb_view(row)

    @app.get("/api/v1/onboarding/kyb/{app_id}/verification",
             response_model_by_alias=True)
    def get_kyb_verification(
        app_id: str,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        """Full KYB content-verification verdict (per-document verdicts,
        extracted fields, cross-document consistency, engine provenance)."""
        row = _get_application(db, "kyb_applications", app_id)
        if row["submitted_by"] != principal.sub and not principal.is_admin:
            raise HTTPException(status_code=403, detail="not your application")
        verdict = _parse_verdict(row.get("verification_json"))
        if verdict is None:
            raise HTTPException(
                status_code=404,
                detail="no verification has run for this application "
                       "(reference-only submission, or predates verification)")
        return verdict

    @app.post("/api/v1/onboarding/kyb/{app_id}/reverify",
              response_model_by_alias=True)
    def reverify_kyb(
        app_id: str,
        payload: KybReverifyRequest | None = None,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        """Re-run content verification, e.g. after resubmitting documents.

        Document bytes are retained hash-only, so a re-run over new content
        requires the resubmitted documents in the request body; with an empty
        body the stored verdict is returned (a re-run over the original bytes
        is impossible and we say so instead of pretending)."""
        row = _get_application(db, "kyb_applications", app_id)
        if row["submitted_by"] != principal.sub and not principal.is_admin:
            raise HTTPException(status_code=403, detail="not your application")
        docs = (payload.documents if payload else None) or []
        if not docs:
            verdict = _parse_verdict(row.get("verification_json"))
            if verdict is None:
                raise HTTPException(
                    status_code=422,
                    detail="no document content retained (hash-only storage); "
                           "resubmit documents in the request body to re-verify")
            verdict["reused_stored_verdict"] = True
            verdict["note"] = ("document content is not retained; returning the "
                               "stored verdict — supply documents to re-run")
            return verdict
        stored_docs, verify_docs = _process_kyb_documents(docs)
        db.execute(
            "UPDATE kyb_applications SET documents = :docs, updated_at = :now"
            " WHERE id = :id",
            {"docs": json.dumps(stored_docs), "now": _now(), "id": app_id},
        )
        if any(d["content"] is not None for d in verify_docs):
            return _run_kyb_verification(db, app_id, verify_docs,
                                         row["business_name"], row["cac_number"])
        raise HTTPException(
            status_code=422,
            detail="resubmitted documents carry no content; nothing to verify")

    @app.post("/api/v1/onboarding/admin/kyb/{app_id}/review", response_model=KybApplicationView,
              response_model_by_alias=True)
    def review_kyb(app_id: str, principal: Principal = Depends(get_current_principal),
                   db: Database = Depends(get_db)) -> KybApplicationView:
        require_admin(principal)
        return _kyb_view(_review_application(db, principal, "kyb_applications", app_id))

    @app.post("/api/v1/onboarding/admin/kyb/{app_id}/approve", response_model=KybApplicationView,
              response_model_by_alias=True)
    def approve_kyb(app_id: str, principal: Principal = Depends(get_current_principal),
                    db: Database = Depends(get_db)) -> KybApplicationView:
        require_admin(principal)
        return _kyb_view(_approve_application(db, principal, "kyb_applications", app_id))

    @app.post("/api/v1/onboarding/admin/kyb/{app_id}/reject", response_model=KybApplicationView,
              response_model_by_alias=True)
    def reject_kyb(app_id: str, payload: ApprovalDecision,
                   principal: Principal = Depends(get_current_principal),
                   db: Database = Depends(get_db)) -> KybApplicationView:
        require_admin(principal)
        return _kyb_view(_reject_application(db, principal, "kyb_applications", app_id, payload.reason))

    # --------------------- Merchant onboarding (dual control) --------------

    @app.post("/api/v1/onboarding/merchants", response_model=MerchantApplicationView,
              status_code=201, response_model_by_alias=True)
    def submit_merchant(
        payload: MerchantSubmission,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> MerchantApplicationView:
        row = _submit_application(db, principal, "merchant_applications", {
            "business_name": payload.business_name,
            "cac_number": payload.cac_number,
            "merchant_category": payload.merchant_category,
            "settlement_bank_code": payload.settlement_bank_code,
            "settlement_account": payload.settlement_account,
            "contact_email": payload.contact_email,
        })
        logger.info("merchant application submitted: id=%s business=%s by=%s",
                    row["id"], row["business_name"], principal.sub)
        return _merchant_view(row)

    @app.get("/api/v1/onboarding/merchants", response_model=MerchantApplicationPage,
             response_model_by_alias=True)
    def list_merchants(
        limit: int = Query(default=50, ge=1, le=500),
        cursor: str | None = None,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> dict:
        # Keyset over (created_at DESC, id DESC); scoped to the submitter
        # unless staff.
        where, cur_params = _keyset_where(cursor, descending=True)
        if principal.is_admin:
            rows = db.query(
                f"SELECT * FROM merchant_applications WHERE TRUE{where}"
                " ORDER BY created_at DESC, id DESC LIMIT :lim",
                {"lim": limit + 1, **cur_params},
            )
        else:
            rows = db.query(
                f"SELECT * FROM merchant_applications WHERE submitted_by = :sub{where}"
                " ORDER BY created_at DESC, id DESC LIMIT :lim",
                {"sub": principal.sub, "lim": limit + 1, **cur_params},
            )
        return _page(rows, limit, _merchant_view)

    @app.post("/api/v1/onboarding/admin/merchants/{app_id}/review",
              response_model=MerchantApplicationView, response_model_by_alias=True)
    def review_merchant(app_id: str, principal: Principal = Depends(get_current_principal),
                        db: Database = Depends(get_db)) -> MerchantApplicationView:
        require_admin(principal)
        return _merchant_view(_review_application(db, principal, "merchant_applications", app_id))

    @app.post("/api/v1/onboarding/admin/merchants/{app_id}/approve",
              response_model=MerchantApplicationView, response_model_by_alias=True)
    def approve_merchant(app_id: str, principal: Principal = Depends(get_current_principal),
                         db: Database = Depends(get_db)) -> MerchantApplicationView:
        require_admin(principal)
        return _merchant_view(_approve_application(db, principal, "merchant_applications", app_id))

    @app.post("/api/v1/onboarding/admin/merchants/{app_id}/reject",
              response_model=MerchantApplicationView, response_model_by_alias=True)
    def reject_merchant(app_id: str, payload: ApprovalDecision,
                        principal: Principal = Depends(get_current_principal),
                        db: Database = Depends(get_db)) -> MerchantApplicationView:
        require_admin(principal)
        return _merchant_view(
            _reject_application(db, principal, "merchant_applications", app_id, payload.reason))

    # --------------------- Regulator access (read-only, expiring, dual control)

    def _regulator_view(row: dict) -> RegulatorAccessView:
        return RegulatorAccessView(
            accessId=row["id"], regulatorOrg=row["regulator_org"],
            principalSub=row["principal_sub"], scope=row["scope"], status=row["status"],
            requestedBy=row["requested_by"], approvedBy=row.get("approved_by"),
            expiresAt=str(row.get("expires_at") or ""),
        )

    def _expire_stale_access(db: Database) -> None:
        db.execute(
            "UPDATE regulator_access SET status = 'expired', updated_at = :now"
            " WHERE status = 'active' AND expires_at <= :now",
            {"now": _now()},
        )

    @app.post("/api/v1/onboarding/admin/regulator-access", response_model=RegulatorAccessView,
              status_code=201, response_model_by_alias=True)
    def request_regulator_access(
        payload: RegulatorAccessRequest,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> RegulatorAccessView:
        """Provision a read-only, time-boxed regulator access grant. The grant
        is INERT until approved by a second, distinct admin (dual control)."""
        require_admin(principal)
        access_id = uuid.uuid4().hex
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
        db.execute(
            "INSERT INTO regulator_access (id, regulator_org, principal_sub, scope, status,"
            " requested_by, expires_at, created_at, updated_at)"
            " VALUES (:id, :org, :sub, 'read_only', 'requested', :by, :exp, :now, :now)",
            {"id": access_id, "org": payload.regulator_org, "sub": payload.principal_sub,
             "by": principal.sub, "exp": expires_at.isoformat(), "now": _now()},
        )
        logger.info("regulator access requested: id=%s org=%s sub=%s by=%s",
                    access_id, payload.regulator_org, payload.principal_sub, principal.sub)
        return _regulator_view(db.query_one(
            "SELECT * FROM regulator_access WHERE id = :id", {"id": access_id}))

    @app.post("/api/v1/onboarding/admin/regulator-access/{access_id}/approve",
              response_model=RegulatorAccessView, response_model_by_alias=True)
    def approve_regulator_access(
        access_id: str,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> RegulatorAccessView:
        require_admin(principal)
        row = db.query_one("SELECT * FROM regulator_access WHERE id = :id", {"id": access_id})
        if not row:
            raise HTTPException(status_code=404, detail="regulator access grant not found")
        if row["status"] != "requested":
            raise HTTPException(status_code=409, detail=f"grant is {row['status']}, not requested")
        if row["requested_by"] == principal.sub:
            raise HTTPException(
                status_code=409,
                detail="dual control: approver must differ from the requester",
            )
        db.execute(
            "UPDATE regulator_access SET status = 'active', approved_by = :by, updated_at = :now"
            " WHERE id = :id AND status = 'requested'",
            {"by": principal.sub, "now": _now(), "id": access_id},
        )
        logger.info("regulator access activated: id=%s by=%s", access_id, principal.sub)
        return _regulator_view(db.query_one(
            "SELECT * FROM regulator_access WHERE id = :id", {"id": access_id}))

    @app.get("/api/v1/onboarding/admin/regulator-access",
             response_model=list[RegulatorAccessView], response_model_by_alias=True)
    def list_regulator_access(
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> list[RegulatorAccessView]:
        require_admin(principal)
        _expire_stale_access(db)
        rows = db.query("SELECT * FROM regulator_access ORDER BY created_at DESC")
        return [_regulator_view(r) for r in rows]

    @app.post("/api/v1/onboarding/admin/regulator-access/{access_id}/revoke",
              response_model=RegulatorAccessView, response_model_by_alias=True)
    def revoke_regulator_access(
        access_id: str,
        payload: ApprovalDecision,
        principal: Principal = Depends(get_current_principal),
        db: Database = Depends(get_db),
    ) -> RegulatorAccessView:
        require_admin(principal)
        row = db.query_one("SELECT * FROM regulator_access WHERE id = :id", {"id": access_id})
        if not row:
            raise HTTPException(status_code=404, detail="regulator access grant not found")
        if row["status"] not in ("requested", "active"):
            raise HTTPException(status_code=409, detail=f"grant is {row['status']}; cannot revoke")
        db.execute(
            "UPDATE regulator_access SET status = 'revoked', revoked_by = :by,"
            " revoke_reason = :reason, updated_at = :now WHERE id = :id",
            {"by": principal.sub, "reason": payload.reason[:2000], "now": _now(), "id": access_id},
        )
        logger.info("regulator access revoked: id=%s by=%s", access_id, principal.sub)
        return _regulator_view(db.query_one(
            "SELECT * FROM regulator_access WHERE id = :id", {"id": access_id}))

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8085")))
