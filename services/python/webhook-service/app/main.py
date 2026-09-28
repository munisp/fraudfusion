"""FraudFusion webhook service (port 8088).

Tenant-facing webhook endpoint management plus the internal event intake and
signed delivery pipeline:

  * POST/GET/DELETE /v1/webhooks — endpoint CRUD per tenant, staff JWT auth
    (Keycloak introspection, fail-closed; app/auth.py). The signing secret
    (whsec_<32 hex>) is returned ONCE at creation; only its sha256 hash is
    persisted.
  * POST /internal/events — service-to-service intake per the Round-9
    emitter contract: X-Internal-Token: {WEBHOOK_INTERNAL_TOKEN}, body =
    event envelope {"id","type","created_at","tenant_id","data"}.
    Fail-closed 503 when WEBHOOK_INTERNAL_TOKEN is unset.
  * GET /v1/webhooks/{id}/deliveries — tenant delivery history with attempt
    log and hash-chain fields.
  * Background delivery worker (in-process asyncio task) — see app/worker.py.

Tenant scoping: staff callers operate on one tenant at a time, selected by
the X-Tenant-Id header (default "default") — same convention as the
tenant_id="default" handling in identity-theft-detector.

Schema: database/20260930_webhooks.sql (PostgreSQL; SQLite mirror in
app/db.py for local dev/tests).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from app import api_keys, chain, worker
from app.api_keys import require_scope
from app.auth import Principal, get_current_principal
from app.db import Database, get_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("webhook-service")

MAX_URL_LENGTH = 2048
MAX_EVENT_TYPES = 50
MAX_DATA_BYTES = 256 * 1024


class EndpointCreate(BaseModel):
    url: str = Field(min_length=8, max_length=MAX_URL_LENGTH)
    event_types: list[str] = Field(min_length=1, max_length=MAX_EVENT_TYPES)


def _validate_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url):
        raise HTTPException(status_code=422, detail="url must be http(s)")
    return url


def _validate_event_types(event_types: list[str]) -> list[str]:
    cleaned = []
    for et in event_types:
        et = et.strip()
        if not re.match(r"^(\*|[a-z0-9_]+(\.[a-z0-9_]+)*)$", et):
            raise HTTPException(status_code=422, detail=f"invalid event type: {et!r}")
        if et not in cleaned:
            cleaned.append(et)
    return cleaned


def _endpoint_view(row: dict) -> dict:
    """Public view — NEVER includes secret or secret_hash."""
    return {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "url": row["url"],
        "event_types": json.loads(row["event_types"] or "[]"),
        "status": row["status"],
        "consecutive_failures": row["consecutive_failures"],
        "created_by": row["created_by"],
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def _delivery_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "event_id": row["event_id"],
        "endpoint_id": row["endpoint_id"],
        "tenant_id": row["tenant_id"],
        "status": row["status"],
        "attempt_count": row["attempt_count"],
        "next_attempt_at": row["next_attempt_at"],
        "attempts": json.loads(row["attempts_json"] or "[]"),
        "last_status_code": row["last_status_code"],
        "last_error": row["last_error"],
        "prev_hash": row["prev_hash"],
        "entry_hash": row["entry_hash"],
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "completed_at": str(row["completed_at"]) if row["completed_at"] else None,
    }


def _check_internal_token(x_internal_token: str = Header(default="")) -> None:
    """Fail-closed guard for /internal/events: 503 when the shared token is
    not configured, 401 on mismatch (constant-time compare)."""
    expected = os.getenv("WEBHOOK_INTERNAL_TOKEN", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WEBHOOK_INTERNAL_TOKEN not configured; internal intake disabled",
        )
    if not hmac.compare_digest(expected, x_internal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="invalid internal token")


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        stop = asyncio.Event()
        client = httpx.AsyncClient()
        poll = float(os.getenv("WEBHOOK_WORKER_POLL_SECONDS", "1"))
        task = asyncio.create_task(
            worker.worker_loop(get_db(), client, stop, poll_interval=poll))
        try:
            yield
        finally:
            stop.set()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            await client.aclose()

    app = FastAPI(title="FraudFusion Webhook Service", version="1.0.0",
                  lifespan=lifespan)

    def _tenant(
        x_tenant_id: str = Header(default=""),
        principal: Principal | api_keys.ApiKeyPrincipal = Depends(
            api_keys.get_data_principal),
    ) -> str:
        """Tenant scoping. Staff JWT principals pick the tenant via
        X-Tenant-Id (default 'default'); API-key principals are pinned to the
        key's tenant — a mismatched X-Tenant-Id is rejected so a key can
        never act on another tenant."""
        if api_keys.is_api_key(principal):
            key_tenant = principal.tenant_id or "default"
            if x_tenant_id.strip() and x_tenant_id.strip() != key_tenant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="X-Tenant-Id does not match the API key's tenant",
                )
            return key_tenant
        return x_tenant_id.strip() or "default"

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": "webhook-service"}

    # ------------------------------------------------------------------
    # Endpoint CRUD (staff JWT, per tenant)
    # ------------------------------------------------------------------
    @app.post("/v1/webhooks", status_code=201)
    def create_endpoint(
        payload: EndpointCreate,
        principal: Principal | api_keys.ApiKeyPrincipal = Depends(
            require_scope("webhooks_manage")),
        db: Database = Depends(get_db),
        tenant_id: str = Depends(_tenant),
    ) -> dict:
        url = _validate_url(payload.url)
        event_types = _validate_event_types(payload.event_types)
        endpoint_id = f"whep_{uuid.uuid4().hex[:24]}"
        secret = f"whsec_{secrets.token_hex(16)}"  # shown ONCE, never stored
        db.execute(
            "INSERT INTO webhook_endpoints (id, tenant_id, url, event_types,"
            " secret_hash, status, created_by) VALUES (:id, :t, :url, :ets, :sh,"
            " 'active', :by)",
            {"id": endpoint_id, "t": tenant_id, "url": url,
             "ets": json.dumps(event_types),
             "sh": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
             "by": principal.sub},
        )
        row = db.query_one("SELECT * FROM webhook_endpoints WHERE id = :id",
                           {"id": endpoint_id})
        logger.info("webhook endpoint created: id=%s tenant=%s by=%s",
                    endpoint_id, tenant_id, principal.sub)
        return {**_endpoint_view(row), "secret": secret}

    @app.get("/v1/webhooks")
    def list_endpoints(
        limit: int = Query(default=100, ge=1, le=500),
        principal: Principal | api_keys.ApiKeyPrincipal = Depends(
            require_scope("webhooks_manage")),
        db: Database = Depends(get_db),
        tenant_id: str = Depends(_tenant),
    ) -> dict:
        rows = db.query(
            "SELECT * FROM webhook_endpoints WHERE tenant_id = :t"
            " ORDER BY created_at DESC, id DESC LIMIT :n",
            {"t": tenant_id, "n": limit},
        )
        return {"endpoints": [_endpoint_view(r) for r in rows]}

    def _get_tenant_endpoint(db: Database, endpoint_id: str, tenant_id: str) -> dict:
        row = db.query_one("SELECT * FROM webhook_endpoints WHERE id = :id",
                           {"id": endpoint_id})
        if not row or row["tenant_id"] != tenant_id:
            # 404 either way: no cross-tenant existence leak.
            raise HTTPException(status_code=404, detail="endpoint not found")
        return row

    @app.get("/v1/webhooks/{endpoint_id}")
    def get_endpoint(
        endpoint_id: str,
        principal: Principal | api_keys.ApiKeyPrincipal = Depends(
            require_scope("webhooks_manage")),
        db: Database = Depends(get_db),
        tenant_id: str = Depends(_tenant),
    ) -> dict:
        return _endpoint_view(_get_tenant_endpoint(db, endpoint_id, tenant_id))

    @app.delete("/v1/webhooks/{endpoint_id}", status_code=204,
                response_class=Response)
    def delete_endpoint(
        endpoint_id: str,
        principal: Principal | api_keys.ApiKeyPrincipal = Depends(
            require_scope("webhooks_manage")),
        db: Database = Depends(get_db),
        tenant_id: str = Depends(_tenant),
    ) -> Response:
        _get_tenant_endpoint(db, endpoint_id, tenant_id)
        # Pending deliveries for a deleted endpoint can never succeed;
        # dead-letter them now instead of leaving them retrying for 10m.
        db.execute(
            "UPDATE webhook_deliveries SET status = 'dead_letter',"
            " last_error = 'endpoint_deleted', updated_at = :t, completed_at = :t"
            " WHERE endpoint_id = :id AND status = 'pending'",
            {"t": chain.utc_now_iso(), "id": endpoint_id},
        )
        db.execute("DELETE FROM webhook_endpoints WHERE id = :id", {"id": endpoint_id})
        logger.info("webhook endpoint deleted: id=%s tenant=%s by=%s",
                    endpoint_id, tenant_id, principal.sub)
        return Response(status_code=204)

    @app.get("/v1/webhooks/{endpoint_id}/deliveries")
    def list_deliveries(
        endpoint_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        principal: Principal | api_keys.ApiKeyPrincipal = Depends(
            require_scope("webhooks_manage")),
        db: Database = Depends(get_db),
        tenant_id: str = Depends(_tenant),
    ) -> dict:
        _get_tenant_endpoint(db, endpoint_id, tenant_id)
        rows = db.query(
            "SELECT * FROM webhook_deliveries WHERE endpoint_id = :id"
            " AND tenant_id = :t ORDER BY created_at DESC, id DESC LIMIT :n",
            {"id": endpoint_id, "t": tenant_id, "n": limit},
        )
        return {"deliveries": [_delivery_view(r) for r in rows]}

    # ------------------------------------------------------------------
    # Internal event intake (emitter contract)
    # ------------------------------------------------------------------
    @app.post("/internal/events", dependencies=[Depends(_check_internal_token)])
    async def receive_event(request: Request, db: Database = Depends(get_db)) -> dict:
        try:
            envelope = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(status_code=400, detail="body must be a JSON event envelope")
        if not isinstance(envelope, dict):
            raise HTTPException(status_code=400, detail="event envelope must be an object")
        event_id = str(envelope.get("id") or "").strip()
        event_type = str(envelope.get("type") or "").strip()
        tenant_id = str(envelope.get("tenant_id") or "default").strip() or "default"
        data = envelope.get("data")
        if not event_id or not event_type or not isinstance(data, dict):
            raise HTTPException(
                status_code=422,
                detail="envelope requires id, type and object data",
            )
        if "created_at" not in envelope:
            envelope["created_at"] = int(time.time())
        envelope["tenant_id"] = tenant_id
        # Canonical stored payload = delivered body (byte-identical for
        # receiver signature verification).
        payload = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        if len(payload.encode("utf-8")) > MAX_DATA_BYTES + 4096:
            raise HTTPException(status_code=413, detail="event payload too large")

        received_at = chain.utc_now_iso()
        if db._is_pg:
            inserted = db.execute(
                "INSERT INTO webhook_events (id, type, tenant_id, payload, received_at)"
                " VALUES (:id, :ty, :t, :p, :r) ON CONFLICT (id) DO NOTHING",
                {"id": event_id, "ty": event_type, "t": tenant_id, "p": payload,
                 "r": received_at},
            )
        else:
            inserted = db.execute(
                "INSERT OR IGNORE INTO webhook_events (id, type, tenant_id, payload,"
                " received_at) VALUES (:id, :ty, :t, :p, :r)",
                {"id": event_id, "ty": event_type, "t": tenant_id, "p": payload,
                 "r": received_at},
            )
        if not inserted:
            logger.info("duplicate event id=%s; no fan-out", event_id)
            return {"status": "duplicate", "event_id": event_id, "deliveries": 0}

        # Fan out to this tenant's ACTIVE endpoints subscribed to the type
        # ("*" subscribes to everything). Disabled (circuit-open) endpoints
        # are skipped.
        endpoints = db.query(
            "SELECT id, event_types FROM webhook_endpoints"
            " WHERE tenant_id = :t AND status = 'active'",
            {"t": tenant_id},
        )
        now = time.time()
        created = 0
        for ep in endpoints:
            subscribed = json.loads(ep["event_types"] or "[]")
            if event_type not in subscribed and "*" not in subscribed:
                continue
            chain.insert_chained_delivery(
                db, delivery_id=f"whd_{uuid.uuid4().hex[:24]}",
                event_id=event_id, endpoint_id=ep["id"], tenant_id=tenant_id,
                next_attempt_at=now)
            created += 1
        logger.info("event %s (%s) tenant=%s -> %d deliveries",
                    event_id, event_type, tenant_id, created)
        return {"status": "accepted", "event_id": event_id, "deliveries": created}

    return app


app = create_app()
