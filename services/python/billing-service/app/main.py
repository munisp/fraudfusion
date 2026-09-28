"""FraudFusion billing & monetization service (:8400, /v1/billing/*).

Implements the platform's monetization stack (see docs/MONETIZATION.md):

- API key lifecycle: issue (plaintext shown exactly once, SHA-256 stored),
  rotate, revoke, list (prefix only). Data-plane auth via the
  ``require_api_key`` dependency: hash lookup, status/scope/expiry checks,
  per-key sliding-window rate limit, async buffered usage recording.
- Metering & rating: idempotent usage ingestion, monthly rollups, rating
  engine (subscription inclusion first, then per-call overage, integer kobo),
  invoice generation with a draft -> issued -> paid/void state machine, and
  dunning (past_due -> suspend keys after grace).
- Control-plane endpoints are tenant-scoped via Keycloak principals
  (fail-closed, see app/auth.py); billing_admin role is cross-tenant.

Schema: database/20260901_billing_monetization.sql (PostgreSQL; SQLite
mirror in app/db.py for local dev/tests).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Path, Query, status

from app.auth import Principal, get_current_principal
from app.db import Database, get_db
from app.keys import (
    UsageBuffer,
    SlidingWindowRateLimiter,
    generate_key,
    require_api_key,
    utcnow,
)
from app.rating import build_invoice_draft, parse_json_map
from app.schemas import (
    ApiKeyCreate,
    ApiKeyIssued,
    ApiKeyView,
    InvoiceTransition,
    SubscriptionCreate,
    UsageEventIn,
    VALID_OPERATIONS,
)

log = logging.getLogger("billing")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

SERVICE_NAME = "billing-service"
PERIOD_RE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")
INVOICE_DUE_DAYS = int(os.getenv("BILLING_INVOICE_DUE_DAYS", "14"))
DUNNING_GRACE_DAYS = int(os.getenv("BILLING_DUNNING_GRACE_DAYS", "7"))


def _decode_json_fields(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    out = dict(row)
    for f in fields:
        value = out.get(f)
        if isinstance(value, str):
            try:
                out[f] = json.loads(value)
            except ValueError:
                pass
    for f in ("expires_at", "last_used_at", "created_at", "updated_at", "issued_at", "paid_at",
              "due_date", "current_period_start", "current_period_end"):
        if f in out and out[f] is not None:
            out[f] = str(out[f])
    return out


def _get_active_subscription(db: Database, tenant_id: str) -> dict[str, Any] | None:
    return db.query_one(
        "SELECT * FROM billing_subscriptions WHERE tenant_id = :t "
        "AND status IN ('trialing', 'active', 'past_due') "
        "ORDER BY created_at DESC LIMIT 1",
        {"t": tenant_id},
    )


def _get_plan(db: Database, plan_id: str) -> dict[str, Any]:
    plan = db.query_one("SELECT * FROM billing_plans WHERE id = :p", {"p": plan_id})
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"plan '{plan_id}' not found")
    return plan


def _key_view(row: dict[str, Any]) -> ApiKeyView:
    r = _decode_json_fields(row, ("scopes",))
    return ApiKeyView(
        id=r["id"], tenant_id=r["tenant_id"], name=r["name"], key_prefix=r["key_prefix"],
        scopes=r["scopes"], rate_limit_rpm=r["rate_limit_rpm"], status=r["status"],
        expires_at=r.get("expires_at"), last_used_at=r.get("last_used_at"),
        created_at=str(r["created_at"]),
    )


def create_app(db: Database | None = None, flush_threshold: int | None = None) -> FastAPI:
    database = db or get_db()
    limiter = SlidingWindowRateLimiter()
    buffer = UsageBuffer(database, flush_threshold=flush_threshold)
    stop = threading.Event()

    def _flush_loop() -> None:
        interval = float(os.getenv("BILLING_USAGE_FLUSH_INTERVAL_SECONDS", "5"))
        while not stop.wait(interval):
            try:
                buffer.flush()
            except Exception:  # noqa: BLE001 - never kill the flush loop
                log.exception("usage buffer flush failed")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        thread = threading.Thread(target=_flush_loop, name="usage-flush", daemon=True)
        thread.start()
        yield
        stop.set()
        buffer.flush()

    app = FastAPI(title="FraudFusion Billing Service", version="1.0.0", lifespan=lifespan)
    app.state.db = database
    app.state.rate_limiter = limiter
    app.state.usage_buffer = buffer

    # -- health ------------------------------------------------------------
    @app.get("/health")
    def health() -> dict[str, Any]:
        backend = limiter.backend
        return {
            "status": "ok",
            "service": SERVICE_NAME,
            "db_backend": database.backend,
            # Loud signal: in-memory limits are per-replica, not global.
            "rate_limit_backend": backend,
            "rate_limit_warning": (
                None if backend == "redis"
                else "in-process rate limiting: limits are per-replica; set REDIS_URL for cluster-wide limits"
            ),
            "usage_buffer_pending": buffer.pending,
        }

    # -- API key lifecycle ---------------------------------------------------
    @app.post("/v1/billing/api-keys", response_model=ApiKeyIssued, status_code=201)
    def issue_api_key(body: ApiKeyCreate, principal: Principal = Depends(get_current_principal)):
        principal.require_tenant(body.tenant_id)
        if database.query_one("SELECT id FROM tenants WHERE id = :t", {"t": body.tenant_id}) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
        sub = _get_active_subscription(database, body.tenant_id)
        if sub is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "tenant has no active subscription; create one before issuing keys",
            )
        plan = _get_plan(database, sub["plan_id"])
        allowed = set(_parse_str_list(plan.get("allowed_scopes")))
        requested = set(body.scopes) if body.scopes else allowed
        if not requested <= allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"scopes {sorted(requested - allowed)} exceed plan '{plan['id']}' allowed scopes",
            )
        plaintext, prefix, key_hash = generate_key()
        key_id = str(uuid.uuid4())
        rate_limit = body.rate_limit_rpm or int(plan.get("default_rate_limit_rpm") or 60)
        database.execute(
            "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, rate_limit_rpm, expires_at) "
            "VALUES (:id, :t, :name, :prefix, :hash, :scopes, :rpm, :exp)",
            {
                "id": key_id, "t": body.tenant_id, "name": body.name, "prefix": prefix,
                "hash": key_hash, "scopes": json.dumps(sorted(requested)), "rpm": rate_limit,
                "exp": body.expires_at,
            },
        )
        row = database.query_one("SELECT * FROM api_keys WHERE id = :id", {"id": key_id})
        log.info("issued api key %s (prefix %s) for tenant %s", key_id, prefix, body.tenant_id)
        return ApiKeyIssued(**_key_view(row).model_dump(), plaintext_key=plaintext)

    @app.get("/v1/billing/api-keys", response_model=list[ApiKeyView])
    def list_api_keys(tenant_id: str = Query(...), principal: Principal = Depends(get_current_principal)):
        principal.require_tenant(tenant_id)
        rows = database.query(
            "SELECT * FROM api_keys WHERE tenant_id = :t ORDER BY created_at DESC", {"t": tenant_id}
        )
        # Prefix only: key_hash is never exposed by the view model.
        return [_key_view(r) for r in rows]

    @app.post("/v1/billing/api-keys/{key_id}/rotate", response_model=ApiKeyIssued)
    def rotate_api_key(key_id: str, principal: Principal = Depends(get_current_principal)):
        row = _get_key_or_404(database, key_id)
        principal.require_tenant(row["tenant_id"])
        if row["status"] == "revoked":
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot rotate a revoked key")
        plaintext, prefix, key_hash = generate_key()
        database.execute(
            "UPDATE api_keys SET key_prefix = :p, key_hash = :h, status = 'active', updated_at = :now WHERE id = :id",
            {"p": prefix, "h": key_hash, "now": utcnow(), "id": key_id},
        )
        row = database.query_one("SELECT * FROM api_keys WHERE id = :id", {"id": key_id})
        return ApiKeyIssued(**_key_view(row).model_dump(), plaintext_key=plaintext)

    @app.post("/v1/billing/api-keys/{key_id}/revoke", response_model=ApiKeyView)
    def revoke_api_key(key_id: str, principal: Principal = Depends(get_current_principal)):
        row = _get_key_or_404(database, key_id)
        principal.require_tenant(row["tenant_id"])
        if row["status"] == "revoked":
            return _key_view(row)  # idempotent
        database.execute(
            "UPDATE api_keys SET status = 'revoked', updated_at = :now WHERE id = :id",
            {"now": utcnow(), "id": key_id},
        )
        return _key_view(database.query_one("SELECT * FROM api_keys WHERE id = :id", {"id": key_id}))

    # -- metered data-plane (API-key auth) ------------------------------------
    @app.post("/v1/billing/meter/{operation}")
    def meter(operation: str = Path(...), key: dict[str, Any] = Depends(require_api_key)):
        if operation not in VALID_OPERATIONS:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown operation '{operation}'")
        return {
            "metered": True,
            "operation": operation,
            "tenant_id": key["tenant_id"],
            "api_key_prefix": key["key_prefix"],
        }

    # -- subscriptions ---------------------------------------------------------
    @app.post("/v1/billing/subscriptions", status_code=201)
    def create_subscription(body: SubscriptionCreate, principal: Principal = Depends(get_current_principal)):
        principal.require_tenant(body.tenant_id)
        if database.query_one("SELECT id FROM tenants WHERE id = :t", {"t": body.tenant_id}) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
        _get_plan(database, body.plan_id)
        if _get_active_subscription(database, body.tenant_id) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "tenant already has an active subscription")
        sub_id = str(uuid.uuid4())
        start = date.today().replace(day=1)
        end = (start.replace(day=28) + timedelta(days=7)).replace(day=1) - timedelta(days=1)
        database.execute(
            "INSERT INTO billing_subscriptions (id, tenant_id, plan_id, status, current_period_start, current_period_end, overrides) "
            "VALUES (:id, :t, :p, 'active', :start, :end, :ov)",
            {"id": sub_id, "t": body.tenant_id, "p": body.plan_id,
             "start": start.isoformat(), "end": end.isoformat(), "ov": json.dumps(body.overrides)},
        )
        return _decode_json_fields(
            database.query_one("SELECT * FROM billing_subscriptions WHERE id = :id", {"id": sub_id}),
            ("overrides",),
        )

    @app.get("/v1/billing/subscriptions/{tenant_id}")
    def get_subscription(tenant_id: str, principal: Principal = Depends(get_current_principal)):
        principal.require_tenant(tenant_id)
        sub = _get_active_subscription(database, tenant_id)
        if sub is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no active subscription")
        out = _decode_json_fields(sub, ("overrides",))
        out["plan"] = _decode_json_fields(_get_plan(database, sub["plan_id"]),
                                          ("included_units", "overage_rates_kobo", "allowed_scopes"))
        return out

    # -- usage ingestion -------------------------------------------------------
    @app.post("/v1/billing/usage", status_code=201)
    def ingest_usage(body: UsageEventIn, principal: Principal = Depends(get_current_principal)):
        principal.require_tenant(body.tenant_id)
        occurred_at = body.occurred_at or utcnow()
        inserted = database.insert_idempotent(
            "INSERT INTO usage_events (id, tenant_id, api_key_id, service, operation, units, amount_kobo, idempotency_key, occurred_at) "
            "VALUES (:id, :t, :key, :svc, :op, :units, 0, :idem, :occ)",
            {"id": str(uuid.uuid4()), "t": body.tenant_id, "key": body.api_key_id,
             "svc": body.service, "op": body.operation, "units": body.units,
             "idem": body.idempotency_key, "occ": occurred_at},
        )
        if inserted:
            database.execute(
                "INSERT INTO usage_rollups (tenant_id, period, operation, units, updated_at) "
                "VALUES (:t, :period, :op, :units, :now) "
                "ON CONFLICT (tenant_id, period, operation) DO UPDATE SET "
                "units = units + :units, updated_at = :now",
                {"t": body.tenant_id, "period": occurred_at[:7], "op": body.operation,
                 "units": body.units, "now": utcnow()},
            )
        return {"recorded": inserted, "idempotent_replay": not inserted,
                "idempotency_key": body.idempotency_key}

    @app.get("/v1/billing/usage/current")
    def current_usage(tenant_id: str = Query(...), principal: Principal = Depends(get_current_principal)):
        principal.require_tenant(tenant_id)
        period = date.today().isoformat()[:7]
        sub = _get_active_subscription(database, tenant_id)
        rollups = {
            r["operation"]: int(r["units"])
            for r in database.query(
                "SELECT operation, units FROM usage_rollups WHERE tenant_id = :t AND period = :p",
                {"t": tenant_id, "p": period},
            )
        }
        response: dict[str, Any] = {"tenant_id": tenant_id, "period": period, "usage": rollups}
        if sub is not None:
            plan = _get_plan(database, sub["plan_id"])
            draft = build_invoice_draft(tenant_id, period, plan,
                                        parse_json_map(sub.get("overrides")) if isinstance(sub.get("overrides"), str) else sub.get("overrides") or {},
                                        rollups)
            response["estimated_bill"] = {
                "subtotal_kobo": draft.subtotal_kobo,
                "vat_kobo": draft.vat_kobo,
                "total_kobo": draft.total_kobo,
                "currency": "NGN",
                "line_items": draft.line_items,
            }
        else:
            response["estimated_bill"] = None
        return response

    # -- invoices ---------------------------------------------------------------
    @app.post("/v1/billing/invoices/generate")
    def generate_invoices(period: str = Query(...), tenant_id: str | None = Query(default=None),
                          principal: Principal = Depends(get_current_principal)):
        if not PERIOD_RE.match(period):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "period must be YYYY-MM")
        if tenant_id:
            principal.require_tenant(tenant_id)
            subs = [s for s in [_get_active_subscription(database, tenant_id)] if s]
        elif principal.is_admin:
            subs = database.query(
                "SELECT * FROM billing_subscriptions WHERE status IN ('trialing', 'active', 'past_due')"
            )
        elif principal.tenant_id:
            # Tenant principals default to their own tenant (fail-closed).
            subs = [s for s in [_get_active_subscription(database, principal.tenant_id)] if s]
        else:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "billing admin role required for bulk generation")
        generated, skipped = [], []
        for sub in subs:
            existing = database.query_one(
                "SELECT * FROM billing_invoices WHERE tenant_id = :t AND period = :p",
                {"t": sub["tenant_id"], "p": period},
            )
            if existing is not None and existing["status"] != "draft":
                skipped.append({"tenant_id": sub["tenant_id"], "invoice_id": existing["id"],
                                "reason": f"invoice already {existing['status']}"})
                continue
            rollups = {
                r["operation"]: int(r["units"])
                for r in database.query(
                    "SELECT operation, units FROM usage_rollups WHERE tenant_id = :t AND period = :p",
                    {"t": sub["tenant_id"], "p": period},
                )
            }
            plan = _get_plan(database, sub["plan_id"])
            overrides = sub.get("overrides")
            overrides = parse_json_map(overrides) if isinstance(overrides, str) else (overrides or {})
            draft = build_invoice_draft(sub["tenant_id"], period, plan, overrides, rollups)
            if existing is None:
                invoice_id = str(uuid.uuid4())
                database.execute(
                    "INSERT INTO billing_invoices (id, tenant_id, subscription_id, period, line_items, subtotal_kobo, vat_kobo, total_kobo) "
                    "VALUES (:id, :t, :sub, :p, :items, :sub_k, :vat, :total)",
                    {"id": invoice_id, "t": sub["tenant_id"], "sub": sub["id"], "p": period,
                     "items": json.dumps(draft.line_items), "sub_k": draft.subtotal_kobo,
                     "vat": draft.vat_kobo, "total": draft.total_kobo},
                )
            else:
                invoice_id = existing["id"]
                database.execute(
                    "UPDATE billing_invoices SET line_items = :items, subtotal_kobo = :sub_k, vat_kobo = :vat, "
                    "total_kobo = :total, subscription_id = :sub, updated_at = :now WHERE id = :id",
                    {"items": json.dumps(draft.line_items), "sub_k": draft.subtotal_kobo,
                     "vat": draft.vat_kobo, "total": draft.total_kobo, "sub": sub["id"],
                     "now": utcnow(), "id": invoice_id},
                )
            generated.append({"tenant_id": sub["tenant_id"], "invoice_id": invoice_id,
                              "period": period, "subtotal_kobo": draft.subtotal_kobo,
                              "vat_kobo": draft.vat_kobo, "total_kobo": draft.total_kobo,
                              "currency": "NGN", "status": "draft"})
        return {"period": period, "generated": generated, "skipped": skipped}

    @app.get("/v1/billing/invoices")
    def list_invoices(tenant_id: str = Query(...), principal: Principal = Depends(get_current_principal)):
        principal.require_tenant(tenant_id)
        rows = database.query(
            "SELECT * FROM billing_invoices WHERE tenant_id = :t ORDER BY period DESC", {"t": tenant_id}
        )
        return [_decode_json_fields(r, ("line_items",)) for r in rows]

    @app.get("/v1/billing/invoices/{invoice_id}")
    def get_invoice(invoice_id: str, principal: Principal = Depends(get_current_principal)):
        row = _get_invoice_or_404(database, invoice_id)
        principal.require_tenant(row["tenant_id"])
        return _decode_json_fields(row, ("line_items",))

    @app.post("/v1/billing/invoices/{invoice_id}/issue")
    def issue_invoice(invoice_id: str, principal: Principal = Depends(get_current_principal)):
        row = _get_invoice_or_404(database, invoice_id)
        principal.require_tenant(row["tenant_id"])
        if row["status"] != "draft":
            raise HTTPException(status.HTTP_409_CONFLICT, f"cannot issue invoice in status '{row['status']}'")
        now = utcnow()
        due = (date.today() + timedelta(days=INVOICE_DUE_DAYS)).isoformat()
        database.execute(
            "UPDATE billing_invoices SET status = 'issued', issued_at = :now, due_date = :due, updated_at = :now WHERE id = :id",
            {"now": now, "due": due, "id": invoice_id},
        )
        return _decode_json_fields(database.query_one("SELECT * FROM billing_invoices WHERE id = :id", {"id": invoice_id}), ("line_items",))

    @app.post("/v1/billing/invoices/{invoice_id}/pay")
    def pay_invoice(invoice_id: str, body: InvoiceTransition | None = None,
                    principal: Principal = Depends(get_current_principal)):
        row = _get_invoice_or_404(database, invoice_id)
        principal.require_tenant(row["tenant_id"])
        if row["status"] != "issued":
            raise HTTPException(status.HTTP_409_CONFLICT, f"cannot pay invoice in status '{row['status']}'")
        journal_id = (body.settlement_journal_id if body else None) or None
        # The settlement journal (DR accounts-receivable / CR revenue) is
        # posted by the ledger-control-service; we record its UUID here as the
        # double-entry link. See docs/MONETIZATION.md.
        database.execute(
            "UPDATE billing_invoices SET status = 'paid', paid_at = :now, settlement_journal_id = :j, updated_at = :now WHERE id = :id",
            {"now": utcnow(), "j": journal_id, "id": invoice_id},
        )
        # Paying clears dunning: resume the subscription if it was past_due.
        database.execute(
            "UPDATE billing_subscriptions SET status = 'active', updated_at = :now "
            "WHERE tenant_id = :t AND status = 'past_due'",
            {"now": utcnow(), "t": row["tenant_id"]},
        )
        return _decode_json_fields(database.query_one("SELECT * FROM billing_invoices WHERE id = :id", {"id": invoice_id}), ("line_items",))

    @app.post("/v1/billing/invoices/{invoice_id}/void")
    def void_invoice(invoice_id: str, principal: Principal = Depends(get_current_principal)):
        row = _get_invoice_or_404(database, invoice_id)
        principal.require_tenant(row["tenant_id"])
        if row["status"] in ("paid", "void"):
            raise HTTPException(status.HTTP_409_CONFLICT, f"cannot void invoice in status '{row['status']}'")
        database.execute(
            "UPDATE billing_invoices SET status = 'void', updated_at = :now WHERE id = :id",
            {"now": utcnow(), "id": invoice_id},
        )
        return _decode_json_fields(database.query_one("SELECT * FROM billing_invoices WHERE id = :id", {"id": invoice_id}), ("line_items",))

    # -- dunning -----------------------------------------------------------------
    @app.post("/v1/billing/dunning/run")
    def run_dunning(as_of: str | None = Query(default=None),
                    principal: Principal = Depends(get_current_principal)):
        if not principal.is_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "billing admin role required")
        today = date.fromisoformat(as_of) if as_of else date.today()
        overdue = database.query(
            "SELECT * FROM billing_invoices WHERE status = 'issued' AND due_date IS NOT NULL AND due_date < :today",
            {"today": today.isoformat()},
        )
        past_due, suspended = [], []
        for inv in overdue:
            tenant = inv["tenant_id"]
            sub = _get_active_subscription(database, tenant)
            if sub is not None and sub["status"] != "past_due":
                database.execute(
                    "UPDATE billing_subscriptions SET status = 'past_due', updated_at = :now WHERE id = :id",
                    {"now": utcnow(), "id": sub["id"]},
                )
                _dunning_event(database, tenant, inv["id"], "past_due",
                               f"invoice {inv['id']} past due {inv['due_date']}", principal.sub or "system")
                past_due.append(tenant)
            due = date.fromisoformat(str(inv["due_date"]))
            if (today - due).days > DUNNING_GRACE_DAYS:
                if sub is not None and sub["status"] != "suspended":
                    database.execute(
                        "UPDATE billing_subscriptions SET status = 'suspended', updated_at = :now WHERE id = :id",
                        {"now": utcnow(), "id": sub["id"]},
                    )
                count = database.execute(
                    "UPDATE api_keys SET status = 'suspended', updated_at = :now "
                    "WHERE tenant_id = :t AND status = 'active'",
                    {"now": utcnow(), "t": tenant},
                )
                if count:
                    _dunning_event(database, tenant, inv["id"], "suspend_keys",
                                   f"{count} key(s) suspended after {DUNNING_GRACE_DAYS}d grace",
                                   principal.sub or "system")
                    suspended.append(tenant)
        return {"as_of": today.isoformat(), "past_due_tenants": past_due,
                "suspended_tenants": suspended, "grace_days": DUNNING_GRACE_DAYS}

    return app


def _parse_str_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(s) for s in raw]
    try:
        return [str(s) for s in json.loads(raw or "[]")]
    except (TypeError, ValueError):
        return []


def _get_key_or_404(db: Database, key_id: str) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM api_keys WHERE id = :id", {"id": key_id})
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "api key not found")
    return row


def _get_invoice_or_404(db: Database, invoice_id: str) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM billing_invoices WHERE id = :id", {"id": invoice_id})
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invoice not found")
    return row


def _dunning_event(db: Database, tenant_id: str, invoice_id: str, action: str,
                   detail: str, actor: str) -> None:
    db.execute(
        "INSERT INTO billing_dunning_events (id, tenant_id, invoice_id, action, detail, actor) "
        "VALUES (:id, :t, :inv, :action, :detail, :actor)",
        {"id": str(uuid.uuid4()), "t": tenant_id, "inv": invoice_id,
         "action": action, "detail": detail, "actor": actor},
    )


app = create_app()
