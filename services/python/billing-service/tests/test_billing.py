"""End-to-end tests for the billing service (SQLite backend, auth stubbed).

Control-plane auth is exercised through dependency overrides; the fail-closed
Keycloak introspection path is shared with onboarding-service. Data-plane
API-key auth is exercised for real through the /v1/billing/meter/* endpoints.
"""

from __future__ import annotations

import hashlib
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, get_current_principal
from app.db import Database, get_db, reset_db_for_tests
from app.main import create_app
from app.rating import build_invoice_draft, rate_operation, vat_kobo

TENANT_USER = Principal(sub="user-1", username="ada", roles=set(), tenant_id="tenant-1")
TENANT2_USER = Principal(sub="user-2", username="bola", roles=set(), tenant_id="tenant-2")
ADMIN = Principal(sub="staff-1", username="staff", roles={"billing_admin"})


@pytest.fixture()
def db(tmp_path):
    database = Database(database_url="", sqlite_path=str(tmp_path / "billing.db"))
    for tenant in ("tenant-1", "tenant-2"):
        database.execute(
            "INSERT INTO tenants (id, organization, contact_email, owner_sub, state) "
            "VALUES (:id, :org, :email, :sub, 'active')",
            {"id": tenant, "org": f"Org {tenant}", "email": f"{tenant}@example.com", "sub": f"user-{tenant}"},
        )
    yield database
    reset_db_for_tests(None)


def make_client(db, principal, flush_threshold=1):
    app = create_app(db=db, flush_threshold=flush_threshold)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_principal] = lambda: principal
    return TestClient(app)


def subscribe(client, tenant_id, plan="growth"):
    resp = client.post("/v1/billing/subscriptions", json={"tenant_id": tenant_id, "plan_id": plan})
    assert resp.status_code == 201, resp.text
    return resp.json()


def issue_key(client, tenant_id="tenant-1", scopes=None, rpm=None):
    body = {"tenant_id": tenant_id, "name": "default"}
    if scopes is not None:
        body["scopes"] = scopes
    if rpm is not None:
        body["rate_limit_rpm"] = rpm
    resp = client.post("/v1/billing/api-keys", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# API key lifecycle
# ---------------------------------------------------------------------------

def test_issue_key_returns_plaintext_once_and_stores_hash_only(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client)
    plaintext = issued["plaintext_key"]
    assert plaintext.startswith("ffk_live_") and len(plaintext) == len("ffk_live_") + 32
    # Hash-only storage: sha256(plaintext) is in the DB, plaintext is not.
    row = db.query_one("SELECT * FROM api_keys WHERE id = :id", {"id": issued["id"]})
    assert row["key_hash"] == hashlib.sha256(plaintext.encode()).hexdigest()
    assert plaintext not in str(row)
    assert row["key_prefix"] == plaintext[: len("ffk_live_") + 8]


def test_list_keys_returns_prefix_only(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client)
    keys = client.get("/v1/billing/api-keys", params={"tenant_id": "tenant-1"}).json()
    assert len(keys) == 1
    assert keys[0]["key_prefix"] == issued["key_prefix"]
    assert "key_hash" not in keys[0]
    assert "plaintext_key" not in keys[0]


def test_rotate_key_invalidates_old_and_returns_new_plaintext_once(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client)
    rotated = client.post(f"/v1/billing/api-keys/{issued['id']}/rotate")
    assert rotated.status_code == 200, rotated.text
    new_plaintext = rotated.json()["plaintext_key"]
    assert new_plaintext != issued["plaintext_key"]
    old_hash = hashlib.sha256(issued["plaintext_key"].encode()).hexdigest()
    assert db.query_one("SELECT id FROM api_keys WHERE key_hash = :h", {"h": old_hash}) is None
    # Old key rejected, new key accepted on the data plane.
    assert client.post("/v1/billing/meter/fraud_score", headers={"X-API-Key": issued["plaintext_key"]}).status_code == 401
    assert client.post("/v1/billing/meter/fraud_score", headers={"X-API-Key": new_plaintext}).status_code == 200


def test_revocation_blocks_data_plane_and_is_idempotent(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client)
    assert client.post("/v1/billing/meter/fraud_score", headers={"X-API-Key": issued["plaintext_key"]}).status_code == 200
    resp = client.post(f"/v1/billing/api-keys/{issued['id']}/revoke")
    assert resp.status_code == 200 and resp.json()["status"] == "revoked"
    # Idempotent: revoking again returns 200, still revoked.
    assert client.post(f"/v1/billing/api-keys/{issued['id']}/revoke").json()["status"] == "revoked"
    assert client.post("/v1/billing/meter/fraud_score", headers={"X-API-Key": issued["plaintext_key"]}).status_code == 403
    # Rotating a revoked key is rejected.
    assert client.post(f"/v1/billing/api-keys/{issued['id']}/rotate").status_code == 409


def test_expired_key_rejected(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client)
    db.execute("UPDATE api_keys SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = :id",
               {"id": issued["id"]})
    assert client.post("/v1/billing/meter/fraud_score", headers={"X-API-Key": issued["plaintext_key"]}).status_code == 401


# ---------------------------------------------------------------------------
# Fail-closed data-plane auth and scope enforcement
# ---------------------------------------------------------------------------

def test_missing_or_invalid_key_401(db):
    client = make_client(db, TENANT_USER)
    assert client.post("/v1/billing/meter/fraud_score").status_code == 401
    assert client.post("/v1/billing/meter/fraud_score", headers={"X-API-Key": "ffk_live_nope"}).status_code == 401


def test_scope_enforcement_403(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client, scopes=["fraud_score"])
    assert client.post("/v1/billing/meter/fraud_score", headers={"X-API-Key": issued["plaintext_key"]}).status_code == 200
    assert client.post("/v1/billing/meter/aml_score", headers={"X-API-Key": issued["plaintext_key"]}).status_code == 403


def test_unknown_scope_rejected_at_creation(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    resp = client.post("/v1/billing/api-keys",
                       json={"tenant_id": "tenant-1", "scopes": ["wire_transfer"]})
    assert resp.status_code == 422


def test_scopes_beyond_plan_denied(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1", plan="developer_sandbox")  # no land_verification
    resp = client.post("/v1/billing/api-keys",
                       json={"tenant_id": "tenant-1", "scopes": ["land_verification"]})
    assert resp.status_code == 403


def test_rate_limit_enforced_429(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client, rpm=2)
    headers = {"X-API-Key": issued["plaintext_key"]}
    assert client.post("/v1/billing/meter/fraud_score", headers=headers).status_code == 200
    assert client.post("/v1/billing/meter/fraud_score", headers=headers).status_code == 200
    assert client.post("/v1/billing/meter/fraud_score", headers=headers).status_code == 429


def test_health_reports_rate_limit_backend_loudly(db):
    client = make_client(db, TENANT_USER)
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["rate_limit_backend"] == "memory"  # REDIS_URL unset in tests
    assert body["rate_limit_warning"]  # loud warning present


def test_metered_call_records_usage_via_buffer(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    issued = issue_key(client)
    for _ in range(3):
        assert client.post("/v1/billing/meter/fraud_score",
                           headers={"X-API-Key": issued["plaintext_key"]}).status_code == 200
    # flush_threshold=1 in tests, so events are flushed synchronously.
    rollup = db.query_one(
        "SELECT units FROM usage_rollups WHERE tenant_id = 'tenant-1' AND operation = 'fraud_score'")
    assert rollup["units"] == 3
    row = db.query_one("SELECT last_used_at FROM api_keys WHERE id = :id", {"id": issued["id"]})
    assert row["last_used_at"]


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------

def test_tenant_isolation_403(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    subscribe(make_client(db, TENANT2_USER), "tenant-2")
    # tenant-1 principal cannot list tenant-2 keys or subscriptions
    assert client.get("/v1/billing/api-keys", params={"tenant_id": "tenant-2"}).status_code == 403
    assert client.get("/v1/billing/subscriptions/tenant-2").status_code == 403
    assert client.get("/v1/billing/usage/current", params={"tenant_id": "tenant-2"}).status_code == 403


def test_admin_is_cross_tenant(db):
    client = make_client(db, ADMIN)
    subscribe(client, "tenant-1")
    assert client.get("/v1/billing/api-keys", params={"tenant_id": "tenant-1"}).status_code == 200


# ---------------------------------------------------------------------------
# Usage ingestion idempotency
# ---------------------------------------------------------------------------

def test_usage_ingest_idempotent(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1")
    event = {"tenant_id": "tenant-1", "service": "fraud-scoring", "operation": "fraud_score",
             "units": 10, "idempotency_key": "evt-123", "occurred_at": "2026-08-15T10:00:00+00:00"}
    first = client.post("/v1/billing/usage", json=event)
    assert first.status_code == 201 and first.json()["recorded"] is True
    replay = client.post("/v1/billing/usage", json=event)
    assert replay.status_code == 201
    assert replay.json()["recorded"] is False and replay.json()["idempotent_replay"] is True
    rollup = db.query_one(
        "SELECT units FROM usage_rollups WHERE tenant_id = 'tenant-1' AND period = '2026-08' AND operation = 'fraud_score'")
    assert rollup["units"] == 10  # counted once


# ---------------------------------------------------------------------------
# Rating math (unit-level)
# ---------------------------------------------------------------------------

def test_rate_operation_inclusion_then_overage():
    rated = rate_operation("fraud_score", 50100,
                           {"fraud_score": 50000}, {"fraud_score": 40})
    assert rated.included_units == 50000
    assert rated.billable_units == 100
    assert rated.amount_kobo == 100 * 40


def test_rate_operation_within_inclusion_is_free():
    rated = rate_operation("fraud_score", 49999,
                           {"fraud_score": 50000}, {"fraud_score": 40})
    assert rated.billable_units == 0 and rated.amount_kobo == 0


def test_vat_rounded_half_up_decimal_safe():
    assert vat_kobo(15000000) == 1125000          # 7.5% exact
    assert vat_kobo(100) == 8                     # 7.5 -> 8 half-up
    assert vat_kobo(15004000) == 1125300
    assert vat_kobo(0) == 0


def test_invoice_draft_math_unit():
    plan = {"id": "growth", "display_name": "Growth", "monthly_fee_kobo": 15000000,
            "included_units": {"fraud_score": 50000}, "overage_rates_kobo": {"fraud_score": 40}}
    draft = build_invoice_draft("t", "2026-08", plan, {}, {"fraud_score": 50100})
    assert draft.subtotal_kobo == 15000000 + 4000
    assert draft.total_kobo == 15004000 + 1125300


# ---------------------------------------------------------------------------
# Invoice generation + state machine
# ---------------------------------------------------------------------------

def _seed_growth_usage(client, db, tenant="tenant-1", period="2026-08", fraud_units=50100):
    subscribe(client, tenant, plan="growth")
    client.post("/v1/billing/usage", json={
        "tenant_id": tenant, "service": "fraud-scoring", "operation": "fraud_score",
        "units": fraud_units, "idempotency_key": f"{tenant}-fraud",
        "occurred_at": f"{period}-15T10:00:00+00:00"})


def test_invoice_generation_totals(db):
    client = make_client(db, TENANT_USER)
    _seed_growth_usage(client, db)
    resp = client.post("/v1/billing/invoices/generate", params={"period": "2026-08"})
    assert resp.status_code == 200, resp.text
    gen = resp.json()["generated"]
    assert len(gen) == 1
    invoice = gen[0]
    assert invoice["subtotal_kobo"] == 15004000       # NGN 150,000 fee + 100 x 40k overage
    assert invoice["vat_kobo"] == 1125300
    assert invoice["total_kobo"] == 16129300
    assert invoice["status"] == "draft" and invoice["currency"] == "NGN"


def test_invoice_regeneration_updates_draft_but_not_issued(db):
    client = make_client(db, TENANT_USER)
    _seed_growth_usage(client, db)
    first = client.post("/v1/billing/invoices/generate", params={"period": "2026-08"}).json()["generated"][0]
    # More usage arrives; regenerating the draft picks it up.
    client.post("/v1/billing/usage", json={
        "tenant_id": "tenant-1", "service": "aml", "operation": "aml_score",
        "units": 10100, "idempotency_key": "t1-aml", "occurred_at": "2026-08-16T10:00:00+00:00"})
    second = client.post("/v1/billing/invoices/generate", params={"period": "2026-08"}).json()["generated"][0]
    assert second["invoice_id"] == first["invoice_id"]
    assert second["subtotal_kobo"] == 15004000 + 100 * 90  # aml overage: 100 units x 90k
    # Issue it; regeneration must now skip.
    client.post(f"/v1/billing/invoices/{first['invoice_id']}/issue")
    skipped = client.post("/v1/billing/invoices/generate", params={"period": "2026-08"}).json()["skipped"]
    assert skipped and skipped[0]["reason"] == "invoice already issued"


def test_invoice_state_machine_transitions(db):
    client = make_client(db, TENANT_USER)
    _seed_growth_usage(client, db)
    invoice_id = client.post("/v1/billing/invoices/generate",
                             params={"period": "2026-08"}).json()["generated"][0]["invoice_id"]
    # draft -> issued
    issued = client.post(f"/v1/billing/invoices/{invoice_id}/issue")
    assert issued.status_code == 200 and issued.json()["status"] == "issued"
    assert issued.json()["due_date"] == (date.today() + timedelta(days=14)).isoformat()
    # invalid: pay from issued is fine, but issue twice is a conflict
    assert client.post(f"/v1/billing/invoices/{invoice_id}/issue").status_code == 409
    # issued -> paid with a ledger settlement journal link
    journal = "11111111-2222-3333-4444-555555555555"
    paid = client.post(f"/v1/billing/invoices/{invoice_id}/pay",
                       json={"settlement_journal_id": journal})
    assert paid.status_code == 200 and paid.json()["status"] == "paid"
    assert paid.json()["settlement_journal_id"] == journal
    # terminal states: cannot void or re-pay
    assert client.post(f"/v1/billing/invoices/{invoice_id}/void").status_code == 409
    assert client.post(f"/v1/billing/invoices/{invoice_id}/pay", json={}).status_code == 409


def test_invoice_void_from_draft(db):
    client = make_client(db, TENANT_USER)
    _seed_growth_usage(client, db)
    invoice_id = client.post("/v1/billing/invoices/generate",
                             params={"period": "2026-08"}).json()["generated"][0]["invoice_id"]
    voided = client.post(f"/v1/billing/invoices/{invoice_id}/void")
    assert voided.status_code == 200 and voided.json()["status"] == "void"
    assert client.post(f"/v1/billing/invoices/{invoice_id}/issue").status_code == 409


def test_generate_requires_valid_period(db):
    client = make_client(db, TENANT_USER)
    assert client.post("/v1/billing/invoices/generate", params={"period": "2026-13"}).status_code == 422
    assert client.post("/v1/billing/invoices/generate", params={"period": "Aug-26"}).status_code == 422


# ---------------------------------------------------------------------------
# Estimated bill & dunning
# ---------------------------------------------------------------------------

def test_current_usage_estimated_bill(db):
    client = make_client(db, TENANT_USER)
    subscribe(client, "tenant-1", plan="growth")
    period = date.today().isoformat()[:7]
    client.post("/v1/billing/usage", json={
        "tenant_id": "tenant-1", "service": "fraud-scoring", "operation": "fraud_score",
        "units": 50250, "idempotency_key": "cur-1", "occurred_at": f"{period}-02T00:00:00+00:00"})
    body = client.get("/v1/billing/usage/current", params={"tenant_id": "tenant-1"}).json()
    assert body["usage"]["fraud_score"] == 50250
    est = body["estimated_bill"]
    assert est["subtotal_kobo"] == 15000000 + 250 * 40
    assert est["total_kobo"] == est["subtotal_kobo"] + est["vat_kobo"]


def test_dunning_marks_past_due_then_suspends_keys_after_grace(db):
    client = make_client(db, ADMIN)
    _seed_growth_usage(client, db)
    issued_key = issue_key(client)
    invoice_id = client.post("/v1/billing/invoices/generate",
                             params={"period": "2026-08"}).json()["generated"][0]["invoice_id"]
    client.post(f"/v1/billing/invoices/{invoice_id}/issue")
    db.execute("UPDATE billing_invoices SET due_date = '2026-09-10' WHERE id = :id", {"id": invoice_id})

    # 1 day overdue: past_due but keys still work (grace period).
    out = client.post("/v1/billing/dunning/run", params={"as_of": "2026-09-11"}).json()
    assert out["past_due_tenants"] == ["tenant-1"] and out["suspended_tenants"] == []
    assert client.post("/v1/billing/meter/fraud_score",
                       headers={"X-API-Key": issued_key["plaintext_key"]}).status_code == 200

    # Beyond grace (7 days): keys suspended, data plane rejects with 403.
    out = client.post("/v1/billing/dunning/run", params={"as_of": "2026-09-20"}).json()
    assert out["suspended_tenants"] == ["tenant-1"]
    assert client.post("/v1/billing/meter/fraud_score",
                       headers={"X-API-Key": issued_key["plaintext_key"]}).status_code == 403
    events = db.query("SELECT action FROM billing_dunning_events WHERE tenant_id = 'tenant-1'")
    assert {e["action"] for e in events} == {"past_due", "suspend_keys"}
