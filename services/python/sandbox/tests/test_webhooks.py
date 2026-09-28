"""Webhook simulation: signing scheme conformance (shared plan contract)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import httpx
import pytest

from app import fixtures, webhooks
from tests.conftest import AUTH

SECRET = fixtures.WEBHOOK_DEMO_SECRET


def _contract_signature(secret: str, t: int, body: bytes) -> str:
    """Independent reimplementation of the FINAL shared contract:
    v1 = HMAC-SHA256(key=sha256(secret).hexdigest().encode(), msg="<t>.<body>")."""
    key = hashlib.sha256(secret.encode("utf-8")).hexdigest().encode("utf-8")
    return hmac.new(key, f"{t}.".encode() + body, hashlib.sha256).hexdigest()


class _Receiver:
    """Captures what httpx.post would have sent."""

    def __init__(self, status_code: int = 200):
        self.calls: list[dict] = []
        self.status_code = status_code

    def post(self, url, content=None, headers=None, timeout=None, **_):
        self.calls.append({"url": url, "content": content,
                           "headers": headers or {}, "timeout": timeout})
        return httpx.Response(self.status_code, json={"ok": True})


@pytest.fixture()
def receiver(monkeypatch):
    rec = _Receiver()
    monkeypatch.setattr(httpx, "post", rec.post)
    return rec


class TestSigningScheme:
    def test_known_answer_vector(self):
        body = b'{"id":"evt_1","type":"kyc.verification.completed"}'
        t = 1_700_000_000
        header = webhooks.sign_body(SECRET, body, timestamp=t)
        expected = _contract_signature(SECRET, t, body)
        assert header == f"t={t},v1={expected}"

    def test_key_derivation_not_raw_secret(self):
        # v1 must NOT match a raw-secret HMAC — derivation is contractual.
        body = b"{}"
        t = 1_700_000_000
        header = webhooks.sign_body(SECRET, body, timestamp=t)
        raw = hmac.new(SECRET.encode(), f"{t}.".encode() + body,
                       hashlib.sha256).hexdigest()
        assert header != f"t={t},v1={raw}"

    def test_verify_roundtrip(self):
        body = webhooks.encode_event(
            webhooks.build_event("kyc.verification.completed"))
        header = webhooks.sign_body(SECRET, body)
        assert webhooks.verify_signature(SECRET, body, header) is True

    def test_verify_rejects_tampered_body(self):
        body = webhooks.encode_event(
            webhooks.build_event("kyb.verification.completed"))
        header = webhooks.sign_body(SECRET, body)
        assert webhooks.verify_signature(SECRET, body + b" ", header) is False

    def test_verify_rejects_stale_timestamp(self):
        body = b"{}"
        header = webhooks.sign_body(SECRET, body,
                                    timestamp=int(time.time()) - 301)
        assert webhooks.verify_signature(SECRET, body, header) is False

    def test_verify_rejects_wrong_secret(self):
        body = b"{}"
        header = webhooks.sign_body(SECRET, body)
        assert webhooks.verify_signature("whsec_other", body, header) is False


class TestTriggerEvent:
    def test_fires_signed_webhook_and_returns_signature(self, client, receiver):
        r = client.post("/sandbox/trigger-event", headers=AUTH, json={
            "url": "http://localhost:9999/receiver",
            "event_type": "kyc.verification.completed",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["delivered"] is True
        assert body["http_status"] == 200
        assert body["environment"] == "sandbox" and body["synthetic"] is True
        assert body["webhook_secret"] == SECRET
        header = body["signature_header"]
        assert header.startswith("t=") and ",v1=" in header

        # The receiver actually got a verifiable signed request.
        assert len(receiver.calls) == 1
        call = receiver.calls[0]
        sent_header = call["headers"]["X-FraudFusion-Signature"]
        assert sent_header == header
        assert webhooks.verify_signature(SECRET, call["content"],
                                         sent_header) is True
        # Independent contract check against the captured raw body.
        t_str, v1 = sent_header.split(",")
        t = int(t_str[2:])
        assert v1[3:] == _contract_signature(SECRET, t, call["content"])

    def test_envelope_shape(self, client, receiver):
        client.post("/sandbox/trigger-event", headers=AUTH, json={
            "url": "http://localhost:9999/hook",
            "event_type": "kyb.verification.completed",
        })
        event = json.loads(receiver.calls[0]["content"])
        assert {"id", "type", "created_at", "tenant_id", "data"} <= set(event)
        assert event["type"] == "kyb.verification.completed"
        assert event["tenant_id"] == "tenant_sandbox"
        assert event["data"]["verdict"] == "verified"

    def test_payload_overrides_merge_into_data(self, client, receiver):
        client.post("/sandbox/trigger-event", headers=AUTH, json={
            "url": "http://localhost:9999/hook",
            "event_type": "identity.exposure.detected",
            "payload_overrides": {"exposure_type": "sim_swap",
                                  "severity": "high"},
        })
        data = json.loads(receiver.calls[0]["content"])["data"]
        assert data["exposure_type"] == "sim_swap"
        assert data["severity"] == "high"
        assert data["alert_id"].startswith("alert_")

    def test_all_event_types_supported(self, client, receiver):
        for event_type in fixtures.WEBHOOK_EVENT_TYPES:
            r = client.post("/sandbox/trigger-event", headers=AUTH, json={
                "url": "http://localhost:9999/hook", "event_type": event_type})
            assert r.status_code == 200, event_type
            assert r.json()["event"]["type"] == event_type

    def test_unknown_event_type_422(self, client):
        r = client.post("/sandbox/trigger-event", headers=AUTH, json={
            "url": "http://localhost:9999/hook", "event_type": "nope"})
        assert r.status_code == 422

    def test_bad_url_422(self, client):
        for url in ("not-a-url", "ftp://example.com/x", "file:///etc/passwd"):
            r = client.post("/sandbox/trigger-event", headers=AUTH, json={
                "url": url, "event_type": "kyc.verification.completed"})
            assert r.status_code == 422, url

    def test_receiver_5xx_reported_not_raised(self, client, monkeypatch):
        rec = _Receiver(status_code=500)
        monkeypatch.setattr(httpx, "post", rec.post)
        r = client.post("/sandbox/trigger-event", headers=AUTH, json={
            "url": "http://localhost:9999/hook",
            "event_type": "kyc.verification.completed"})
        body = r.json()
        assert r.status_code == 200
        assert body["delivered"] is False
        assert body["http_status"] == 500
        assert body["error"]

    def test_transport_error_reported_not_raised(self, client, monkeypatch):
        def boom(*a, **k):
            raise httpx.ConnectError("connection refused")
        monkeypatch.setattr(httpx, "post", boom)
        r = client.post("/sandbox/trigger-event", headers=AUTH, json={
            "url": "http://localhost:1/hook",
            "event_type": "kyc.verification.completed"})
        body = r.json()
        assert r.status_code == 200
        assert body["delivered"] is False
        assert "ConnectError" in body["error"]
        assert body["signature_header"]  # signature still returned


class TestFixturesEndpoint:
    def test_seeded_customers(self, client):
        r = client.get("/sandbox/fixtures", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert body["environment"] == "sandbox" and body["synthetic"] is True
        customers = body["test_customers"]
        assert len(customers) == 10
        ids = [c["customer_id"] for c in customers]
        assert len(set(ids)) == 10
        # Magic-suffix coverage present in the seeded set.
        suffixes = {c["bvn"][-3:] for c in customers}
        assert {"000", "001", "002", "003"} <= suffixes
        outcomes = {c["bvn"][-3:]: c["expected_decision"] for c in customers}
        assert outcomes["000"] == "approved"
        assert outcomes["001"] == "manual_review"
        assert outcomes["002"] == "rejected"
        assert outcomes["003"] == "rejected"  # sanctions hit
        assert body["webhook_demo_secret"] == SECRET
        assert {b["cac_number"] for b in body["test_businesses"]} == {
            "RC000000", "RC000001", "RC000002"}

    def test_seeded_customers_behave_as_documented(self, client):
        for c in client.get("/sandbox/fixtures", headers=AUTH).json()[
                "test_customers"]:
            r = client.post("/api/v1/kyc/verify", headers=AUTH, json={
                "customer_id": c["customer_id"], "bvn": c["bvn"],
                "nin": c["nin"], "phone": c["phone"], "email": c["email"],
                "first_name": c["first_name"], "last_name": c["last_name"]})
            assert r.json()["decision"] == c["expected_decision"], c
