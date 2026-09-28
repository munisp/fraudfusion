"""Client tests — fully offline via httpx.MockTransport (no network)."""

import base64
import json

import httpx
import pytest

from fraudfusion import (
    AuthenticationError,
    ConflictError,
    FraudFusionClient,
    FraudFusionError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
    ValidationError,
    new_idempotency_key,
)

API_KEY = "ffk_test_" + "ab" * 16
BASE = "http://sandbox.test"


class Recorder:
    """MockTransport handler factory: records requests, replays queued
    responses (or routes by (method, path))."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def client(self, handler, **kw) -> FraudFusionClient:
        kw.setdefault("retry_base_delay", 0.0)
        return FraudFusionClient(
            API_KEY, BASE, transport=httpx.MockTransport(handler), **kw)

    def queue(self, *responses: httpx.Response, **kw) -> FraudFusionClient:
        queue = list(responses)

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            assert queue, f"unexpected extra request: {request.method} {request.url.path}"
            return queue.pop(0)

        return self.client(handler, **kw)

    def router(self, routes: dict, **kw) -> FraudFusionClient:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            key = (request.method, request.url.path)
            assert key in routes, f"no route for {key}"
            out = routes[key]
            body, status = out if isinstance(out, tuple) else (out, 200)
            return httpx.Response(status, json=body)

        return self.client(handler, **kw)


def json_response(body, status=200, headers=None):
    return httpx.Response(status, json=body, headers=headers)


@pytest.fixture
def rec():
    return Recorder()


# --------------------------------------------------------------------------
# auth header + idempotency
# --------------------------------------------------------------------------

def test_api_key_header_and_auto_idempotency(rec):
    client = rec.router({("POST", "/api/v1/kyc/verify/basic"): {"request_id": "r1"}})
    client.kyc_verify(customer_id="c1", first_name="Ada", last_name="Lovelace")
    req = rec.requests[0]
    assert req.headers["X-API-Key"] == API_KEY
    assert req.headers["Idempotency-Key"]  # auto-generated
    body = json.loads(req.content)
    assert body == {"customer_id": "c1", "first_name": "Ada", "last_name": "Lovelace"}


def test_explicit_idempotency_key(rec):
    key = new_idempotency_key()
    client = rec.router({("POST", "/api/v1/kyc/verify/basic"): {}})
    client.kyc_verify(customer_id="c1", first_name="a", last_name="b",
                      idempotency_key=key)
    assert rec.requests[0].headers["Idempotency-Key"] == key


def test_idempotency_opt_out(rec):
    client = rec.router({("POST", "/api/v1/kyc/verify/basic"): {}})
    client.kyc_verify(customer_id="c1", first_name="a", last_name="b",
                      idempotency_key=False)
    assert "Idempotency-Key" not in rec.requests[0].headers


# --------------------------------------------------------------------------
# KYC
# --------------------------------------------------------------------------

def test_kyc_verify_levels_and_payloads(rec):
    routes = {
        ("POST", "/api/v1/kyc/verify/basic"): {"verification_level": "basic"},
        ("POST", "/api/v1/kyc/verify/enhanced"): {"verification_level": "enhanced"},
        ("POST", "/api/v1/kyc/verify/premium"): {"verification_level": "premium"},
    }
    client = rec.router(routes)
    base = dict(customer_id="c1", first_name="a", last_name="b")
    assert client.kyc_verify(**base)["verification_level"] == "basic"
    assert client.kyc_verify(**base, level="enhanced", check_pep=True,
                             check_sanctions=True, nationality="NG")[
        "verification_level"] == "enhanced"
    assert client.kyc_verify(**base, level="premium", check_credit_bureau=True,
                             credit_bureau_provider="crc")[
        "verification_level"] == "premium"

    enhanced_body = json.loads(rec.requests[1].content)
    assert enhanced_body["check_pep"] is True
    assert enhanced_body["check_sanctions"] is True
    assert enhanced_body["nationality"] == "NG"
    premium_body = json.loads(rec.requests[2].content)
    assert premium_body["check_credit_bureau"] is True
    assert premium_body["credit_bureau_provider"] == "crc"
    # basic payload must NOT carry screening flags
    basic_body = json.loads(rec.requests[0].content)
    assert "check_pep" not in basic_body and "check_credit_bureau" not in basic_body


def test_kyc_verify_invalid_level(rec):
    client = rec.router({})
    with pytest.raises(ValueError):
        client.kyc_verify(customer_id="c", first_name="a", last_name="b",
                          level="gold")


def test_kyc_status_path(rec):
    client = rec.router({("GET", "/api/v1/kyc/status/req123"): {"decision": "approved"}})
    assert client.kyc_status("req123")["decision"] == "approved"


# --------------------------------------------------------------------------
# document / biometric
# --------------------------------------------------------------------------

def test_document_verify_multipart(rec):
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    client = rec.router({("POST", "/api/v1/document/verify"):
                         {"status": "verified", "detected_format": "png"}})
    out = client.document_verify(png, "national_id", filename="id.png")
    assert out["status"] == "verified"
    req = rec.requests[0]
    assert req.headers["Content-Type"].startswith("multipart/form-data")
    content = req.read()
    assert b'name="document"; filename="id.png"' in content
    assert b'name="document_type"' in content and b"national_id" in content
    assert b'name="check_forgery"' in content and b"true" in content
    assert png in content


def test_document_verify_check_forgery_false(rec):
    client = rec.router({("POST", "/api/v1/document/verify"): {"status": "manual_review"}})
    client.document_verify(b"%PDF-1.4 fake", "cac_certificate", check_forgery=False)
    assert b"false" in rec.requests[0].read()


def test_biometric_verify_encodes_bytes(rec):
    selfie = b"\xff\xd8\xff selfie-bytes"
    client = rec.router({("POST", "/api/v1/biometric/verify"): {"status": "verified"}})
    client.biometric_verify(selfie, reference=b"ref", check_liveness=True)
    body = json.loads(rec.requests[0].content)
    assert body["selfie_image_base64"] == base64.b64encode(selfie).decode()
    assert body["reference_image_base64"] == base64.b64encode(b"ref").decode()
    assert body["check_liveness"] is True


def test_biometric_verify_rejects_bad_base64(rec):
    client = rec.router({})
    with pytest.raises(ValueError):
        client.biometric_verify("!!!not-base64!!!")


# --------------------------------------------------------------------------
# KYB
# --------------------------------------------------------------------------

def test_kyb_submit_camelcase(rec):
    view = {"applicationId": "app_1", "businessName": "Acme Ltd",
            "cacNumber": "RC1234567", "status": "submitted"}
    client = rec.router({("POST", "/api/v1/onboarding/kyb"): (view, 201)})
    out = client.kyb_submit(
        business_name="Acme Ltd", cac_number="RC1234567",
        contact_email="ops@acme.example",
        documents=[{"type": "cac_certificate", "reference": "s3://bucket/cac.pdf"}],
    )
    assert out["applicationId"] == "app_1"
    body = json.loads(rec.requests[0].content)
    assert body["businessName"] == "Acme Ltd"
    assert body["cacNumber"] == "RC1234567"
    assert body["businessType"] == "limited_liability"
    assert body["contactEmail"] == "ops@acme.example"
    assert body["documents"][0]["type"] == "cac_certificate"


def test_kyb_get_and_verification(rec):
    client = rec.router({
        ("GET", "/api/v1/onboarding/kyb/app_1"): {"applicationId": "app_1"},
        ("GET", "/api/v1/onboarding/kyb/app_1/verification"):
            {"verdict": "verified", "documents": []},
    })
    assert client.kyb_get("app_1")["applicationId"] == "app_1"
    assert client.kyb_get_verification("app_1")["verdict"] == "verified"


# --------------------------------------------------------------------------
# intel
# --------------------------------------------------------------------------

def test_intel_national_summary(rec):
    client = rec.router({("GET", "/v1/intel/national/summary"):
                         {"national_fraud_rate": {"posterior_mean": 0.042}}})
    assert client.intel_national_summary()["national_fraud_rate"]["posterior_mean"] == 0.042


def test_intel_states_state_hotspots_typology(rec):
    client = rec.router({
        ("GET", "/v1/intel/states"): {"states": []},
        ("GET", "/v1/intel/states/lagos"): {"code": "lagos"},
        ("GET", "/v1/intel/hotspots"): {"hotspots": []},
        ("GET", "/v1/intel/typology-mix"): {"zones": {}},
    })
    client.intel_states()
    client.intel_state("lagos")
    client.intel_hotspots(k=5, threshold=0.05)
    client.intel_typology_mix()
    hotspot_req = rec.requests[2]
    assert hotspot_req.url.params["k"] == "5"
    assert hotspot_req.url.params["threshold"] == "0.05"


def test_intel_cultural(rec):
    client = rec.router({
        ("GET", "/v1/intel/cultural/calendar"): {"active_events": []},
        ("POST", "/v1/intel/cultural/ajo/assess"): {"p_legitimate_mean": 0.9},
        ("POST", "/v1/intel/cultural/score"): {"cultural_fraud_score": 0.31},
    })
    client.intel_cultural_calendar("2026-03-20", state="kano")
    assert rec.requests[0].url.params["date"] == "2026-03-20"
    assert rec.requests[0].url.params["state"] == "kano"

    out = client.intel_cultural_ajo_assess(
        n_members=12, contribution_cv=0.1, cadence_cv=0.2,
        rotation_coverage=1.0, payout_ratio=1.0, tenure_days=400)
    assert out["p_legitimate_mean"] == 0.9
    ajo_body = json.loads(rec.requests[1].content)
    assert ajo_body["n_members"] == 12

    out = client.intel_cultural_score({"event_window_mismatch": 0.8},
                                      claimed_event="ramadan", date="2026-03-01")
    assert out["cultural_fraud_score"] == 0.31
    score_body = json.loads(rec.requests[2].content)
    assert score_body["indicators"] == {"event_window_mismatch": 0.8}
    assert score_body["claimed_event"] == "ramadan"
    assert score_body["date"] == "2026-03-01"


def test_intel_legitimacy(rec):
    client = rec.router({
        ("POST", "/v1/intel/request-legitimacy/assess"):
            {"score": 0.95, "risk_band": "critical"},
        ("GET", "/v1/intel/request-legitimacy/matrix"): {"matrix_version": "1.0"},
    })
    out = client.intel_legitimacy_assess(
        requesting_entity_type="road_safety",
        fields_requested=["bvn", "otp"], channel="sms", link_present=True)
    assert out["risk_band"] == "critical"
    body = json.loads(rec.requests[0].content)
    assert body == {"requesting_entity_type": "road_safety",
                    "fields_requested": ["bvn", "otp"],
                    "channel": "sms", "link_present": True}
    assert client.intel_legitimacy_matrix()["matrix_version"] == "1.0"


# --------------------------------------------------------------------------
# webhooks
# --------------------------------------------------------------------------

def test_webhooks_crud_and_deliveries(rec):
    client = rec.router({
        ("GET", "/v1/webhooks"): {"endpoints": []},
        ("POST", "/v1/webhooks"): ({"id": "we_1", "secret": "whsec_shown_once"}, 201),
        ("DELETE", "/v1/webhooks/we_1"): ({}, 204),
        ("GET", "/v1/webhooks/we_1/deliveries"): {"deliveries": []},
    })
    assert client.webhooks_list() == {"endpoints": []}
    created = client.webhook_create("https://me.example/hook",
                                    ["kyc.verification.completed"],
                                    description="primary")
    assert created["secret"] == "whsec_shown_once"
    body = json.loads(rec.requests[1].content)
    assert body["url"] == "https://me.example/hook"
    assert body["event_types"] == ["kyc.verification.completed"]
    assert body["description"] == "primary"
    client.webhook_delete("we_1")
    assert client.webhook_deliveries("we_1") == {"deliveries": []}


# --------------------------------------------------------------------------
# error mapping
# --------------------------------------------------------------------------

@pytest.mark.parametrize("status,exc", [
    (400, ValidationError),
    (401, AuthenticationError),
    (403, PermissionError),
    (404, NotFoundError),
    (409, ConflictError),
    (422, ValidationError),
])
def test_error_mapping(rec, status, exc):
    client = rec.queue(json_response({"detail": "boom"}, status))
    with pytest.raises(exc) as ei:
        client.kyc_status("x")
    assert ei.value.status_code == status
    assert ei.value.detail == "boom"


def test_server_error_after_retries_exhausted(rec):
    client = rec.queue(*[json_response({"detail": "db down"}, 500)] * 4)
    with pytest.raises(ServerError) as ei:
        client.kyc_status("x")
    assert ei.value.status_code == 500
    assert len(rec.requests) == 4  # 1 initial + 3 retries


def test_rate_limit_error_carries_detail(rec):
    client = rec.queue(*[json_response({"detail": "slow down"}, 429)] * 4)
    with pytest.raises(RateLimitError) as ei:
        client.kyc_status("x")
    assert ei.value.status_code == 429
    assert len(rec.requests) == 4


def test_non_json_error_body(rec):
    client = rec.queue(httpx.Response(502, text="<html>bad gateway</html>"),
                       max_retries=0)
    with pytest.raises(ServerError) as ei:
        client.kyc_status("x")
    assert "bad gateway" in ei.value.detail


# --------------------------------------------------------------------------
# retry semantics
# --------------------------------------------------------------------------

def test_retry_recovers_on_429_then_200(rec):
    client = rec.queue(
        json_response({"detail": "rate limited"}, 429),
        json_response({"ok": True}, 200),
    )
    assert client.kyc_status("x") == {"ok": True}
    assert len(rec.requests) == 2


def test_retry_recovers_on_500_sequence(rec):
    client = rec.queue(
        json_response({"detail": "x"}, 500),
        json_response({"detail": "x"}, 503),
        json_response({"ok": 1}, 200),
    )
    assert client.kyc_status("x") == {"ok": 1}
    assert len(rec.requests) == 3


def test_no_retry_on_4xx(rec):
    client = rec.queue(json_response({"detail": "nope"}, 403))
    with pytest.raises(PermissionError):
        client.kyc_status("x")
    assert len(rec.requests) == 1


def test_retry_after_header_honored(rec, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("fraudfusion.client.time.sleep", sleeps.append)
    client = rec.queue(
        json_response({"detail": "rl"}, 429, headers={"Retry-After": "7"}),
        json_response({"ok": True}, 200),
    )
    assert client.kyc_status("x") == {"ok": True}
    assert sleeps == [7.0]


def test_connection_error_retried_then_raises(rec):
    def handler(request: httpx.Request) -> httpx.Response:
        rec.requests.append(request)
        raise httpx.ConnectError("refused", request=request)

    client = rec.client(handler)
    with pytest.raises(FraudFusionError) as ei:
        client.kyc_status("x")
    assert "failed after 4 attempts" in str(ei.value)
    assert len(rec.requests) == 4


def test_max_retries_zero_disables_retry(rec):
    client = rec.queue(json_response({"detail": "x"}, 500), max_retries=0)
    with pytest.raises(ServerError):
        client.kyc_status("x")
    assert len(rec.requests) == 1


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------

def test_context_manager_and_constructor_validation():
    with pytest.raises(ValueError):
        FraudFusionClient("")
    with FraudFusionClient(API_KEY, "http://x.test/",
                           transport=httpx.MockTransport(
                               lambda r: httpx.Response(200, json={"ok": 1}))) as c:
        assert c.base_url == "http://x.test"  # trailing slash stripped
        assert c.kyc_status("anything") == {"ok": 1}
