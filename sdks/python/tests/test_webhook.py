"""Known-answer + behaviour tests for the webhook signature verifier.

Implements the shared signing scheme:
  X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
  key derivation: key = sha256(secret).hexdigest().encode("utf-8")
  signed payload: HMAC-SHA256(key, "<t>.<raw body>")
  ±300s tolerance, constant-time compare.

The KAT vector below was generated independently with:
  python -c "import hmac,hashlib
  key = hashlib.sha256(b'whsec_testsecret').hexdigest().encode()
  print(hmac.new(key, b'1700000000.' + BODY, hashlib.sha256).hexdigest())"
and the SAME vector is used by the TypeScript SDK test-suite, so both
verifiers are pinned against identical bytes.
"""

import pytest

from fraudfusion import (
    WebhookSignatureError,
    compute_signature,
    derive_signing_key,
    parse_signature_header,
    verify_webhook_signature,
)

SECRET = "whsec_testsecret"
T = 1700000000  # 2023-11-14T22:13:20Z
BODY = (
    '{"id":"evt_01JTEST","type":"kyc.verification.completed",'
    '"created_at":"2023-11-14T22:13:20+00:00","tenant_id":"ten_demo",'
    '"data":{"verification_id":"ver_abc123","status":"verified"}}'
)
# sha256("whsec_testsecret").hexdigest() — the derived HMAC key.
DERIVED_KEY = "e2ba7a07c32c49c4ac02192da58827a38284fa93d08ab4632af87b25e1f5c8be"
EXPECTED_V1 = "ededc70731f82ecc4ba7f338def73b8d5fecc42d662d33106cccf2525bbd8202"
HEADER = f"t={T},v1={EXPECTED_V1}"


def test_key_derivation():
    assert derive_signing_key(SECRET).decode() == DERIVED_KEY


def test_known_answer_vector():
    assert compute_signature(SECRET, T, BODY) == EXPECTED_V1
    assert verify_webhook_signature(SECRET, BODY, HEADER, now=T) is True


def test_accepts_bytes_body_and_secret():
    assert verify_webhook_signature(
        SECRET.encode(), BODY.encode(), HEADER, now=T) is True


def test_tolerance_edges_accepted():
    assert verify_webhook_signature(SECRET, BODY, HEADER, now=T + 300) is True
    assert verify_webhook_signature(SECRET, BODY, HEADER, now=T - 300) is True


def test_expired_and_future_timestamps_rejected():
    assert verify_webhook_signature(SECRET, BODY, HEADER, now=T + 301) is False
    assert verify_webhook_signature(SECRET, BODY, HEADER, now=T - 301) is False


def test_custom_tolerance():
    assert verify_webhook_signature(SECRET, BODY, HEADER, now=T + 60,
                                    tolerance=30) is False


def test_wrong_secret_rejected():
    assert verify_webhook_signature("whsec_wrong", BODY, HEADER, now=T) is False


def test_tampered_body_rejected():
    tampered = BODY.replace("verified", "rejected")
    assert verify_webhook_signature(SECRET, tampered, HEADER, now=T) is False


def test_tampered_timestamp_rejected():
    # Same v1 but a different t -> HMAC over "<t>.<body>" no longer matches.
    header = f"t={T + 1},v1={EXPECTED_V1}"
    assert verify_webhook_signature(SECRET, BODY, header, now=T) is False


def test_extra_header_segments_tolerated():
    header = f"t={T},v1={EXPECTED_V1},v0=ignored"
    assert verify_webhook_signature(SECRET, BODY, header, now=T) is True


@pytest.mark.parametrize("bad", [
    "",
    "garbage",
    f"v1={EXPECTED_V1}",          # missing t
    f"t={T}",                     # missing v1
    "t=notanumber,v1=deadbeef",   # non-integer t
])
def test_malformed_headers_raise(bad):
    with pytest.raises(WebhookSignatureError):
        verify_webhook_signature(SECRET, BODY, bad, now=T)


def test_parse_signature_header():
    ts, v1 = parse_signature_header(HEADER)
    assert ts == T and v1 == EXPECTED_V1


def test_default_now_used_when_omitted(monkeypatch):
    import fraudfusion.webhook as wh
    monkeypatch.setattr(wh.time, "time", lambda: float(T))
    assert verify_webhook_signature(SECRET, BODY, HEADER) is True
