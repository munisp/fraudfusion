"""Signature scheme tests, including a known-answer vector computed by hand.

KAT derivation (independent of app code):
  secret = "whsec_0123456789abcdef0123456789abcdef"
  key    = sha256(secret).hexdigest() as utf-8 bytes
         = "10fc1027ac25d44cac487660968579b4556103ff0ce9d3c631038540def93aef"
  t      = 1735689600  (2025-01-01T00:00:00Z)
  body   = the compact JSON envelope below
  v1     = HMAC-SHA256(key, b"1735689600." + body) hex
         = "bfb5ad8f2d63bcebf52d2a06229bb9da9fb082260d6cc776a7a9f2da18fad620"

Run: python3 -m pytest tests/test_signing.py -q
"""

from __future__ import annotations

from app import signing

SECRET = "whsec_0123456789abcdef0123456789abcdef"
KEY_HEX = "10fc1027ac25d44cac487660968579b4556103ff0ce9d3c631038540def93aef"
KAT_TIMESTAMP = 1735689600
KAT_BODY = (
    b'{"id":"evt_0001","type":"kyb.verification.completed","created_at":1735689600,'
    b'"tenant_id":"default","data":{"application_id":"app_123","verdict":"verified",'
    b'"document_sha256s":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}'
)
KAT_SIGNATURE = "bfb5ad8f2d63bcebf52d2a06229bb9da9fb082260d6cc776a7a9f2da18fad620"


def test_known_answer_vector():
    key = signing.derive_signing_key(SECRET)
    assert key.decode() == KEY_HEX
    assert signing.compute_signature(key, KAT_TIMESTAMP, KAT_BODY) == KAT_SIGNATURE
    header = signing.build_signature_header(key, KAT_TIMESTAMP, KAT_BODY)
    assert header == f"t={KAT_TIMESTAMP},v1={KAT_SIGNATURE}"


def test_verify_accepts_valid_signature_within_tolerance():
    header = f"t={KAT_TIMESTAMP},v1={KAT_SIGNATURE}"
    assert signing.verify_signature(SECRET, KAT_BODY, header,
                                    now=KAT_TIMESTAMP + 300)
    assert signing.verify_signature(SECRET, KAT_BODY, header,
                                    now=KAT_TIMESTAMP - 300)


def test_verify_rejects_stale_or_future_timestamp():
    header = f"t={KAT_TIMESTAMP},v1={KAT_SIGNATURE}"
    assert not signing.verify_signature(SECRET, KAT_BODY, header,
                                        now=KAT_TIMESTAMP + 301)
    assert not signing.verify_signature(SECRET, KAT_BODY, header,
                                        now=KAT_TIMESTAMP - 301)


def test_verify_rejects_tampered_body_and_wrong_secret():
    header = f"t={KAT_TIMESTAMP},v1={KAT_SIGNATURE}"
    assert not signing.verify_signature(SECRET, KAT_BODY + b" ", header,
                                        now=KAT_TIMESTAMP)
    assert not signing.verify_signature("whsec_" + "f" * 32, KAT_BODY, header,
                                        now=KAT_TIMESTAMP)


def test_verify_rejects_malformed_headers():
    for bad in ("", "v1=abc", "t=abc,v1=def", "t=1", None, "t=1;v1=2"):
        assert not signing.verify_signature(SECRET, KAT_BODY, bad,  # type: ignore[arg-type]
                                            now=KAT_TIMESTAMP)


def test_header_parser_tolerates_whitespace_and_order():
    t, sig = signing.parse_signature_header(f" v1={KAT_SIGNATURE} , t={KAT_TIMESTAMP} ")
    assert t == KAT_TIMESTAMP and sig == KAT_SIGNATURE
