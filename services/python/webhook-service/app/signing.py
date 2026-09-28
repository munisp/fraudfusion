"""Webhook request signing — the shared Round-9 contract.

Header:   X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
Payload:  "<t>.<raw request body>" (utf-8)
Key:      sha256(endpoint_signing_secret).hexdigest() as utf-8 bytes.

The endpoint signing secret (whsec_<32 hex chars>) is shown ONCE at endpoint
creation; only its sha256 hash is persisted (hash-only storage). The hash hex
is therefore the HMAC key material used by the delivery worker. Receivers
holding the whsec_ secret derive the same key:

    key = hashlib.sha256(secret.encode("utf-8")).hexdigest().encode("utf-8")

Timestamp tolerance is +/-300s and comparison is constant-time
(hmac.compare_digest).
"""

from __future__ import annotations

import hashlib
import hmac
import time

SIGNATURE_HEADER = "X-FraudFusion-Signature"
TIMESTAMP_TOLERANCE_SECONDS = 300
SECRET_PREFIX = "whsec_"


def derive_signing_key(secret: str) -> bytes:
    """HMAC key for an endpoint: sha256(secret) hex digest as utf-8 bytes."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest().encode("utf-8")


def compute_signature(key: bytes, timestamp: int, body: bytes) -> str:
    """Hex HMAC-SHA256 over "<timestamp>.<body>"."""
    msg = str(int(timestamp)).encode("utf-8") + b"." + body
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def build_signature_header(key: bytes, timestamp: int, body: bytes) -> str:
    """The full header value: "t=<unix_ts>,v1=<hex>"."""
    return f"t={int(timestamp)},v1={compute_signature(key, timestamp, body)}"


def parse_signature_header(header: str) -> tuple[int, str]:
    """Parse "t=<unix>,v1=<hex>" (whitespace-tolerant, order-tolerant)."""
    parts: dict[str, str] = {}
    for piece in (header or "").split(","):
        if "=" in piece:
            k, _, v = piece.strip().partition("=")
            parts[k.strip()] = v.strip()
    if "t" not in parts or "v1" not in parts:
        raise ValueError("signature header must contain t= and v1=")
    return int(parts["t"]), parts["v1"]


def verify_signature(
    secret: str,
    body: bytes,
    header: str,
    *,
    now: float | None = None,
    tolerance: int = TIMESTAMP_TOLERANCE_SECONDS,
) -> bool:
    """Verify a delivered webhook against the endpoint's whsec_ secret.

    Re-implements the receiver-side check so tests (and integrators reading
    this module) have a reference implementation. Returns False on any
    malformed header, stale/future timestamp, or signature mismatch — never
    raises.
    """
    try:
        timestamp, signature = parse_signature_header(header)
    except (ValueError, TypeError):
        return False
    now = time.time() if now is None else now
    if abs(now - timestamp) > tolerance:
        return False
    expected = compute_signature(derive_signing_key(secret), timestamp, body)
    return hmac.compare_digest(expected, signature)
