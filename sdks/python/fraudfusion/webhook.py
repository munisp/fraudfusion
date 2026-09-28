"""Webhook signature verification — implements the FraudFusion shared
signing scheme exactly:

    Header:         X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
    Key derivation: webhook secrets are stored hash-only server-side, so the
                    HMAC key at delivery time is DERIVED from the secret:
                        key = sha256(secret).hexdigest().encode("utf-8")
    Signed payload: HMAC-SHA256(key, "<t>.<raw request body>")
    Tolerance:      |now - t| <= 300 seconds (replay protection)
    Comparison:     constant-time (hmac.compare_digest)

Usage::

    from fraudfusion import verify_webhook_signature

    ok = verify_webhook_signature(
        secret="whsec_...",
        body=request.body(),                      # raw bytes, unparsed
        header=request.headers["X-FraudFusion-Signature"],
    )
    if not ok:
        return Response(status_code=401)

Verify the signature BEFORE parsing the JSON body, and always against the
RAW request body bytes — never a re-serialised dict (key order/whitespace
would change the HMAC).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Union

from .exceptions import WebhookSignatureError

DEFAULT_TOLERANCE_SECONDS = 300
SIGNATURE_HEADER = "X-FraudFusion-Signature"

BodyLike = Union[str, bytes]


def _as_bytes(value: BodyLike, what: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"{what} must be str or bytes, got {type(value).__name__}")


def parse_signature_header(header: str) -> tuple[int, str]:
    """Parse ``t=<unix>,v1=<hex>`` into (timestamp, hex_signature).

    Raises WebhookSignatureError on any malformed input — a header we cannot
    parse is a programming/integration error, not a mere mismatch.
    """
    if not header or not isinstance(header, str):
        raise WebhookSignatureError("signature header is empty or not a string")
    timestamp = None
    v1 = None
    for part in header.split(","):
        key, sep, value = part.strip().partition("=")
        if not sep:
            continue  # ignore stray segments rather than failing hard
        if key == "t":
            timestamp = value
        elif key == "v1":
            v1 = value
    if timestamp is None or v1 is None:
        raise WebhookSignatureError(
            "signature header must contain t=<unix_ts> and v1=<hex> components")
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise WebhookSignatureError(f"signature timestamp is not an integer: {timestamp!r}") from exc
    return ts, v1


def derive_signing_key(secret: BodyLike) -> bytes:
    """Derive the HMAC key from a webhook signing secret.

    The webhook service stores secrets hash-only, so at delivery time the
    HMAC key is the hex SHA-256 of the secret, encoded as UTF-8:
    ``sha256(secret).hexdigest().encode("utf-8")``. Receivers MUST apply the
    same derivation before verifying.
    """
    return hashlib.sha256(_as_bytes(secret, "secret")).hexdigest().encode("utf-8")


def compute_signature(secret: BodyLike, timestamp: int, body: BodyLike) -> str:
    """Hex HMAC-SHA256 of ``"<t>.<raw body>"`` keyed by the DERIVED key
    ``sha256(secret).hexdigest().encode("utf-8")`` — the exact value that
    goes into the ``v1=`` component. Exposed so receivers can cross-check
    and so tests can build vectors."""
    payload = str(timestamp).encode("ascii") + b"." + _as_bytes(body, "body")
    return hmac.new(derive_signing_key(secret), payload, hashlib.sha256).hexdigest()


def verify_webhook_signature(
    secret: BodyLike,
    body: BodyLike,
    header: str,
    *,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    now: Union[int, float, None] = None,
) -> bool:
    """Verify an X-FraudFusion-Signature header against the raw request body.

    Returns True only when the timestamp is within ``tolerance`` seconds of
    ``now`` (default: current time, ±300s) AND the v1 HMAC matches
    (constant-time compare). Returns False for an expired/future timestamp or
    a mismatched signature. Raises WebhookSignatureError only for a header
    that cannot be parsed at all.
    """
    ts, expected = parse_signature_header(header)
    current = time.time() if now is None else float(now)
    if abs(current - ts) > tolerance:
        return False
    actual = compute_signature(secret, ts, body)
    return hmac.compare_digest(actual, expected)
