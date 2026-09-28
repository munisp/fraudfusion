"""Synthetic webhook emitter for /sandbox/trigger-event.

Signing scheme — the shared plan contract, identical to webhook-service and
verified by the SDKs:

  Header:         X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
  HMAC key:       sha256(secret).hexdigest().encode("utf-8")  (secrets are
                  stored hash-only, so the HMAC key is DERIVED from the secret)
  Signed payload: "<t>.<raw request body>"
  Envelope JSON:  {"id", "type", "created_at", "tenant_id", "data"}

The demo secret (fixtures.WEBHOOK_DEMO_SECRET) is documented in README.md so
developers can verify signatures end-to-end.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone

from app import fixtures

SANDBOX_TENANT_ID = "tenant_sandbox"


def _derived_hmac_key(secret: str) -> bytes:
    """HMAC key derivation per the final shared contract: secrets are stored
    hash-only, so the HMAC key is sha256(secret).hexdigest() as UTF-8 bytes."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest().encode("utf-8")


def sign_body(secret: str, body: bytes, timestamp: int | None = None) -> str:
    """Return the X-FraudFusion-Signature header value for ``body``."""
    t = int(timestamp if timestamp is not None else time.time())
    signed = str(t).encode() + b"." + body
    digest = hmac.new(_derived_hmac_key(secret), signed,
                      hashlib.sha256).hexdigest()
    return f"t={t},v1={digest}"


def verify_signature(secret: str, body: bytes, header: str,
                     tolerance_seconds: int = 300,
                     now: int | None = None) -> bool:
    """Verify an X-FraudFusion-Signature header (constant-time compare).

    Provided for tests and for developers reading the sandbox source as a
    reference implementation of the shared scheme."""
    parts = dict(part.split("=", 1) for part in header.split(",") if "=" in part)
    t_str, v1 = parts.get("t"), parts.get("v1")
    if not t_str or not v1:
        return False
    try:
        t = int(t_str)
    except ValueError:
        return False
    now = int(now if now is not None else time.time())
    if abs(now - t) > tolerance_seconds:
        return False
    expected = hmac.new(_derived_hmac_key(secret),
                        t_str.encode() + b"." + body,
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)


def default_event_data(event_type: str) -> dict:
    """Synthetic per-event-type payloads (hash refs / ids only — NO PII)."""
    if event_type == "kyc.verification.completed":
        return {
            "verification_id": f"kyc_{uuid.uuid4().hex[:16]}",
            "customer_id": "cus_sandbox_001",
            "status": "completed",
            "verification_level": "basic",
            "decision": "approved",
            "risk_score": 0.1,
            "document_type": "national_id",
            "document_sha256": hashlib.sha256(b"sandbox-doc").hexdigest(),
        }
    if event_type == "kyb.verification.completed":
        return {
            "application_id": f"kyb_{uuid.uuid4().hex[:16]}",
            "verdict": "verified",
            "document_sha256s": [hashlib.sha256(b"sandbox-cac-cert").hexdigest()],
        }
    if event_type == "identity.exposure.detected":
        return {
            "alert_id": f"alert_{uuid.uuid4().hex[:16]}",
            "exposure_type": "credential_leak",
            "subject_hash_ref": hashlib.sha256(b"sandbox-subject").hexdigest(),
        }
    return {}


def build_event(event_type: str, payload_overrides: dict | None = None) -> dict:
    """Build the shared event envelope: {id, type, created_at, tenant_id, data}."""
    data = default_event_data(event_type)
    if payload_overrides:
        data.update(payload_overrides)
    return {
        "id": f"evt_{uuid.uuid4().hex[:24]}",
        "type": event_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": SANDBOX_TENANT_ID,
        "data": data,
    }


def encode_event(event: dict) -> bytes:
    """Canonical JSON encoding of the envelope (the signed raw body)."""
    return json.dumps(event, separators=(",", ":"), sort_keys=False).encode()


def deliver_event(url: str, event: dict, secret: str,
                  timeout: float = 5.0) -> dict:
    """POST the signed envelope to ``url``. Returns delivery metadata.

    Never raises for transport failures — delivery status is reported in the
    return value so developers can see what happened."""
    import httpx

    body = encode_event(event)
    signature = sign_body(secret, body)
    headers = {
        "Content-Type": "application/json",
        "X-FraudFusion-Signature": signature,
    }
    result = {
        "event": event,
        "signature_header": signature,
        "webhook_secret": secret,
        "delivered": False,
        "http_status": None,
        "error": None,
    }
    try:
        response = httpx.post(url, content=body, headers=headers, timeout=timeout)
        result["http_status"] = response.status_code
        result["delivered"] = response.status_code < 400
        if response.status_code >= 400:
            result["error"] = f"receiver responded {response.status_code}"
    except Exception as exc:  # transport error — reported, never raised
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result
