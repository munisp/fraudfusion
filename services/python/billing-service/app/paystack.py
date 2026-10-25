"""Paystack payment-rail adapter for billing-service.

Two flows, both fail-closed:

  * checkout — POST initialize a Paystack transaction for an issued invoice
    (amount in kobo, reference = invoice id) and return the hosted
    authorization_url for the tenant to pay
  * webhook  — POST /webhooks/paystack, verified with HMAC-SHA512 over the
    RAW request body using PAYSTACK_SECRET_KEY; on `charge.success` the
    matching invoice is marked paid

Never silently succeeds: no secret key configured -> the rail reports
unavailable and every entry point answers 503.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Optional

PAYSTACK_BASE = os.getenv("PAYSTACK_BASE_URL", "https://api.paystack.co")


def _secret() -> Optional[str]:
    return os.getenv("PAYSTACK_SECRET_KEY", "").strip() or None


def available() -> bool:
    return _secret() is not None


def verify_webhook_signature(raw_body: bytes, signature: str) -> bool:
    """Paystack signs the raw body with HMAC-SHA512 (secret key)."""
    secret = _secret()
    if not secret or not signature:
        return False
    expect = hmac.new(secret.encode(), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expect, signature)


def initialize_checkout(invoice: dict[str, Any], email: str,
                        callback_url: Optional[str] = None) -> dict[str, Any]:
    """Initialize a hosted checkout for an invoice. Returns
    {status: ok, authorization_url, reference} or an honest error block."""
    secret = _secret()
    if not secret:
        return {"status": "unavailable",
                "reason": "PAYSTACK_SECRET_KEY not configured"}
    import httpx

    payload: dict[str, Any] = {
        "email": email,
        "amount": int(invoice["total_kobo"]),
        "reference": invoice["id"],
        "currency": "NGN",
        "metadata": {"invoice_id": invoice["id"],
                     "tenant_id": invoice["tenant_id"]},
    }
    if callback_url:
        payload["callback_url"] = callback_url
    try:
        resp = httpx.post(
            f"{PAYSTACK_BASE}/transaction/initialize", json=payload,
            headers={"Authorization": f"Bearer {secret}"}, timeout=15.0)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return {"status": "unavailable", "reason": f"paystack unreachable: {exc}"}
    if resp.status_code == 200 and data.get("status"):
        return {"status": "ok",
                "authorization_url": data["data"]["authorization_url"],
                "reference": data["data"]["reference"]}
    return {"status": "error",
            "reason": data.get("message") or f"paystack HTTP {resp.status_code}"}
