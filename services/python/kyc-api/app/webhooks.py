"""Webhook event emitter (shared internal emitter contract, plan.md).

POST {WEBHOOK_SERVICE_URL}/internal/events with header
``X-Internal-Token: {WEBHOOK_INTERNAL_TOKEN}`` and the event envelope
``{"id", "type", "created_at", "tenant_id", "data"}``.

Fire-and-forget: 2s timeout, failures are logged and NEVER raised into the
request path; a missing WEBHOOK_SERVICE_URL makes emission a no-op (debug
log) so local dev and tests without the webhook service keep working.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

log = logging.getLogger("kyc-api.webhooks")

EMIT_TIMEOUT_SECONDS = 2.0


def _post(url: str, **kwargs) -> httpx.Response:
    """Seam for tests (monkeypatch/MockTransport) — plain httpx POST."""
    return httpx.post(url, **kwargs)


def emit_event(event_type: str, tenant_id: str, data: dict[str, Any]) -> bool:
    """Emit one event envelope to webhook-service. Returns True when the POST
    was attempted successfully; never raises."""
    url = os.getenv("WEBHOOK_SERVICE_URL", "").strip().rstrip("/")
    if not url:
        log.debug("WEBHOOK_SERVICE_URL unset; skipping %s emission", event_type)
        return False
    envelope = {
        "id": uuid.uuid4().hex,
        "type": event_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "data": data,
    }
    try:
        _post(
            f"{url}/internal/events",
            json=envelope,
            headers={"X-Internal-Token": os.getenv("WEBHOOK_INTERNAL_TOKEN", "")},
            timeout=EMIT_TIMEOUT_SECONDS,
        )
        return True
    except Exception as exc:  # noqa: BLE001 - fire-and-forget, never raise
        log.warning("webhook emit %s failed (swallowed, request unaffected): %s",
                    event_type, exc)
        return False
