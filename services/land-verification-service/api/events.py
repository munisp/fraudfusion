"""Webhook event emitter for the land due-diligence module (Round 12).

Same internal emitter contract as kyc-api/onboarding/identity (Round 9):
POST {WEBHOOK_SERVICE_URL}/internal/events with header
``X-Internal-Token: {WEBHOOK_INTERNAL_TOKEN}`` and envelope
``{"id", "type", "created_at", "tenant_id", "data"}``.

Fire-and-forget: 2s timeout, failures logged and NEVER raised into the
request path; WEBHOOK_SERVICE_URL unset makes emission a no-op so local dev
and tests without webhook-service keep working.

Land event types:
  parcel.registered        — first-wins registration accepted
  parcel.conflict.detected — multiple-sale signal (duplicate ref or shared
                             certificate/survey-hash) — the alarm partners
                             want to wake up for
  parcel.cleared           — all consents confirmed, no conflicts
  dispute.opened           — dispute case opened, SLA clock started
  dispute.sla.breached     — open dispute past its SLA (emitted by the
                             sweeper, exactly once per dispute)
  dispute.resolved         — dispute resolved/withdrawn
  revocation.opened        — revocation notice served
  revocation.compensated   — compensation paid (acquisition now lawful)
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

log = logging.getLogger("land-verification.webhooks")

EMIT_TIMEOUT_SECONDS = 2.0


def _post(url: str, **kwargs) -> httpx.Response:
    """Seam for tests (monkeypatch) — plain httpx POST."""
    return httpx.post(url, **kwargs)


def emit_event(event_type: str, tenant_id: str, data: dict[str, Any]) -> bool:
    """Emit one event envelope to webhook-service. Never raises."""
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
