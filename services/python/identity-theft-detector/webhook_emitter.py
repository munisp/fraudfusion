"""Fire-and-forget webhook event emitter (Round-9 shared contract).

POSTs an event envelope {"id","type","created_at","tenant_id","data"} to
{WEBHOOK_SERVICE_URL}/internal/events with X-Internal-Token:
{WEBHOOK_INTERNAL_TOKEN}. Short timeout (2s), logs on failure, NEVER raises
into the request path; no-op (debug log) when WEBHOOK_SERVICE_URL is unset.
Duplicated per-service on purpose — the repo has no shared python package
convention.
"""

from __future__ import annotations

import logging
import os
import time
import uuid

import httpx

logger = logging.getLogger("identity-theft-detector.webhooks")

EMIT_TIMEOUT_SECONDS = 2.0


def emit_event(event_type: str, tenant_id: str, data: dict, *,
               transport: httpx.BaseTransport | None = None) -> bool:
    """Emit one event; returns True when the intake accepted it (2xx)."""
    base = os.getenv("WEBHOOK_SERVICE_URL", "").rstrip("/")
    if not base:
        logger.debug("WEBHOOK_SERVICE_URL unset; dropping event %s", event_type)
        return False
    envelope = {
        "id": f"evt_{uuid.uuid4().hex}",
        "type": event_type,
        "created_at": int(time.time()),
        "tenant_id": tenant_id or "default",
        "data": data,
    }
    headers = {"X-Internal-Token": os.getenv("WEBHOOK_INTERNAL_TOKEN", "")}
    try:
        if transport is not None:  # tests inject httpx.MockTransport
            with httpx.Client(transport=transport, timeout=EMIT_TIMEOUT_SECONDS) as c:
                resp = c.post(f"{base}/internal/events", json=envelope, headers=headers)
        else:
            resp = httpx.post(f"{base}/internal/events", json=envelope,
                              headers=headers, timeout=EMIT_TIMEOUT_SECONDS)
        if resp.status_code >= 300:
            logger.warning("webhook emit %s failed: status=%d",
                           event_type, resp.status_code)
            return False
        return True
    except Exception as exc:  # NEVER raise into the request path
        logger.warning("webhook emit %s failed: %s", event_type, exc.__class__.__name__)
        return False
