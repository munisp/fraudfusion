"""Auto-metering middleware — closes the "usage is recorded manually" gap.

Mount ``UsageMeteringMiddleware`` on any FastAPI service with a route map
and every matched, successful request is automatically metered against the
tenant's subscription via the mesh:

    POST {BILLING_SERVICE_URL}/internal/usage
    X-Internal-Token: {BILLING_INTERNAL_TOKEN}

The billing side inserts idempotently (idempotency_key) and rolls up into
usage_rollups, so middleware retries or duplicate deliveries never
double-bill.

Fail-closed honesty:
  * billing unreachable / internal token unset / non-2xx from billing ->
    the client request STILL SUCCEEDS (metering never breaks the request
    path), but the failure is logged and counted in ``metering_stats()``.
  * unattributed requests (tenant resolver returns None) are skipped and
    counted, never guessed into some default tenant.
  * failed requests (non-2xx/3xx responses) are not billed.
"""
from __future__ import annotations

import logging
import threading
import uuid
from typing import Callable, List, Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:  # package import
    from .mesh import MeshService
except ImportError:  # sys.path import (service layout)
    from mesh import MeshService  # type: ignore

log = logging.getLogger("fraudfusion.metering")

# Route map entry: (http_method, path_prefix, billing_operation)
RouteRule = Tuple[str, str, str]

_stats_lock = threading.Lock()
_STATS = {
    "metered": 0,
    "skipped_unmatched": 0,
    "skipped_unattributed": 0,
    "skipped_failed_response": 0,
    "failed": 0,
}


def metering_stats() -> dict:
    """Process-local metering counters — the honest accounting of what was
    billed vs skipped vs lost. Expose on a health/metrics endpoint."""
    with _stats_lock:
        return dict(_STATS)


def reset_metering_stats() -> None:
    with _stats_lock:
        for key in _STATS:
            _STATS[key] = 0


def _bump(key: str) -> None:
    with _stats_lock:
        _STATS[key] += 1


def header_tenant_resolver(header: str = "x-tenant-id") -> Callable[[Request], Optional[str]]:
    """Default tenant attribution: an explicit request header. Services with
    API-key auth should pass their own resolver mapping key -> tenant_id."""
    def resolve(request: Request) -> Optional[str]:
        value = request.headers.get(header, "").strip()
        return value or None
    return resolve


class UsageMeteringMiddleware(BaseHTTPMiddleware):
    """Post successful matched requests to billing-service as usage events.

    routes: list of (method, path_prefix, operation) — a request matches
    when method equals and the path equals the prefix or extends it by one
    segment boundary (prefix + "/...").
    """

    def __init__(self, app, *, routes: List[RouteRule], service_name: str,
                 tenant_resolver: Optional[Callable[[Request], Optional[str]]] = None,
                 billing: Optional[MeshService] = None,
                 units: int = 1,
                 meter_statuses: range = range(200, 400)):
        super().__init__(app)
        self.routes = [(m.upper(), p.rstrip("/"), op) for m, p, op in routes]
        self.service_name = service_name
        self.tenant_resolver = tenant_resolver or header_tenant_resolver()
        self._billing = billing
        self.units = units
        self.meter_statuses = meter_statuses

    def _billing_client(self) -> MeshService:
        if self._billing is None:
            self._billing = MeshService("billing")
        return self._billing

    def _match(self, method: str, path: str) -> Optional[str]:
        for m, prefix, op in self.routes:
            if method.upper() != m:
                continue
            if path == prefix or path.startswith(prefix + "/"):
                return op
        return None

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        operation = self._match(request.method, request.url.path)
        if operation is None:
            _bump("skipped_unmatched")
            return response
        if response.status_code not in self.meter_statuses:
            _bump("skipped_failed_response")
            return response
        tenant_id = self.tenant_resolver(request)
        if not tenant_id:
            _bump("skipped_unattributed")
            log.warning("metering skipped: no tenant attributable for %s %s",
                        request.method, request.url.path)
            return response
        request_id = request.headers.get("x-request-id", "").strip() or uuid.uuid4().hex
        result = self._billing_client().post("/internal/usage", {
            "tenant_id": tenant_id,
            "service": self.service_name,
            "operation": operation,
            "units": self.units,
            "idempotency_key": f"{self.service_name}:{request_id}",
        })
        if result.get("status") == "ok":
            _bump("metered")
        else:
            _bump("failed")
            log.error("metering FAILED for tenant=%s op=%s: %s",
                      tenant_id, operation, result.get("reason"))
        return response
