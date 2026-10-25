"""FraudFusion service mesh — shared fail-closed inter-service client.

Every FraudFusion service can call every other service through this module
with one consistent contract:

  * Env-configured registry: <SERVICE>_URL (e.g. KYC_API_URL,
    LAND_SERVICE_URL, INTEL_SERVICE_URL, ONBOARDING_SERVICE_URL,
    BACKOFFICE_API_URL, BILLING_SERVICE_URL, WEBHOOK_SERVICE_URL,
    DOC_INTEL_URL). Unset = honestly unavailable, NEVER a fabricated result.
  * Internal-token auth: X-Internal-Token (per-service <S>_INTERNAL_TOKEN,
    falling back to FRAUDFUSION_INTERNAL_TOKEN).
  * Fail-closed: any transport/HTTP/JSON error returns
    {"status": "unavailable", "reason": ...} — never raises into the
    caller's request path.
  * Provenance on every call: adapter, source URL, latency_ms.

Mirrors the adapter philosophy of services/python/doc-verification/
adapters.py: availability is reported, never assumed.
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

import httpx

TIMEOUT_SECONDS = float(os.getenv("MESH_TIMEOUT_SECONDS", "3"))

# Canonical registry: service name -> env var carrying its base URL.
REGISTRY = {
    "kyc": "KYC_API_URL",
    "land": "LAND_SERVICE_URL",
    "intel": "INTEL_SERVICE_URL",
    "onboarding": "ONBOARDING_SERVICE_URL",
    "backoffice": "BACKOFFICE_API_URL",
    "billing": "BILLING_SERVICE_URL",
    "webhook": "WEBHOOK_SERVICE_URL",
    "doc_intel": "DOC_INTEL_URL",
    "fraud_signals": "FRAUD_SIGNALS_URL",
    "account_takeover": "ACCOUNT_TAKEOVER_URL",
    "identity_theft": "IDENTITY_THEFT_URL",
    "kg_qa": "KG_QA_URL",
}


class MeshService:
    """Client handle for one peer service. Fail-closed, provenance-first."""

    def __init__(self, name: str, base_url: Optional[str] = None,
                 token: Optional[str] = None,
                 timeout: float = TIMEOUT_SECONDS,
                 transport: httpx.BaseTransport | None = None):
        self.name = name
        env = REGISTRY.get(name, f"{name.upper()}_URL")
        self.base_url = (base_url if base_url is not None
                         else os.getenv(env, "")).strip().rstrip("/")
        self.token = (token if token is not None
                      else os.getenv(f"{name.upper()}_INTERNAL_TOKEN",
                                     os.getenv("FRAUDFUSION_INTERNAL_TOKEN", "")))
        self.timeout = timeout
        self._transport = transport

    @property
    def available(self) -> bool:
        return bool(self.base_url)

    def _headers(self) -> dict[str, str]:
        h = {}
        if self.token:
            h["X-Internal-Token"] = self.token
        # Scope-gated peers (e.g. kyc-api screening) accept a service API
        # key: <SERVICE>_API_KEY env, sent as X-API-Key.
        key = os.getenv(f"{self.name.upper()}_API_KEY", "").strip()
        if key:
            h["X-API-Key"] = key
        return h

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, transport=self._transport)

    def call(self, method: str, path: str,
             json_body: Any = None, params: dict | None = None) -> dict[str, Any]:
        """One mesh call. Returns {"status": "ok", "data": ...} or
        {"status": "unavailable", "reason": ...}; never raises."""
        base = {"adapter": "service_mesh", "service": self.name,
                "source": self.base_url or None}
        if not self.available:
            return {"status": "unavailable",
                    "reason": f"{REGISTRY.get(self.name)} not configured", **base}
        started = time.monotonic()
        try:
            with self._client() as client:
                resp = client.request(method.upper(),
                                      f"{self.base_url}{path}",
                                      json=json_body, params=params,
                                      headers=self._headers())
        except httpx.HTTPError as exc:
            return {"status": "unavailable",
                    "reason": f"{self.name} unreachable "
                              f"({exc.__class__.__name__})", **base}
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        if resp.status_code >= 400:
            return {"status": "unavailable",
                    "reason": f"{self.name} returned HTTP {resp.status_code}",
                    "latency_ms": latency_ms, **base}
        try:
            data = resp.json()
        except ValueError:
            data = {"text": resp.text[:500]}
        return {"status": "ok", "data": data, "latency_ms": latency_ms, **base}

    def get(self, path: str, **kw) -> dict[str, Any]:
        return self.call("GET", path, **kw)

    def post(self, path: str, payload: Any = None, **kw) -> dict[str, Any]:
        return self.call("POST", path, json_body=payload, **kw)

    def ping(self) -> dict[str, Any]:
        """Health probe against the peer's /health endpoint."""
        return self.get("/health")


# ---------------------------------------------------------------------------
# Mesh facade + typed cross-service helpers
# ---------------------------------------------------------------------------

class Mesh:
    """Facade over the registry: mesh.kyc.post(...), mesh.intel.get(...)."""

    def __init__(self, transport: httpx.BaseTransport | None = None,
                 timeout: float = TIMEOUT_SECONDS):
        self._transport = transport
        self._timeout = timeout
        for name in REGISTRY:
            setattr(self, name, MeshService(name, timeout=timeout,
                                            transport=transport))

    def status(self) -> dict[str, Any]:
        """Availability + live health of every registered peer. Used by the
        /integrations/status endpoints; never raises."""
        report = {}
        for name in REGISTRY:
            svc: MeshService = getattr(self, name)
            if not svc.available:
                report[name] = {"configured": False, "reachable": False,
                                "reason": f"{REGISTRY[name]} not configured"}
                continue
            probe = svc.ping()
            report[name] = {
                "configured": True,
                "reachable": probe["status"] == "ok",
                **({"latency_ms": probe["latency_ms"]}
                   if probe["status"] == "ok"
                   else {"reason": probe.get("reason")}),
            }
        return report


_default_mesh: Mesh | None = None


def get_mesh() -> Mesh:
    """Process-lazy default mesh (env is read per call at the service
    level, so tests can re-point URLs with monkeypatch + fresh Mesh())."""
    global _default_mesh
    if _default_mesh is None:
        _default_mesh = Mesh()
    return _default_mesh
