"""Dual data-plane authentication for intel-service.

Data-plane endpoints (/v1/intel/*) accept EITHER:

  * a staff Keycloak bearer token (app/auth.py — mirrors kyc-api), OR
  * a tenant API key (``X-API-Key: ffk_live_*`` / ``ffk_test_*``) validated
    against billing-service's ``POST /internal/api-keys/introspect``.

API-key validation is FAIL-CLOSED: when BILLING_INTROSPECT_URL is unset or
billing is unreachable the request is denied (503); inactive keys are denied
(401). Introspection responses are cached in-process for at most
CACHE_TTL_SECONDS keyed by the SHA-256 of the presented key (the plaintext
key is never stored). Scope enforcement is per-endpoint via
``require_scope(...)``; the tenant_id from billing is attached to the
principal. (intel-service serves aggregate, k-anonymity-suppressed data with
no tenant-owned rows, so tenant scoping is attach-only here.)
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import Depends, Header, HTTPException, Request, status

from app.auth import Principal, get_current_principal

log = logging.getLogger("intel-service.api_keys")

BILLING_INTROSPECT_URL = os.getenv("BILLING_INTROSPECT_URL", "").strip()
BILLING_INTERNAL_TOKEN = os.getenv("BILLING_INTERNAL_TOKEN", "")
INTROSPECT_TIMEOUT_SECONDS = 2.0
CACHE_TTL_SECONDS = 60.0  # <= 60s per the shared contract


@dataclass
class ApiKeyPrincipal:
    """Tenant machine principal derived from a validated ffk_ API key."""
    key_id: str
    tenant_id: str
    scopes: list[str] = field(default_factory=list)
    key_type: str = "live"
    auth_method: str = "api_key"
    roles: set[str] = field(default_factory=set)

    @property
    def sub(self) -> str:
        return f"apikey:{self.key_id}"

    @property
    def username(self) -> str:
        return self.sub


def is_api_key(principal: Any) -> bool:
    return getattr(principal, "auth_method", "jwt") == "api_key"


def principal_tenant(principal: Any) -> str:
    return getattr(principal, "tenant_id", "") or "default"


# ---------------------------------------------------------------------------
# Introspection with a bounded in-memory TTL cache
# ---------------------------------------------------------------------------

class _IntrospectCache:
    def __init__(self, ttl: float = CACHE_TTL_SECONDS):
        self._ttl = ttl
        self._entries: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def get(self, digest: str) -> dict | None:
        with self._lock:
            entry = self._entries.get(digest)
            if entry is None:
                return None
            expires, payload = entry
            if time.monotonic() >= expires:
                self._entries.pop(digest, None)
                return None
            return payload

    def put(self, digest: str, payload: dict) -> None:
        with self._lock:
            self._entries[digest] = (time.monotonic() + self._ttl, payload)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_CACHE = _IntrospectCache()


def reset_cache_for_tests() -> None:
    _CACHE.clear()


def _post(url: str, **kwargs) -> httpx.Response:
    """Seam for tests (monkeypatch) — the real path is a plain httpx POST."""
    return httpx.post(url, **kwargs)


def _lookup_key(key: str) -> dict:
    """Return billing's introspection payload for the key (cached <= 60s)."""
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    cached = _CACHE.get(digest)
    if cached is not None:
        return cached
    if not BILLING_INTROSPECT_URL:
        # Fail closed: no validator configured => deny.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "API-key validation not configured (BILLING_INTROSPECT_URL unset)",
        )
    try:
        response = _post(
            BILLING_INTROSPECT_URL,
            json={"key": key},
            headers={"X-Internal-Token": BILLING_INTERNAL_TOKEN},
            timeout=INTROSPECT_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"API-key validator unreachable: {exc.__class__.__name__}",
        ) from exc
    if response.status_code != 200:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"API-key validator error (status {response.status_code})",
        )
    payload = response.json()
    _CACHE.put(digest, payload)
    return payload


def _principal_from_api_key(key: str) -> ApiKeyPrincipal:
    if not key.startswith("ffk_"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "malformed API key")
    payload = _lookup_key(key)
    if not payload.get("active"):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"API key not active: {payload.get('reason', 'unknown reason')}",
        )
    return ApiKeyPrincipal(
        key_id=payload.get("key_id", ""),
        tenant_id=payload.get("tenant_id", ""),
        scopes=[str(s) for s in payload.get("scopes") or []],
        key_type=payload.get("key_type") or "live",
    )


def _jwt_principal(request: Request, authorization: str) -> Principal:
    # Honour FastAPI dependency_overrides on the staff-JWT dependency so test
    # suites can override get_current_principal directly.
    override = request.app.dependency_overrides.get(get_current_principal)
    if override is not None:
        return override()
    return get_current_principal(authorization=authorization)


def get_data_principal(
    request: Request,
    authorization: str = Header(default=""),
    x_api_key: str = Header(default=""),
) -> Principal | ApiKeyPrincipal:
    """Dual auth: X-API-Key wins when present; otherwise staff bearer JWT."""
    if x_api_key.strip():
        return _principal_from_api_key(x_api_key.strip())
    return _jwt_principal(request, authorization)


def require_scope(scope: str):
    """Per-endpoint scope enforcement for API-key principals. Staff JWT
    principals are unaffected."""

    def dependency(
        principal: Principal | ApiKeyPrincipal = Depends(get_data_principal),
    ) -> Principal | ApiKeyPrincipal:
        if is_api_key(principal) and scope not in principal.scopes:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"API key lacks required scope '{scope}'",
            )
        return principal

    return dependency
