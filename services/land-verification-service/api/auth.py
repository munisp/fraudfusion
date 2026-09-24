"""
Keycloak bearer-token authentication for the Land Verification Service.

Fail-closed design:
  * Missing/expired token            -> 401
  * Keycloak unreachable or not
    configured (KEYCLOAK_URL unset)  -> 503 (no self-declared identity fallback)

Configuration (environment):
  KEYCLOAK_URL            e.g. http://keycloak:8080  (required)
  KEYCLOAK_REALM          default: fraudfusion
  KEYCLOAK_CLIENT_ID      introspection client id (required)
  KEYCLOAK_CLIENT_SECRET  introspection client secret (required)
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
from typing import Any

import httpx
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "fraudfusion")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")


def auth_configured() -> bool:
    return bool(KEYCLOAK_URL and KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET)


# One shared client for the process: previously a fresh AsyncClient (new
# TCP+TLS connection) was constructed per introspection call.
_shared_client: httpx.AsyncClient | None = None

# Bounded in-process introspection cache (token-hash keyed, TTL + negative
# TTL, singleflight) — takes the Keycloak round trip off every request.
_TOKEN_CACHE_TTL = float(os.getenv("AUTH_CACHE_TTL_SECONDS", "45"))
_TOKEN_NEG_TTL = 5.0
_TOKEN_CACHE_MAX = 10000
_token_cache: dict[str, tuple[float, Any, Any]] = {}
_token_inflight: dict[str, asyncio.Future] = {}
_token_cache_lock = asyncio.Lock()


def _client() -> httpx.AsyncClient:
    global _shared_client
    if _shared_client is None:
        _shared_client = httpx.AsyncClient(
            timeout=5.0,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=32),
        )
    return _shared_client


def _store_token_cache(key: str, entry: tuple[float, Any, Any]) -> None:
    if len(_token_cache) >= _TOKEN_CACHE_MAX:
        now = time.monotonic()
        for k in [k for k, v in _token_cache.items() if v[0] <= now]:
            del _token_cache[k]
        if len(_token_cache) >= _TOKEN_CACHE_MAX:
            return  # correctness never depends on the cache
    _token_cache[key] = entry


async def introspect_token(token: str) -> dict[str, Any]:
    """Call the Keycloak token-introspection endpoint (RFC 7662), cached."""
    key = hashlib.sha256(token.encode()).hexdigest()
    async with _token_cache_lock:
        entry = _token_cache.get(key)
        if entry and entry[0] > time.monotonic():
            _, claims, exc = entry
            if exc is not None:
                raise exc
            return claims
        fut = _token_inflight.get(key)
        leader = fut is None
        if leader:
            fut = asyncio.get_running_loop().create_future()
            _token_inflight[key] = fut
    if not leader:
        claims, exc = await fut
        if exc is not None:
            raise exc
        return claims
    url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    try:
        response = await _client().post(
            url,
            data={"token": token},
            auth=(KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET),
        )
        response.raise_for_status()
        claims = response.json()
        ttl = _TOKEN_CACHE_TTL if claims.get("active") else _TOKEN_NEG_TTL
        _store_token_cache(key, (time.monotonic() + ttl, claims, None))
        fut.set_result((claims, None))
        return claims
    except Exception as exc:
        _store_token_cache(key, (time.monotonic() + _TOKEN_NEG_TTL, None, exc))
        fut.set_result((None, exc))
        raise
    finally:
        async with _token_cache_lock:
            _token_inflight.pop(key, None)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """Resolve the authenticated Keycloak subject (user id). Fail-closed."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Bearer token required")
    if not auth_configured():
        raise HTTPException(
            status_code=503,
            detail="Authentication is not configured (KEYCLOAK_URL / client credentials missing).",
        )
    try:
        claims = await introspect_token(credentials.credentials)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Token introspection unavailable")
    if not claims.get("active"):
        raise HTTPException(status_code=401, detail="Token is not active")
    subject = claims.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="Token has no subject")
    return subject
