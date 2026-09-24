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

import os
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


async def introspect_token(token: str) -> dict[str, Any]:
    """Call the Keycloak token-introspection endpoint (RFC 7662)."""
    url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            url,
            data={"token": token},
            auth=(KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET),
        )
    response.raise_for_status()
    return response.json()


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
