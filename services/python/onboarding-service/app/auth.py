"""Keycloak bearer-token authentication (fail-closed).

Every request is verified against the realm's token-introspection endpoint.
Mirrors the Go detectors' policy: non-HTTPS Keycloak URLs are rejected unless
KEYCLOAK_INSECURE_HTTP=true (in-cluster plaintext / local dev only). When
Keycloak is not configured or introspection fails, requests are denied.

Roles are read from realm_access.roles; staff endpoints require
ONBOARDING_ADMIN_ROLE (default "onboarding_admin"; the realm's "admin" role
is always accepted as well).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx
from fastapi import Header, HTTPException, status

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "fraudfusion")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "onboarding-service")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
ADMIN_ROLE = os.getenv("ONBOARDING_ADMIN_ROLE", "onboarding_admin")
_ADMIN_ROLES = {ADMIN_ROLE, "admin"}


@dataclass
class Principal:
    sub: str
    username: str
    roles: set[str] = field(default_factory=set)

    @property
    def is_admin(self) -> bool:
        return bool(self.roles & _ADMIN_ROLES)


def _introspect(token: str) -> dict:
    if not KEYCLOAK_URL:
        # Fail closed: no identity provider configured => deny.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication provider not configured",
        )
    if KEYCLOAK_URL.startswith("http://") and os.getenv("KEYCLOAK_INSECURE_HTTP", "").lower() != "true":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Keycloak URL must be https (KEYCLOAK_INSECURE_HTTP=true for local dev only)",
        )
    endpoint = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    try:
        response = httpx.post(
            endpoint,
            data={
                "token": token,
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
            },
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"authentication provider unreachable: {exc.__class__.__name__}",
        ) from exc
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"authentication provider error (status {response.status_code})",
        )
    return response.json()


def get_current_principal(authorization: str = Header(default="")) -> Principal:
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _introspect(authorization.removeprefix("Bearer ").strip())
    if not payload.get("active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token is not active",
            headers={"WWW-Authenticate": "Bearer"},
        )
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token has no subject")
    realm_roles = (payload.get("realm_access") or {}).get("roles") or []
    return Principal(
        sub=sub,
        username=payload.get("preferred_username", sub),
        roles=set(realm_roles),
    )


def require_admin(principal: Principal) -> Principal:
    if not principal.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"requires one of the staff roles: {sorted(_ADMIN_ROLES)}",
        )
    return principal
