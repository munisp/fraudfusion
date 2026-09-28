"""Keycloak bearer-token authentication for billing control-plane (fail-closed).

Same policy as the onboarding service: every control-plane request is
verified against the realm's token-introspection endpoint; when Keycloak is
not configured or introspection fails, requests are denied.

Tenant scoping: a principal carries a `tenant_id` claim (the tenant the
authenticated user belongs to). Tenant-scoped endpoints allow access when
`principal.tenant_id == <target tenant>` or when the principal holds the
billing admin role (BILLING_ADMIN_ROLE, default "billing_admin"; the realm
"admin" role is always accepted).

Data-plane endpoints (metered calls) use API keys instead — see keys.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx
from fastapi import Header, HTTPException, status

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "fraudfusion")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "billing-service")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
ADMIN_ROLE = os.getenv("BILLING_ADMIN_ROLE", "billing_admin")
_ADMIN_ROLES = {ADMIN_ROLE, "admin"}


@dataclass
class Principal:
    sub: str
    username: str
    roles: set[str] = field(default_factory=set)
    tenant_id: str = ""

    @property
    def is_admin(self) -> bool:
        return bool(self.roles & _ADMIN_ROLES)

    def require_tenant(self, tenant_id: str) -> None:
        """Fail-closed tenant scoping for control-plane endpoints."""
        if self.is_admin:
            return
        if not tenant_id or self.tenant_id != tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="principal is not authorized for this tenant",
            )


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
        )
    data = _introspect(authorization[len("Bearer "):])
    if not data.get("active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token inactive or invalid",
        )
    roles = set(data.get("realm_access", {}).get("roles", []))
    tenant_id = data.get("tenant_id") or data.get("tenant") or ""
    return Principal(
        sub=data.get("sub", ""),
        username=data.get("preferred_username", ""),
        roles=roles,
        tenant_id=tenant_id,
    )


def require_admin(principal: Principal) -> Principal:
    if not principal.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="billing admin role required",
        )
    return principal
