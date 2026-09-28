"""Keycloak JWT authentication for backoffice-api (fail-closed).

Tokens are verified against the realm JWKS endpoint (RS256). When
KEYCLOAK_URL is not configured, every request is denied 503 — there is no
mock/dev fallback. Tenant scoping comes from the `tenant_id` claim (default
"default"); every query in this service is filtered by it.

Logout and admin revocation are honored via backoffice_session_revocations:
a token is rejected when its jti is revoked, or when its `sub` was revoked
after the token was issued (revoked_at > iat).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import jwt as pyjwt
from fastapi import Depends, Header, HTTPException, status

from app.db import Database, get_db

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "fraudfusion")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "backoffice-api")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")

# Roles allowed to perform backoffice mutations (dual control is additional).
OPS_ROLES = {"admin", "backoffice_admin", "backoffice_ops"}

_jwks_client = None


def _jwks():
    global _jwks_client
    if _jwks_client is None:
        url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
        _jwks_client = pyjwt.PyJWKClient(url)
    return _jwks_client


def reset_jwks_for_tests() -> None:
    global _jwks_client
    _jwks_client = None


@dataclass
class Principal:
    sub: str
    email: str = ""
    name: str = ""
    roles: set[str] = field(default_factory=set)
    tenant_id: str = "default"
    jti: str = ""
    iat: int = 0

    @property
    def can_operate(self) -> bool:
        return bool(self.roles & OPS_ROLES)


def _deny(status_code: int, detail: str) -> None:
    raise HTTPException(status_code=status_code, detail=detail)


def get_principal(
    authorization: str | None = Header(default=None),
    db: Database = Depends(get_db),
) -> Principal:
    if not KEYCLOAK_URL:
        _deny(status.HTTP_503_SERVICE_UNAVAILABLE,
              "authentication provider not configured (KEYCLOAK_URL)")
    if not authorization or not authorization.startswith("Bearer "):
        _deny(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        key = _jwks().get_signing_key_from_jwt(token).key
        claims = pyjwt.decode(
            token, key, algorithms=["RS256"],
            options={"verify_aud": False},
        )
    except pyjwt.PyJWTError as exc:
        _deny(status.HTTP_401_UNAUTHORIZED, f"invalid token: {exc.__class__.__name__}")

    principal = Principal(
        sub=claims.get("sub", ""),
        email=claims.get("email", ""),
        name=claims.get("name", ""),
        roles=set((claims.get("realm_access") or {}).get("roles") or []),
        tenant_id=claims.get("tenant_id", "default"),
        jti=claims.get("jti", ""),
        iat=int(claims.get("iat", 0)),
    )
    if not principal.sub:
        _deny(status.HTTP_401_UNAUTHORIZED, "token missing sub")

    # Revocation checks (logout / admin session kill).
    if principal.jti:
        revoked = db.query_one(
            "SELECT 1 AS x FROM backoffice_session_revocations"
            " WHERE tenant_id = :t AND jti = :j",
            {"t": principal.tenant_id, "j": principal.jti},
        )
        if revoked:
            _deny(status.HTTP_401_UNAUTHORIZED, "session revoked")
    sub_revoked = db.query_one(
        "SELECT revoked_at FROM backoffice_session_revocations"
        " WHERE tenant_id = :t AND jti = '*' AND sub = :s"
        " ORDER BY revoked_at DESC LIMIT 1",
        {"t": principal.tenant_id, "s": principal.sub},
    )
    if sub_revoked:
        from datetime import datetime

        try:
            revoked_at = datetime.fromisoformat(
                str(sub_revoked["revoked_at"]).replace("Z", "+00:00")).timestamp()
        except ValueError:
            revoked_at = float("inf")  # unparseable revocation => fail closed
        if principal.iat <= revoked_at:
            _deny(status.HTTP_401_UNAUTHORIZED, "session revoked")
    return principal


def require_ops(principal: Principal) -> None:
    if not principal.can_operate:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"requires one of the backoffice ops roles: {sorted(OPS_ROLES)}",
        )
