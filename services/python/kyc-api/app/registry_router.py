"""Live-registry verification endpoints (Round 10, Lane R).

Self-contained APIRouter mounted by main.py. Dual auth via app/api_keys.py
(scope: kyc_verify). Format validation reuses app/identity.py; registry
lookups go through app/registry_adapters.py (fail-closed — unconfigured
registries report honest unavailable). Requests are logged HASH-ONLY in
document_verifications (registry_reference + outcome, never PII payloads).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app import identity, registry_adapters
from app.api_keys import require_scope
from app.auth import Principal
from app.db import Database, get_db

logger = logging.getLogger(__name__)

_RC_RE = re.compile(r"^RC\d{6,8}$")


class BvnVerifyRequest(BaseModel):
    bvn: str = Field(min_length=11, max_length=11, pattern=r"^\d{11}$")


class NinVerifyRequest(BaseModel):
    nin: str = Field(min_length=11, max_length=11, pattern=r"^\d{11}$")


class CacLookupRequest(BaseModel):
    rc_number: str


def _audit(db: Database, actor: str, doc_type: str, subject: str,
           outcome: str, provenance: dict) -> None:
    try:
        db.execute(
            "INSERT INTO document_verifications (id, actor_sub, document_type,"
            " detected_format, sha256, size_bytes, status, provenance_json,"
            " reasons_json, created_at)"
            " VALUES (:id, :actor, :dt, :fmt, :sha, 0, :st, :prov, '[]', :now)",
            {"id": uuid.uuid4().hex, "actor": actor, "dt": doc_type,
             "fmt": "registry_lookup",
             "sha": hashlib.sha256(subject.encode()).hexdigest(),
             "st": {"verified": "verified", "found": "verified",
                    "mismatch": "rejected", "not_found": "rejected"}.get(
                        outcome, "unavailable"),
             "prov": json.dumps([provenance]),
             "now": datetime.now(timezone.utc).isoformat()})
    except Exception as exc:  # audit must never break the lookup
        logger.error("registry audit persistence failed: %s", exc)


def create_registry_router() -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/registry/status")
    async def registry_status(
        principal: Principal = Depends(require_scope("kyc_verify")),
    ) -> dict:
        """Availability report for all three registries (honest)."""
        return {"registries": [
            registry_adapters.get_bvn_adapter().availability(),
            registry_adapters.get_nin_adapter().availability(),
            registry_adapters.get_cac_adapter().availability(),
        ]}

    @router.post("/api/v1/registry/bvn/verify")
    async def bvn_verify(
        payload: BvnVerifyRequest,
        principal: Principal = Depends(require_scope("kyc_verify")),
        db: Database = Depends(get_db),
    ) -> dict:
        fmt = identity.validate_bvn(payload.bvn)
        if not fmt.get("format_valid"):
            return {"status": "invalid_format", "format_check": fmt,
                    "registry": None}
        result = registry_adapters.get_bvn_adapter().verify_bvn(payload.bvn)
        _audit(db, getattr(principal, "sub", ""), "bvn_registry", payload.bvn,
               result["status"], {k: result.get(k) for k in
                                  ("adapter", "source", "reason")})
        return {"status": result["status"], "format_check": fmt,
                "registry": result}

    @router.post("/api/v1/registry/nin/verify")
    async def nin_verify(
        payload: NinVerifyRequest,
        principal: Principal = Depends(require_scope("kyc_verify")),
        db: Database = Depends(get_db),
    ) -> dict:
        fmt = identity.validate_nin(payload.nin)
        if not fmt.get("format_valid"):
            return {"status": "invalid_format", "format_check": fmt,
                    "registry": None}
        result = registry_adapters.get_nin_adapter().verify_nin(payload.nin)
        _audit(db, getattr(principal, "sub", ""), "nin_registry", payload.nin,
               result["status"], {k: result.get(k) for k in
                                  ("adapter", "source", "reason")})
        return {"status": result["status"], "format_check": fmt,
                "registry": result}

    @router.post("/api/v1/registry/cac/lookup")
    async def cac_lookup(
        payload: CacLookupRequest,
        principal: Principal = Depends(require_scope("kyc_verify")),
        db: Database = Depends(get_db),
    ) -> dict:
        if not _RC_RE.match(payload.rc_number or ""):
            raise HTTPException(422, "rc_number must match ^RC\\d{6,8}$")
        result = registry_adapters.get_cac_adapter().lookup_company(
            payload.rc_number)
        _audit(db, getattr(principal, "sub", ""), "cac_registry",
               payload.rc_number, result["status"],
               {k: result.get(k) for k in ("adapter", "source", "reason")})
        return {"status": result["status"], "registry": result}

    return router
