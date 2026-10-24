"""Sandbox registry doubles (Round 10, Lane R).

Deterministic SYNTHETIC mirrors of the response shapes that kyc-api's live
registry adapters (app/registry_adapters.py: NIBSS BVN / NIMC NIN / CAC)
parse. A deployment can point its adapter env URLs at this sandbox —

  NIBSS_BVN_URL=http://localhost:8091/sandbox/registry
  NIMC_API_URL=http://localhost:8091/sandbox/registry
  CAC_API_URL=http://localhost:8091/sandbox/registry

— and integration-test the full adapter wiring end-to-end BEFORE real
registry credentials exist. Everything returned here is invented; every
payload carries "synthetic": true. These endpoints are intentionally open
(like /health): the adapters authenticate with their own Bearer token, and
no real data exists here to protect.

Magic values (documented in README):
  BVN/NIN ending "9"  -> 404 (registry has no record)
  BVN/NIN ending "8"  -> match=false (details mismatch)
  any other 11 digits -> match=true, verified_fields=["name","date_of_birth"]
  RC000002            -> 404 (company not registered)
  RC* ending "9"      -> found but status "INACTIVE"
  any other RC\d{6,8} -> found, status "ACTIVE"
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter()


def _id_response(kind: str, value: str) -> dict:
    if not (value.isdigit() and len(value) == 11):
        raise HTTPException(422, f"{kind} must be exactly 11 digits")
    if value.endswith("9"):
        raise HTTPException(404, "registry has no record for this identifier")
    reference = f"SANDBOX-{kind.upper()}-{value[-4:]}"
    if value.endswith("8"):
        return {"match": False, "verified_fields": [],
                "reference": reference, "synthetic": True}
    return {"match": True, "verified_fields": ["name", "date_of_birth"],
            "reference": reference, "synthetic": True}


@router.get("/bvn/verify")
def bvn_verify(bvn: str = "") -> dict:
    return _id_response("bvn", bvn)


@router.get("/nin/verify")
def nin_verify(nin: str = "") -> dict:
    return _id_response("nin", nin)


@router.get("/company/lookup")
def company_lookup(rc: str = "") -> dict:
    import re
    if not re.match(r"^RC\d{6,8}$", rc or ""):
        raise HTTPException(422, "rc must match ^RC\\d{6,8}$")
    if rc == "RC000002":
        raise HTTPException(404, "company not registered")
    status = "INACTIVE" if rc.endswith("9") else "ACTIVE"
    return {"company": {
        "rc_number": rc,
        "name": f"SANDBOX COMPANY {rc} LTD",
        "status": status,
        "registration_date": "2019-04-12",
    }, "synthetic": True}
