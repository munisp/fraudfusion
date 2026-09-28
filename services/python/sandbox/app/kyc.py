"""Synthetic KYC verification — mirrors kyc-api response SHAPES.

Response mirrors kyc-api's KYCResponse (request_id, customer_id, status,
verification_level, risk_score, risk_level, decision, verification_results,
timestamp, processing_time_ms) plus the sandbox markers
(environment="sandbox", synthetic=true). All data is deterministic and
invented; no registry is consulted.

BVN/NIN validation mirrors kyc-api's app/identity.py messages so client
error-handling code paths behave the same; the sandbox replaces the real
Luhn/registry checks with its documented magic-suffix fixtures.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

SANDBOX_MARKERS = {"environment": "sandbox", "synthetic": True}


class AddressEvidenceInput(BaseModel):
    method: str
    verified_at: str = Field(min_length=8, max_length=40)


class BasicKYCRequest(BaseModel):
    """Mirror of kyc-api BasicKYCRequest (same fields/constraints)."""
    customer_id: str = Field(min_length=1, max_length=100)
    bvn: Optional[str] = None
    nin: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    date_of_birth: Optional[str] = None
    address_evidence: Optional[AddressEvidenceInput] = None


class EnhancedKYCRequest(BasicKYCRequest):
    check_pep: bool = True
    check_sanctions: bool = True
    nationality: Optional[str] = None


class PremiumKYCRequest(EnhancedKYCRequest):
    check_credit_bureau: bool = True
    credit_bureau_provider: str = "crc"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level(score: float) -> str:
    """Mirrors kyc-api risk bands."""
    if score >= 0.8:
        return "critical"
    if score >= 0.5:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Identity validation (mirrors kyc-api app/identity.py messages)
# ---------------------------------------------------------------------------

def validate_bvn(bvn: Optional[str]) -> dict:
    if not bvn:
        return {"provided": False, "format_valid": False,
                "registry_status": "not_provided"}
    if not (bvn.isdigit() and len(bvn) == 11):
        return {"provided": True, "format_valid": False,
                "reason": "BVN must be exactly 11 digits",
                "registry_status": "not_checked"}
    return {"provided": True, "format_valid": True,
            "registry_status": "sandbox_synthetic",
            "registry_detail": "sandbox fixture — no registry lookup performed"}


def validate_nin(nin: Optional[str]) -> dict:
    if not nin:
        return {"provided": False, "format_valid": False,
                "registry_status": "not_provided"}
    if not (nin.isdigit() and len(nin) == 11):
        return {"provided": True, "format_valid": False,
                "reason": "NIN must be exactly 11 digits",
                "registry_status": "not_checked"}
    if len(set(nin)) == 1:
        return {"provided": True, "format_valid": False,
                "reason": "NIN cannot be a repeated digit",
                "registry_status": "not_checked"}
    return {"provided": True, "format_valid": True,
            "registry_status": "sandbox_synthetic",
            "registry_detail": "sandbox fixture — no registry lookup performed"}


# ---------------------------------------------------------------------------
# Tier fixtures (mirror kyc-api tier_limits_ngn shape; synthetic limits)
# ---------------------------------------------------------------------------

_TIER_FIXTURES = {
    "basic": ("tier_1", 50_000, 300_000),
    "enhanced": ("tier_2", 200_000, 500_000),
    "premium": ("tier_3", 5_000_000, 25_000_000),
}

_TIER_REQUIREMENTS = {
    "tier_1": ["bvn_or_nin"],
    "tier_2": ["bvn_or_nin", "id_document"],
    "tier_3": ["bvn_or_nin", "id_document", "enhanced_due_diligence"],
}


def _phone_tenure_fixture(phone: Optional[str]) -> dict:
    """Mirrors kyc-api app/phone_tenure.py result shape (synthetic values)."""
    if not phone:
        return {"state": "not_provided", "recycled_number_risk": False,
                "risk_contribution": 0.0, "window_days": 90,
                "reason": "no phone number supplied at onboarding"}
    return {"state": "verified_clean", "recycled_number_risk": False,
            "risk_contribution": 0.0, "window_days": 90,
            "signals": {"reassigned_recently": False, "number_age_days": 1825,
                        "prior_owner_account_links": False},
            "reason": "sandbox fixture — synthetic clean tenure"}


def _magic_suffix(payload: BasicKYCRequest) -> Optional[str]:
    """The documented BVN magic suffix (000/001/002/003), if any."""
    bvn = payload.bvn
    if bvn and bvn.isdigit() and len(bvn) == 11 and bvn[-3:] in {
            "000", "001", "002", "003"}:
        return bvn[-3:]
    return None


def run_kyc_verification(level: str, payload: BasicKYCRequest) -> dict:
    """Deterministic synthetic verification mirroring the KYCResponse shape."""
    started = time.perf_counter()
    results: dict[str, Any] = {"level": level}
    risk = 0.10

    bvn_result = validate_bvn(payload.bvn)
    nin_result = validate_nin(payload.nin)
    results["bvn"] = bvn_result
    results["nin"] = nin_result
    results["phone_tenure"] = _phone_tenure_fixture(payload.phone)
    risk += results["phone_tenure"]["risk_contribution"]

    id_ok = (bvn_result.get("provided") and bvn_result["format_valid"]) or (
        nin_result.get("provided") and nin_result["format_valid"])
    id_invalid = (bvn_result.get("provided") and not bvn_result["format_valid"]) or (
        nin_result.get("provided") and not nin_result["format_valid"])

    tier, single_txn, daily = _TIER_FIXTURES[level]
    results["tier"] = tier
    results["tier_limits_ngn"] = {
        "single_transaction": single_txn,
        "daily": daily,
        "requirements": list(_TIER_REQUIREMENTS[tier]),
    }
    results["address_verification"] = {"required": False, "reasons": []}

    suffix = _magic_suffix(payload)
    full_name = f"{payload.first_name} {payload.last_name}"
    check_pep = getattr(payload, "check_pep", False)
    check_sanctions = getattr(payload, "check_sanctions", False)

    pep = sanctions = None
    if level in ("enhanced", "premium") and check_pep:
        is_pep = suffix == "001"
        pep = {"is_pep": is_pep, "matches": (
            [{"name": full_name, "list": "sandbox_pep_fixture",
              "match_score": 0.97}] if is_pep else []),
            "screened_name": full_name, "source": "sandbox_synthetic"}
        results["pep_screening"] = pep
        if is_pep:
            risk += 0.45
    # The sanctions fixture (BVN ...003) fires at EVERY level so the documented
    # magic value holds on the default endpoint too (unlike the real service,
    # where sanctions screening is enhanced/premium-only).
    if (level in ("enhanced", "premium") and check_sanctions) or suffix == "003":
        is_hit = suffix == "003"
        sanctions = {"is_sanctioned": is_hit, "matches": (
            [{"name": full_name, "list": "sandbox_sanctions_fixture",
              "program": "SYNTHETIC", "match_score": 0.99}] if is_hit else []),
            "screened_name": full_name, "source": "sandbox_synthetic"}
        results["sanctions_screening"] = sanctions
        if is_hit:
            risk += 0.85

    if level == "premium" and getattr(payload, "check_credit_bureau", False):
        results["credit_bureau"] = {
            "status": "ok", "provider": getattr(
                payload, "credit_bureau_provider", "crc"),
            "score": 720, "source": "sandbox_synthetic",
            "detail": "sandbox fixture — no bureau call performed"}

    fixture_reject = suffix == "002"
    if fixture_reject:
        risk += 0.85
        results["fixture_outcome"] = (
            "sandbox fixture: BVN ending 002 always rejects")
    elif suffix == "001":
        results["fixture_outcome"] = (
            "sandbox fixture: BVN ending 001 always routes to manual_review")
    elif suffix == "003":
        results["fixture_outcome"] = (
            "sandbox fixture: BVN ending 003 always hits sanctions")

    if id_invalid:
        risk += 0.5
    risk = round(min(risk, 1.0), 3)

    if sanctions and sanctions["is_sanctioned"]:
        decision = "rejected"
    elif id_invalid or fixture_reject:
        decision = "rejected"
    elif (pep and pep["is_pep"]) or risk >= 0.5 or suffix == "001":
        decision = "manual_review"
    else:
        decision = "approved"

    return {
        "request_id": uuid.uuid4().hex,
        "customer_id": payload.customer_id,
        "status": "completed",
        "verification_level": level,
        "risk_score": risk,
        "risk_level": _risk_level(risk),
        "decision": decision,
        "verification_results": results,
        "timestamp": _now(),
        "processing_time_ms": round((time.perf_counter() - started) * 1000, 2),
        **SANDBOX_MARKERS,
    }


# ---------------------------------------------------------------------------
# Document verification (mirrors kyc-api /api/v1/document/verify shape)
# ---------------------------------------------------------------------------

IMAGE_MAGIC = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"%PDF": "pdf",
    b"GIF8": "gif",
    b"RIFF": "webp",
}

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def sniff_type(data: bytes) -> str:
    """Same magic-byte table as kyc-api."""
    for magic, kind in IMAGE_MAGIC.items():
        if data.startswith(magic):
            if kind == "webp" and data[8:12] != b"WEBP":
                continue
            return kind
    return "unknown"


def document_checks(data: bytes, document_type: str, check_forgery: bool,
                    filename: str = "") -> dict:
    """Mirror of kyc-api's _document_checks envelope + deterministic verdict."""
    kind = sniff_type(data)
    checks = [
        {"check": "non_empty", "passed": len(data) > 0},
        {"check": "size_within_limit", "passed": len(data) <= MAX_UPLOAD_BYTES},
        {"check": "recognized_format", "passed": kind != "unknown"},
    ]
    structurally_valid = all(c["passed"] for c in checks)

    # Deterministic magic by filename (documented in README).
    lowered = (filename or "").lower()
    if any(tok in lowered for tok in ("reject", "fail")):
        forced = "rejected"
    elif "review" in lowered:
        forced = "manual_review"
    else:
        forced = None

    forgery = {
        "performed": check_forgery,
        "forgery_detected": forced == "rejected",
        "confidence": 0.99 if forced != "rejected" else 0.05,
        "reason": "sandbox fixture — synthetic forgery analysis "
                  "(no ML model runs in the sandbox)",
        "structural_checks": checks,
    } if check_forgery else {"performed": False, "reason": "check_forgery=false"}

    status = forced or ("verified" if structurally_valid else "rejected")
    return {
        "document_type": document_type,
        "detected_format": kind,
        "size_bytes": len(data),
        "checks": checks,
        "forgery": forgery,
        "structurally_valid": structurally_valid,
        "verification_id": uuid.uuid4().hex,
        "status": status,
        "document_sha256": hashlib.sha256(data).hexdigest(),
        "timestamp": _now(),
        **SANDBOX_MARKERS,
    }
