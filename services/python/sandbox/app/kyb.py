"""Synthetic KYB verification — mirrors onboarding-service SHAPES.

POST /api/v1/onboarding/kyb returns the KybApplicationView shape (camelCase
aliases, exactly like the real service); GET .../kyb/{id}/verification returns
the kyb_verification.verify_kyb_documents verdict envelope. Deterministic
fixtures keyed on the CAC number (see fixtures.py / README.md). Application
ids are deterministic (sha256 of cac+business name) so a developer can
re-fetch the verification without storing anything — the sandbox keeps an
in-memory registry too, so both flows work.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

SANDBOX_MARKERS = {"environment": "sandbox", "synthetic": True}

CAC_NUMBER_RE = re.compile(r"^RC\d{6,8}$")

BusinessType = Literal["business_name", "limited_liability", "plc", "ngo",
                       "partnership"]

KYB_MAX_UPLOAD_BYTES = 10 * 1024 * 1024
KYB_MAX_CONTENT_CHARS = 14_000_000


class KybDocument(BaseModel):
    """Mirror of onboarding-service KybDocument."""
    type: Literal["cac_certificate", "memart", "utility_bill", "board_resolution"]
    reference: str = Field(min_length=1, max_length=500)
    content: Optional[str] = Field(default=None, max_length=KYB_MAX_CONTENT_CHARS)

    @field_validator("content")
    @classmethod
    def _content_is_base64(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        import base64
        import binascii
        try:
            if not base64.b64decode(value, validate=True):
                raise ValueError("content decodes to empty bytes")
        except (binascii.Error, ValueError) as exc:
            raise ValueError("content must be non-empty valid base64") from exc
        return value


class KybSubmission(BaseModel):
    """Mirror of onboarding-service KybSubmission (same aliases/validators)."""
    business_name: str = Field(alias="businessName", min_length=2, max_length=200)
    cac_number: str = Field(alias="cacNumber")
    business_type: BusinessType = Field(default="limited_liability",
                                        alias="businessType")
    contact_email: EmailStr = Field(alias="contactEmail")
    documents: list[KybDocument] = Field(min_length=1)

    model_config = {"populate_by_name": True}

    @field_validator("cac_number")
    @classmethod
    def _cac(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not CAC_NUMBER_RE.match(normalized):
            raise ValueError(
                "CAC number must look like RC1234567 (RC followed by 6-8 digits)")
        return normalized


_CAC_VERDICTS = {
    "RC000000": "verified",
    "RC000001": "manual_review",
    "RC000002": "rejected",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def deterministic_application_id(business_name: str, cac_number: str) -> str:
    digest = hashlib.sha256(f"{cac_number}|{business_name}".encode()).hexdigest()
    return f"kyb_{digest[:16]}"


def _doc_verdict(doc: KybDocument, verdict: str, cac_number: str) -> dict:
    """Per-document verdict mirroring kyb_verification._doc_result shape."""
    sha = None
    if doc.content is not None:
        import base64
        sha = hashlib.sha256(base64.b64decode(doc.content)).hexdigest()
    checks = []
    if doc.type == "cac_certificate":
        checks.append({"check": "rc_matches_submission",
                       "passed": verdict != "rejected",
                       "detail": f"sandbox fixture for {cac_number}"})
    notes = {
        "verified": ["sandbox fixture: document content verified (synthetic)"],
        "manual_review": ["sandbox fixture: document routed to manual review"],
        "rejected": ["sandbox fixture: document failed verification"],
    }[verdict]
    return {
        "type": doc.type,
        "reference": doc.reference,
        "content_sha256": sha,
        "verdict": verdict,
        "checks": checks,
        "extracted": ({"company_name": None, "rc_number": cac_number}
                      if doc.type == "cac_certificate" else {}),
        "notes": notes,
    }


def build_kyb_verdict(payload: KybSubmission) -> dict:
    """Verdict envelope mirroring kyb_verification.verify_kyb_documents."""
    verdict = _CAC_VERDICTS.get(payload.cac_number, "verified")
    docs_with_content = sum(1 for d in payload.documents if d.content is not None)
    per_doc = [_doc_verdict(d, verdict, payload.cac_number)
               for d in payload.documents]
    reasons = {
        "verified": "all submitted document content verified and consistent "
                    "(sandbox fixture)",
        "manual_review": "one or more documents need human review "
                         "(sandbox fixture: CAC RC000001)",
        "rejected": "one or more documents failed verification "
                    "(sandbox fixture: CAC RC000002)",
    }
    cac_check = next((c["passed"] for d in per_doc
                      if d["type"] == "cac_certificate"
                      for c in d["checks"]
                      if c["check"] == "rc_matches_submission"), None)
    return {
        "verdict": verdict,
        "reason": reasons[verdict],
        "documents": per_doc,
        "documents_with_content": docs_with_content,
        "documents_total": len(payload.documents),
        "consistency": {
            "cac_rc_matches_submission": cac_check,
            "memart_cac_name_consistent": True if verdict == "verified" else None,
        },
        "provenance": {
            "engines": ["sandbox_fixture"],
            "doc_verification_importable": False,
            "pypdf_available": False,
        },
        "verified_at": _now(),
        **SANDBOX_MARKERS,
    }


def build_application_view(payload: KybSubmission, verdict: dict,
                           api_key: str) -> dict:
    """KybApplicationView-shaped response (camelCase, like the real service)."""
    status = {"verified": "approved", "manual_review": "under_review",
              "rejected": "rejected"}[verdict["verdict"]]
    return {
        "applicationId": deterministic_application_id(
            payload.business_name, payload.cac_number),
        "businessName": payload.business_name,
        "cacNumber": payload.cac_number,
        "businessType": payload.business_type,
        "status": status,
        "submittedBy": f"apikey:{api_key[:12]}…",
        "reviewedBy": None,
        "approvedBy": "sandbox-auto" if status == "approved" else None,
        "rejectionReason": (verdict["reason"] if status == "rejected" else None),
        "createdAt": verdict["verified_at"],
        "verification": {
            "verdict": verdict["verdict"],
            "verifiedAt": verdict["verified_at"],
            "engines": verdict["provenance"]["engines"],
            "documentsWithContent": verdict["documents_with_content"],
        },
        **SANDBOX_MARKERS,
    }
