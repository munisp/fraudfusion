"""Pydantic request/response schemas — aligned with ml-onboarding-portal/src/api.ts."""

from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

Environment = Literal["sandbox", "production"]
KycTier = Literal["basic", "enhanced", "premium"]
TenantState = Literal["not_started", "in_progress", "pending_review", "active", "suspended"]
KeyStatus = Literal["pending", "reviewed", "approved", "rejected", "revoked"]


class ApiKeyRequest(BaseModel):
    organization: str = Field(min_length=2, max_length=200)
    contact_email: EmailStr = Field(alias="contactEmail")
    use_case: str = Field(default="", alias="useCase", max_length=2000)
    environment: Environment = "sandbox"
    label: str = Field(default="", max_length=200)

    model_config = {"populate_by_name": True}


class ApiKeyGrant(BaseModel):
    key_id: str = Field(alias="keyId")
    api_key: Optional[str] = Field(default=None, alias="apiKey")
    environment: str
    status: str

    model_config = {"populate_by_name": True}


class KycTierSelection(BaseModel):
    tenant_id: str = Field(alias="tenantId")
    tier: KycTier

    model_config = {"populate_by_name": True}


class ChecklistItem(BaseModel):
    id: str
    label: str
    done: bool
    required: bool


class ChecklistUpdate(BaseModel):
    done: bool


class OnboardingStatus(BaseModel):
    tenant_id: str = Field(alias="tenantId")
    tier: Optional[str] = None
    api_key_issued: bool = Field(alias="apiKeyIssued")
    checklist: list[ChecklistItem]
    state: TenantState
    updated_at: Optional[str] = Field(default=None, alias="updatedAt")

    model_config = {"populate_by_name": True}


class ApprovalDecision(BaseModel):
    reason: str = Field(default="", max_length=2000)


class ApiKeyRequestView(BaseModel):
    """Staff-facing view of an API key request (never includes key material)."""

    key_id: str = Field(alias="keyId")
    tenant_id: str = Field(alias="tenantId")
    organization: str
    environment: str
    status: KeyStatus
    key_prefix: Optional[str] = Field(default=None, alias="keyPrefix")
    requested_by: str = Field(alias="requestedBy")
    reviewed_by: Optional[str] = Field(default=None, alias="reviewedBy")
    approved_by: Optional[str] = Field(default=None, alias="approvedBy")
    rejection_reason: Optional[str] = Field(default=None, alias="rejectionReason")
    created_at: Optional[str] = Field(default=None, alias="createdAt")

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# KYB / merchant / regulator-access extensions (20260827_pep_kyb_merchant.sql)
# ---------------------------------------------------------------------------

CAC_NUMBER_RE = re.compile(r"^RC\d{6,8}$")  # e.g. RC1234567
NUBAN_RE = re.compile(r"^\d{10}$")

BusinessType = Literal["business_name", "limited_liability", "plc", "ngo", "partnership"]
ApplicationStatus = Literal["submitted", "under_review", "approved", "rejected"]


def _validate_cac(value: str) -> str:
    normalized = value.strip().upper()
    if not CAC_NUMBER_RE.match(normalized):
        raise ValueError("CAC number must look like RC1234567 (RC followed by 6-8 digits)")
    return normalized


# Mirrors kyc-api's MAX_UPLOAD_BYTES convention (10MB per document). The
# base64 envelope inflates bytes by ~4/3, so the raw string cap is slightly
# above 13.3M chars; the exact decoded-size check (413) happens at intake in
# app/main.py, the same place kyc-api enforces it.
KYB_MAX_UPLOAD_BYTES = 10 * 1024 * 1024
KYB_MAX_CONTENT_CHARS = 14_000_000


class KybDocument(BaseModel):
    """One KYB supporting document. `reference` (e.g. an s3:// pointer) is
    always required; `content` is an OPTIONAL base64-encoded copy of the
    document bytes for automated verification. Content is never persisted or
    logged — only its SHA-256 hash is stored alongside the reference."""
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
    business_name: str = Field(alias="businessName", min_length=2, max_length=200)
    cac_number: str = Field(alias="cacNumber")
    business_type: BusinessType = Field(default="limited_liability", alias="businessType")
    contact_email: EmailStr = Field(alias="contactEmail")
    documents: list[KybDocument] = Field(min_length=1)

    model_config = {"populate_by_name": True}

    _cac = field_validator("cac_number")(_validate_cac)


class KybReverifyRequest(BaseModel):
    """Optional resubmitted documents for POST /kyb/{id}/reverify. Document
    content is never retained (hash-only), so a content re-run requires the
    documents to be supplied again here; an empty body just returns the
    stored verdict."""
    documents: list[KybDocument] = Field(default_factory=list)


class KybVerificationSummary(BaseModel):
    """Compact verdict summary embedded in KYB application views (the full
    per-document verdict JSON is served by GET .../kyb/{id}/verification)."""
    verdict: str  # verified | manual_review | rejected | engine_unavailable | skipped
    verified_at: Optional[str] = Field(default=None, alias="verifiedAt")
    engines: list[str] = Field(default_factory=list)
    documents_with_content: int = Field(alias="documentsWithContent")

    model_config = {"populate_by_name": True}


class KybApplicationView(BaseModel):
    application_id: str = Field(alias="applicationId")
    business_name: str = Field(alias="businessName")
    cac_number: str = Field(alias="cacNumber")
    business_type: str = Field(alias="businessType")
    status: str
    submitted_by: str = Field(alias="submittedBy")
    reviewed_by: Optional[str] = Field(default=None, alias="reviewedBy")
    approved_by: Optional[str] = Field(default=None, alias="approvedBy")
    rejection_reason: Optional[str] = Field(default=None, alias="rejectionReason")
    created_at: Optional[str] = Field(default=None, alias="createdAt")
    verification: Optional[KybVerificationSummary] = None

    model_config = {"populate_by_name": True}


class MerchantSubmission(BaseModel):
    business_name: str = Field(alias="businessName", min_length=2, max_length=200)
    cac_number: Optional[str] = Field(default=None, alias="cacNumber")
    merchant_category: str = Field(default="general", alias="merchantCategory", max_length=100)
    settlement_bank_code: str = Field(alias="settlementBankCode", min_length=3, max_length=10)
    settlement_account: str = Field(alias="settlementAccount")
    contact_email: EmailStr = Field(alias="contactEmail")

    model_config = {"populate_by_name": True}

    _cac = field_validator("cac_number")(lambda v: _validate_cac(v) if v else v)

    @field_validator("settlement_account")
    @classmethod
    def _nuban(cls, value: str) -> str:
        if not NUBAN_RE.match(value.strip()):
            raise ValueError("settlement account must be a 10-digit NUBAN")
        return value.strip()


class MerchantApplicationView(BaseModel):
    application_id: str = Field(alias="applicationId")
    business_name: str = Field(alias="businessName")
    merchant_category: str = Field(alias="merchantCategory")
    status: str
    submitted_by: str = Field(alias="submittedBy")
    reviewed_by: Optional[str] = Field(default=None, alias="reviewedBy")
    approved_by: Optional[str] = Field(default=None, alias="approvedBy")
    rejection_reason: Optional[str] = Field(default=None, alias="rejectionReason")
    created_at: Optional[str] = Field(default=None, alias="createdAt")

    model_config = {"populate_by_name": True}


class AgentSubmission(BaseModel):
    """CBN agent-banking agent onboarding. The BVN is captured BY REFERENCE
    ONLY: the service stores a salted SHA-256 hash, never the plaintext."""
    agent_code: str = Field(min_length=3, max_length=100)
    full_name: str = Field(min_length=2, max_length=200)
    principal_fintech: str = Field(min_length=2, max_length=255)
    principal_reference: str = Field(min_length=3, max_length=255)
    bvn: str = Field(min_length=11, max_length=11)
    float_account_number: str = Field(min_length=10, max_length=10)
    float_account_bank: str = Field(min_length=3, max_length=10)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    cbn_tier: str = Field(pattern="^(tier_1|tier_2|tier_3)$")

    @field_validator("bvn")
    @classmethod
    def _bvn_digits(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("BVN must be 11 digits")
        return value

    @field_validator("float_account_number")
    @classmethod
    def _nuban(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("float account must be a 10-digit NUBAN")
        return value


class AgentApplicationView(BaseModel):
    model_config = {"populate_by_name": True}

    id: str
    agent_code: str
    full_name: str
    principal_fintech: str
    principal_reference: str
    float_account_number: str
    float_account_bank: str
    latitude: float
    longitude: float
    cbn_tier: str = Field(serialization_alias="cbnTier")
    status: str
    screening_status: str = Field(serialization_alias="screeningStatus")
    submitted_by: str = Field(serialization_alias="submittedBy")
    reviewed_by: Optional[str] = Field(default=None, serialization_alias="reviewedBy")
    approved_by: Optional[str] = Field(default=None, serialization_alias="approvedBy")
    created_at: str = Field(serialization_alias="createdAt")
    updated_at: str = Field(serialization_alias="updatedAt")


class AgentApplicationPage(BaseModel):
    items: list[AgentApplicationView]
    next_cursor: Optional[str] = Field(default=None, serialization_alias="nextCursor")


# ---------------------------------------------------------------------------
# Agent integrity scoring (enrollment-agent fraud-rate surveillance)
# ---------------------------------------------------------------------------

AgentOutcome = Literal["clean", "flagged", "confirmed_fraud"]


class AgentOutcomeSubmission(BaseModel):
    """Post-onboarding outcome for one customer enrolled by an agent."""
    customer_ref: str = Field(min_length=1, max_length=200)
    outcome: AgentOutcome


class AgentOutcomeView(BaseModel):
    model_config = {"populate_by_name": True}

    outcome_id: str = Field(serialization_alias="outcomeId")
    agent_id: str = Field(serialization_alias="agentId")
    customer_ref: str = Field(serialization_alias="customerRef")
    outcome: str
    recorded_at: str = Field(serialization_alias="recordedAt")


class AgentIntegrityView(BaseModel):
    """Agent integrity score. k-anonymity: below min_enrollments the
    fraud_rate is suppressed ('insufficient_data') so small agents are never
    extreme-scored or individually exposed."""
    model_config = {"populate_by_name": True}

    agent_id: str = Field(serialization_alias="agentId")
    status: str  # 'ok' | 'insufficient_data'
    enrollments: int
    fraud_rate: Optional[float] = Field(default=None, serialization_alias="fraudRate")
    prior_mean: float = Field(serialization_alias="priorMean")
    alert: bool = False
    alert_threshold: float = Field(serialization_alias="alertThreshold")
    min_enrollments: int = Field(serialization_alias="minEnrollments")
    counts: dict = Field(default_factory=dict)


class RegulatorAccessRequest(BaseModel):
    regulator_org: str = Field(alias="regulatorOrg", min_length=2, max_length=100)
    principal_sub: str = Field(alias="principalSub", min_length=1, max_length=200)
    expires_in_days: int = Field(alias="expiresInDays", ge=1, le=365)

    model_config = {"populate_by_name": True}


class RegulatorAccessView(BaseModel):
    access_id: str = Field(alias="accessId")
    regulator_org: str = Field(alias="regulatorOrg")
    principal_sub: str = Field(alias="principalSub")
    scope: str
    status: str
    requested_by: str = Field(alias="requestedBy")
    approved_by: Optional[str] = Field(default=None, alias="approvedBy")
    expires_at: str = Field(alias="expiresAt")

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Keyset-paginated list envelopes. Hot list endpoints return one of these
# instead of an unbounded array: `items` plus an opaque `next_cursor` that the
# caller passes back as the `cursor` query param until it comes back null.
# Keyset (WHERE (created_at, id) </> (cursor...)) keeps page cost O(limit)
# regardless of depth, unlike OFFSET scans.
# ---------------------------------------------------------------------------


class ApiKeyRequestPage(BaseModel):
    items: list[ApiKeyRequestView]
    next_cursor: Optional[str] = None


class KybApplicationPage(BaseModel):
    items: list[KybApplicationView]
    next_cursor: Optional[str] = None


class MerchantApplicationPage(BaseModel):
    items: list[MerchantApplicationView]
    next_cursor: Optional[str] = None
