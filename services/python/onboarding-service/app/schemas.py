"""Pydantic request/response schemas — aligned with ml-onboarding-portal/src/api.ts."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field

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
