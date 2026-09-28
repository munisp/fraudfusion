"""Pydantic request/response models for the billing API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

VALID_OPERATIONS = {"fraud_score", "aml_score", "kyc_verify", "kgqa_query", "land_verification"}


class ApiKeyCreate(BaseModel):
    tenant_id: str = Field(min_length=1)
    name: str = ""
    scopes: list[str] = Field(default_factory=list)
    rate_limit_rpm: int | None = Field(default=None, gt=0)
    expires_at: str | None = None
    # "test" mints an ffk_test_ key: full data-plane access against the
    # tenant's scopes but usage is audit-only (never billed).
    key_type: str = "live"

    @field_validator("scopes")
    @classmethod
    def scopes_known(cls, value: list[str]) -> list[str]:
        unknown = set(value) - VALID_OPERATIONS
        if unknown:
            raise ValueError(f"unknown scopes: {sorted(unknown)}")
        return value

    @field_validator("key_type")
    @classmethod
    def key_type_known(cls, value: str) -> str:
        if value not in ("live", "test"):
            raise ValueError("key_type must be 'live' or 'test'")
        return value


class ApiKeyView(BaseModel):
    id: str
    tenant_id: str
    name: str
    key_prefix: str
    scopes: list[str]
    key_type: str = "live"
    rate_limit_rpm: int
    status: str
    expires_at: str | None
    last_used_at: str | None
    created_at: str


class ApiKeyIssued(ApiKeyView):
    """Plaintext key — returned exactly once at issue/rotation time."""
    plaintext_key: str


class SubscriptionCreate(BaseModel):
    tenant_id: str = Field(min_length=1)
    plan_id: str = Field(min_length=1)
    overrides: dict[str, Any] = Field(default_factory=dict)


class UsageEventIn(BaseModel):
    tenant_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    units: int = Field(default=1, gt=0)
    idempotency_key: str = Field(min_length=1, max_length=255)
    occurred_at: str | None = None
    api_key_id: str | None = None


class IntrospectRequest(BaseModel):
    """Service-to-service API-key introspection (POST /internal/api-keys/introspect)."""
    key: str = Field(min_length=1, max_length=128)


class InvoiceTransition(BaseModel):
    settlement_journal_id: str | None = None  # ledger_journals UUID when paid
    reason: str = ""
