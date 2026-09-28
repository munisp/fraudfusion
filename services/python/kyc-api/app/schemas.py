"""Pydantic schemas — aligned with frontend/kyc-frontend/src/services/api.ts."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class AddressEvidenceInput(BaseModel):
    """Address-verification evidence supplied at onboarding/review.

    method: how the address was verified (physical_visit | utility_bill |
    agent_confirmation | electronic). verified_at: ISO-8601 date/datetime of
    the verification — drives the CBN quarterly-contact staleness check."""
    method: Literal["physical_visit", "utility_bill", "agent_confirmation", "electronic"]
    verified_at: str = Field(min_length=8, max_length=40)


class CounterpartyRigorEntry(BaseModel):
    """Admin-managed counterparty verification-rigor registry entry."""
    institution_code: str = Field(min_length=2, max_length=50)
    institution_name: str = Field(min_length=2, max_length=255)
    rigor_level: Literal["cbn_full_biometric", "cbn_basic", "unverified", "unknown"]
    source_note: str = Field(default="", max_length=1000)


class BasicKYCRequest(BaseModel):
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


class KYCResponse(BaseModel):
    request_id: str
    customer_id: str
    status: str
    verification_level: str
    risk_score: float
    risk_level: str
    decision: str
    verification_results: dict[str, Any]
    timestamp: str
    processing_time_ms: float


class BiometricVerifyRequest(BaseModel):
    selfie_image_base64: str = Field(min_length=1)
    reference_image_base64: Optional[str] = None
    check_liveness: bool = True


class ScreeningRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=200)
    date_of_birth: Optional[str] = None
    nationality: Optional[str] = None
    passport_number: Optional[str] = None


class CreditBureauRequest(BaseModel):
    bvn: str = Field(min_length=11, max_length=11)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    provider: str = "crc"


class FraudCheckRequest(BaseModel):
    customer_id: str = Field(min_length=1, max_length=100)
    transaction_data: dict[str, Any]
    historical_data: Optional[list[dict[str, Any]]] = None


class BehavioralAnalysisRequest(BaseModel):
    customer_id: str = Field(min_length=1, max_length=100)
    behavioral_data: dict[str, Any]


class RekycRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
    deadline_days: int = Field(default=30, ge=1, le=180)


class AppealRequest(BaseModel):
    kyc_request_id: Optional[str] = None  # defaults to the customer's latest request
    grounds: str = Field(min_length=10, max_length=2000)


class AppealDecisionRequest(BaseModel):
    decision: str = Field(pattern="^(upheld|overturned|dismissed)$")
    reason: str = Field(min_length=3, max_length=2000)
