"""Pydantic schemas for the Land Document Verification Service."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class DocumentType(str, enum.Enum):
    CERTIFICATE_OF_OCCUPANCY = "c_of_o"
    SURVEY_PLAN = "survey_plan"
    DEED_OF_ASSIGNMENT = "deed_of_assignment"
    GOVERNMENT_ALLOCATION = "government_allocation"


class State(str, enum.Enum):
    LAGOS = "lagos"
    FCT = "fct"
    RIVERS = "rivers"
    OGUN = "ogun"
    KANO = "kano"


class VerificationStatus(str, enum.Enum):
    """State machine states for a verification."""

    RECEIVED = "received"
    DOCUMENT_ANALYSIS = "document_analysis"
    REGISTRY_LOOKUP = "registry_lookup"
    SITE_INSPECTION = "site_inspection"
    FRAUD_REVIEW = "fraud_review"
    COMPLETED = "completed"
    REJECTED = "rejected"


# Allowed transitions for the verification state machine.
ALLOWED_TRANSITIONS: dict[VerificationStatus, set[VerificationStatus]] = {
    VerificationStatus.RECEIVED: {VerificationStatus.DOCUMENT_ANALYSIS, VerificationStatus.REJECTED},
    VerificationStatus.DOCUMENT_ANALYSIS: {
        VerificationStatus.REGISTRY_LOOKUP,
        VerificationStatus.FRAUD_REVIEW,
        VerificationStatus.REJECTED,
    },
    VerificationStatus.REGISTRY_LOOKUP: {
        VerificationStatus.SITE_INSPECTION,
        VerificationStatus.FRAUD_REVIEW,
        VerificationStatus.COMPLETED,
        VerificationStatus.REJECTED,
    },
    VerificationStatus.SITE_INSPECTION: {
        VerificationStatus.FRAUD_REVIEW,
        VerificationStatus.COMPLETED,
        VerificationStatus.REJECTED,
    },
    VerificationStatus.FRAUD_REVIEW: {
        VerificationStatus.COMPLETED,
        VerificationStatus.REJECTED,
    },
    VerificationStatus.COMPLETED: set(),
    VerificationStatus.REJECTED: set(),
}

TERMINAL_STATES = {VerificationStatus.COMPLETED, VerificationStatus.REJECTED}


class Party(BaseModel):
    """A party to a land transaction (assignor/assignee, grantor/grantee)."""

    name: str
    role: str = Field(default="assignee", description="assignor|assignee|grantor|grantee|surveyor")
    bvn: Optional[str] = None
    nin: Optional[str] = None
    cac_number: Optional[str] = None


class Parcel(BaseModel):
    """A land parcel referenced by a document."""

    plot_number: Optional[str] = None
    survey_plan_number: Optional[str] = None
    address: Optional[str] = None
    state: Optional[State] = None
    lga: Optional[str] = None
    size_sqm: Optional[float] = None
    beacon_coordinates: list[str] = Field(default_factory=list)


class DocumentUploadRequest(BaseModel):
    document_type: DocumentType
    file_name: Optional[str] = None
    file_size: int = 0
    mime_type: Optional[str] = None
    user_id: str
    state: State


class VerificationRequest(BaseModel):
    verification_id: str
    document_upload: DocumentUploadRequest
    user_id: str
    priority: str = "normal"


class StateTransition(BaseModel):
    verification_id: str
    from_status: Optional[VerificationStatus]
    to_status: VerificationStatus
    reason: str = ""
    actor: str = "system"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class VerificationResult(BaseModel):
    verification_id: str
    status: VerificationStatus
    document_type: DocumentType
    parcel: Optional[Parcel] = None
    parties: list[Party] = Field(default_factory=list)
    extracted_data: dict[str, Any] = Field(default_factory=dict)
    ocr_confidence: float = 0.0
    registry_verification: Optional[dict[str, Any]] = None
    cac_verification: Optional[dict[str, Any]] = None
    surveyor_verification: Optional[dict[str, Any]] = None
    coordinate_verification: Optional[dict[str, Any]] = None
    fraud_detection: Optional[dict[str, Any]] = None
    verification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    processing_time_seconds: float = 0.0
