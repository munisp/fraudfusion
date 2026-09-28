"""Request-legitimacy router for intel-service (mounted under
/v1/intel/request-legitimacy/).

Scores whether an entity's request for personal data is LEGITIMATE given who
is asking — the field-guidance heuristic from the NIN/BVN identity-theft
reporting: a data request is suspicious when the entity has no legitimate
need for that field ("if FRSC asks for your plate number that makes sense;
your BVN, not so much").

    POST /v1/intel/request-legitimacy/assess

The core of the module is APPROPRIATENESS_MATRIX: explicit, documented,
tunable data mapping entity TYPE x field -> expected / plausible /
inappropriate. It is deliberately entity-TYPE based (road_safety, bank,
fintech, telco, employer, unknown) and never names specific real companies.
Nigerian context encoded:

  * banks/fintechs may request BVN (regulated KYC via verified flows);
  * telcos may request NIN (SIM-registration mandate);
  * road_safety NEVER needs BVN/NIN/OTP — its business is plate numbers,
    licences, and vehicle data;
  * NO legitimate entity requests an OTP via a link — OTPs are generated FOR
    you, never collected FROM you;
  * even when an entity legitimately needs a credential field, a bare link is
    never the safe channel (expected -> plausible downgrade + safe-action
    guidance).

Stateless by design: no artifact, no DB, no torch — pure scoring.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger("intel-service.request-legitimacy")

MATRIX_VERSION = "1.0.0"

# --- taxonomy --------------------------------------------------------------
# Recognised fields (request values are normalised: lowercase, spaces/dashes
# -> underscores). Unrecognised fields score as "unrecognized" (mild risk).
KNOWN_FIELDS = [
    "bvn", "nin", "dob", "phone", "plate_number", "otp", "voters_card",
    "passport", "address", "email",
]

# Credential-grade fields: the ones harvested in identity-theft campaigns.
# When a link is present, an "expected" verdict for these is downgraded to
# "plausible" — a legitimate need never makes the LINK a safe channel.
CREDENTIAL_FIELDS = {"bvn", "nin", "otp", "voters_card", "passport"}

ENTITY_TYPES = ["road_safety", "bank", "fintech", "telco", "employer", "unknown"]

# Verdict -> base field risk.
VERDICT_RISK = {"expected": 0.0, "plausible": 0.35, "inappropriate": 1.0,
                "unrecognized": 0.6}

# --- THE MATRIX (explicit data; tune here, not in code) ---------------------
# Entity-type rows; field columns; values are verdicts. Absent cells fall
# back to DEFAULT_VERDICT[entity_type]. Design notes per row in comments.
APPROPRIATENESS_MATRIX: dict[str, dict[str, str]] = {
    # FRSC-lite bodies: plates, licences, vehicle data are their business.
    # They NEVER need BVN/NIN/OTP ("your BVN, not so much").
    "road_safety": {
        "plate_number": "expected",
        "dob": "plausible",        # driver licensing captures DOB in person
        "phone": "plausible",
        "email": "plausible",
        "address": "plausible",
        "bvn": "inappropriate",
        "nin": "inappropriate",
        "otp": "inappropriate",
        "voters_card": "inappropriate",
        "passport": "inappropriate",
    },
    # Regulated banking KYC legitimately captures BVN — via verified flows
    # (branch, official app, *USSD#), never via an SMS link.
    "bank": {
        "bvn": "expected",
        "dob": "expected",
        "phone": "expected",
        "email": "expected",
        "address": "expected",
        "nin": "plausible",        # Tier-3 KYC
        "voters_card": "plausible",  # accepted ID alternative
        "passport": "plausible",
        "otp": "inappropriate",    # banks never ASK for your OTP
        "plate_number": "inappropriate",
    },
    # Licensed fintechs run BVN KYC under the same BVN-watchlist regime.
    "fintech": {
        "bvn": "expected",
        "dob": "expected",
        "phone": "expected",
        "email": "expected",
        "address": "plausible",
        "nin": "plausible",
        "voters_card": "plausible",
        "passport": "plausible",
        "otp": "inappropriate",
        "plate_number": "inappropriate",
    },
    # NIN-SIM linkage is a statutory telco mandate; BVN is not a telco field.
    "telco": {
        "nin": "expected",
        "phone": "expected",
        "dob": "plausible",
        "email": "plausible",
        "address": "plausible",
        "bvn": "inappropriate",
        "otp": "inappropriate",
        "plate_number": "inappropriate",
        "voters_card": "inappropriate",
        "passport": "inappropriate",
    },
    # Employers legitimately collect contact + payroll-KYC data after an
    # offer; OTPs and plate numbers are never employment data.
    "employer": {
        "phone": "expected",
        "email": "expected",
        "dob": "plausible",
        "address": "plausible",
        "bvn": "plausible",        # payroll/bank-verification onboarding
        "nin": "plausible",
        "passport": "plausible",
        "otp": "inappropriate",
        "plate_number": "inappropriate",
        "voters_card": "inappropriate",
    },
    # Unknown claimant: core identity credentials are inappropriate by
    # default — an unidentifiable requester has no legitimate need for them.
    "unknown": {
        "bvn": "inappropriate",
        "nin": "inappropriate",
        "otp": "inappropriate",
        "voters_card": "inappropriate",
        "passport": "inappropriate",
        "plate_number": "inappropriate",
        "dob": "plausible",
        "phone": "plausible",
        "email": "plausible",
        "address": "plausible",
    },
}

# Fallback verdict for an entity/field cell not explicitly listed.
DEFAULT_VERDICT: dict[str, str] = {
    "road_safety": "inappropriate",   # narrow legitimate scope
    "bank": "plausible",
    "fintech": "plausible",
    "telco": "inappropriate",
    "employer": "plausible",
    "unknown": "inappropriate",
}

# Channel risk multipliers: remote, spoofable channels amplify risk.
CHANNEL_MULTIPLIERS: dict[str, float] = {
    "in_person": 0.8,
    "ussd": 0.9,
    "web_form": 1.0,
    "email": 1.1,
    "sms": 1.2,
}

LINK_MULTIPLIER = 1.3            # any link in the request
OTP_LINK_BONUS = 0.2             # OTP + link: canonical smishing signature
INAPPROPRIATE_LINK_BONUS = 0.1   # inappropriate field harvested via a link

RISK_BANDS = [(0.8, "critical"), (0.6, "high"), (0.4, "medium"), (0.0, "low")]


def risk_band(score: float) -> str:
    for thr, band in RISK_BANDS:
        if score >= thr:
            return band
    return "low"


def _norm(value: str) -> str:
    v = value.strip().lower().replace("-", "_").replace(" ", "_")
    return re.sub(r"[^a-z0-9_]", "", v)


class RequestLegitimacyAssessRequest(BaseModel):
    """A data-collection request to be scored for legitimacy."""
    requesting_entity_type: str = Field(
        description="entity TYPE only (road_safety, bank, fintech, telco, "
                    "employer, unknown) — never a specific company name")
    fields_requested: list[str] = Field(
        default_factory=list,
        description="e.g. bvn, nin, dob, phone, plate_number, otp, "
                    "voters_card, passport, address, email")
    channel: str = Field(description="sms, email, web_form, in_person, ussd")
    link_present: bool = False


def _verdict_for(entity_type: str, field: str) -> tuple[str, str]:
    """(verdict, reason) for one entity/field cell."""
    if field not in KNOWN_FIELDS:
        return "unrecognized", (f"'{field}' is not in the known-field taxonomy; "
                                f"cannot confirm a legitimate need")
    row = APPROPRIATENESS_MATRIX[entity_type]
    if field in row:
        verdict = row[field]
    else:
        verdict = DEFAULT_VERDICT[entity_type]
    reasons = {
        "expected": (f"a {entity_type} entity legitimately needs '{field}' "
                     f"for its normal business"),
        "plausible": (f"a {entity_type} entity may legitimately need '{field}' "
                      f"in some verified flows"),
        "inappropriate": (f"a {entity_type} entity has NO legitimate need for "
                          f"'{field}' — a classic identity-theft tell"),
    }
    return verdict, reasons[verdict]


def assess(req: RequestLegitimacyAssessRequest) -> dict[str, Any]:
    """Pure scoring function (kept separate from the router for unit tests)."""
    entity_type = _norm(req.requesting_entity_type)
    if entity_type not in APPROPRIATENESS_MATRIX:
        entity_type = "unknown"
    channel = _norm(req.channel)
    channel_mult = CHANNEL_MULTIPLIERS.get(channel, 1.0)

    field_verdicts: list[dict[str, str]] = []
    risks: list[float] = []
    has_inappropriate = False
    otp_requested = False
    for raw_field in req.fields_requested:
        field = _norm(raw_field)
        verdict, reason = _verdict_for(entity_type, field)
        # Link-channel downgrade: even a legitimate need never makes a bare
        # link a safe channel for credential-grade fields.
        if req.link_present and verdict == "expected" and field in CREDENTIAL_FIELDS:
            verdict = "plausible"
            reason += ("; downgraded because the request arrives via a link — "
                       "navigate directly to the organisation's official site "
                       "instead")
        if field == "otp":
            otp_requested = True
            if verdict != "inappropriate":  # defensive: matrix says it already
                verdict = "inappropriate"
            reason += ("; no legitimate entity requests your OTP — OTPs are "
                       "generated FOR you, never collected FROM you")
        if verdict == "inappropriate":
            has_inappropriate = True
        risks.append(VERDICT_RISK[verdict])
        field_verdicts.append({"field": field, "verdict": verdict,
                               "reason": reason})

    base = sum(risks) / len(risks) if risks else 0.0
    score = base * channel_mult
    if req.link_present:
        score *= LINK_MULTIPLIER
    bonuses: list[str] = []
    if otp_requested and req.link_present:
        score += OTP_LINK_BONUS
        bonuses.append("OTP requested via a link — canonical smishing signature")
    if has_inappropriate and req.link_present:
        score += INAPPROPRIATE_LINK_BONUS
        bonuses.append("inappropriate field(s) harvested via a link")
    score = round(min(max(score, 0.0), 1.0), 4)

    inappropriate = [v["field"] for v in field_verdicts
                     if v["verdict"] == "inappropriate"]
    if inappropriate:
        explanation = (
            f"A {entity_type} entity has no legitimate need for "
            f"{', '.join(inappropriate)} — that mismatch is the core "
            f"identity-theft tell. Requests for {', '.join(inappropriate)} "
            f"arriving over {channel}"
            + (" with a link" if req.link_present else "")
            + " should be treated as hostile until independently verified."
        )
    elif score < 0.4:
        explanation = (
            f"The fields requested are consistent with what a {entity_type} "
            f"entity legitimately needs. Residual risk comes only from the "
            f"{channel} channel itself — verify the sender independently."
        )
    else:
        explanation = (
            f"The fields requested are individually plausible for a "
            f"{entity_type} entity, but the {channel} channel"
            + (" with an embedded link" if req.link_present else "")
            + " elevates the risk — verify through an official channel first."
        )

    safe_action = (
        "Do NOT use any link in the message. Navigate directly to the "
        "organisation's official website or app (type the address yourself), "
        "or call its published helpline, and ask whether the request is "
        "genuine. Never share BVN, NIN, OTP, or card PIN in response to an "
        "unsolicited message."
    )

    return {
        "score": score,
        "risk_band": risk_band(score),
        "requesting_entity_type": entity_type,
        "channel": channel,
        "link_present": req.link_present,
        "field_verdicts": field_verdicts,
        "rule_bonuses": bonuses,
        "explanation": explanation,
        "safe_action": safe_action,
        "matrix_version": MATRIX_VERSION,
        "note": ("entity-TYPE based heuristic scoring (documented, tunable "
                 "matrix) — no specific company names; a legitimate-NEED "
                 "verdict never vouches for a specific sender"),
    }


def create_request_legitimacy_router() -> APIRouter:
    router = APIRouter(prefix="/v1/intel/request-legitimacy",
                       tags=["request-legitimacy"])

    @router.post("/assess")
    def assess_endpoint(req: RequestLegitimacyAssessRequest):
        return assess(req)

    @router.get("/matrix")
    def matrix():
        """Expose the tunable appropriateness matrix for audit/review."""
        return {"matrix_version": MATRIX_VERSION,
                "entity_types": ENTITY_TYPES,
                "known_fields": KNOWN_FIELDS,
                "credential_fields": sorted(CREDENTIAL_FIELDS),
                "appropriateness_matrix": APPROPRIATENESS_MATRIX,
                "default_verdict": DEFAULT_VERDICT,
                "verdict_risk": VERDICT_RISK,
                "channel_multipliers": CHANNEL_MULTIPLIERS,
                "link_multiplier": LINK_MULTIPLIER,
                "risk_bands": [{"min_score": thr, "band": band}
                               for thr, band in RISK_BANDS]}

    return router
