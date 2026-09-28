"""Synthetic intel endpoints — mirror intel-service SHAPES.

- GET /v1/intel/national/summary: deterministic synthetic national summary in
  the real response shape.
- POST /v1/intel/request-legitimacy/assess: the same documented, deterministic
  heuristic matrix as intel-service (it is stateless there too, so the sandbox
  mirrors it faithfully) — response shape identical, note field marks it
  sandbox-synthetic.
- POST /v1/intel/cultural/score: same documented weights/bands as
  intel-service; the artifact-backed calendar/ajo layers are replaced by a
  small static synthetic calendar (documented in README).
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any, Optional

from pydantic import BaseModel, Field

SANDBOX_MARKERS = {"environment": "sandbox", "synthetic": True}

# ---------------------------------------------------------------------------
# National summary (deterministic synthetic fixture)
# ---------------------------------------------------------------------------

NATIONAL_SUMMARY: dict[str, Any] = {
    "data_period_weeks": 26,
    "provenance": "sandbox_synthetic — invented aggregates, no real data",
    "national_fraud_rate": {"posterior_mean": 0.0213, "ci95": [0.0192, 0.0235]},
    "week_trend": {"direction": "flat", "delta_last4_vs_prior4": 0.0004},
    "top_typologies": [
        {"typology": "social_engineering", "share": 0.31},
        {"typology": "account_takeover", "share": 0.24},
        {"typology": "sim_swap", "share": 0.17},
        {"typology": "merchant_fraud", "share": 0.12},
        {"typology": "romance_investment", "share": 0.09},
    ],
    "totals": {"txn_year": 1_240_000_000, "fraud_year": 26_400_000},
    "forecast_4wk": [
        {"week": 1, "posterior_mean": 0.0214, "ci95": [0.0190, 0.0239]},
        {"week": 2, "posterior_mean": 0.0215, "ci95": [0.0189, 0.0242]},
        {"week": 3, "posterior_mean": 0.0213, "ci95": [0.0186, 0.0243]},
        {"week": 4, "posterior_mean": 0.0216, "ci95": [0.0187, 0.0246]},
    ],
    "model_version": "sandbox-synthetic-1.0.0",
}


# ---------------------------------------------------------------------------
# Request legitimacy (mirrors intel-service app/request_legitimacy.py)
# ---------------------------------------------------------------------------

MATRIX_VERSION = "1.0.0"

KNOWN_FIELDS = [
    "bvn", "nin", "dob", "phone", "plate_number", "otp", "voters_card",
    "passport", "address", "email",
]
CREDENTIAL_FIELDS = {"bvn", "nin", "otp", "voters_card", "passport"}
ENTITY_TYPES = ["road_safety", "bank", "fintech", "telco", "employer", "unknown"]
VERDICT_RISK = {"expected": 0.0, "plausible": 0.35, "inappropriate": 1.0,
                "unrecognized": 0.6}

APPROPRIATENESS_MATRIX: dict[str, dict[str, str]] = {
    "road_safety": {
        "plate_number": "expected", "dob": "plausible", "phone": "plausible",
        "email": "plausible", "address": "plausible", "bvn": "inappropriate",
        "nin": "inappropriate", "otp": "inappropriate",
        "voters_card": "inappropriate", "passport": "inappropriate",
    },
    "bank": {
        "bvn": "expected", "dob": "expected", "phone": "expected",
        "email": "expected", "address": "expected", "nin": "plausible",
        "voters_card": "plausible", "passport": "plausible",
        "otp": "inappropriate", "plate_number": "inappropriate",
    },
    "fintech": {
        "bvn": "expected", "dob": "expected", "phone": "expected",
        "email": "expected", "address": "plausible", "nin": "plausible",
        "voters_card": "plausible", "passport": "plausible",
        "otp": "inappropriate", "plate_number": "inappropriate",
    },
    "telco": {
        "nin": "expected", "phone": "expected", "dob": "plausible",
        "email": "plausible", "address": "plausible", "bvn": "inappropriate",
        "otp": "inappropriate", "plate_number": "inappropriate",
        "voters_card": "inappropriate", "passport": "inappropriate",
    },
    "employer": {
        "phone": "expected", "email": "expected", "dob": "plausible",
        "address": "plausible", "bvn": "plausible", "nin": "plausible",
        "passport": "plausible", "otp": "inappropriate",
        "plate_number": "inappropriate", "voters_card": "inappropriate",
    },
    "unknown": {
        "bvn": "inappropriate", "nin": "inappropriate", "otp": "inappropriate",
        "voters_card": "inappropriate", "passport": "inappropriate",
        "plate_number": "inappropriate", "dob": "plausible",
        "phone": "plausible", "email": "plausible", "address": "plausible",
    },
}

DEFAULT_VERDICT: dict[str, str] = {
    "road_safety": "inappropriate", "bank": "plausible", "fintech": "plausible",
    "telco": "inappropriate", "employer": "plausible", "unknown": "inappropriate",
}

CHANNEL_MULTIPLIERS: dict[str, float] = {
    "in_person": 0.8, "ussd": 0.9, "web_form": 1.0, "email": 1.1, "sms": 1.2,
}
LINK_MULTIPLIER = 1.3
OTP_LINK_BONUS = 0.2
INAPPROPRIATE_LINK_BONUS = 0.1
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
    """Mirror of intel-service RequestLegitimacyAssessRequest."""
    requesting_entity_type: str
    fields_requested: list[str] = Field(default_factory=list)
    channel: str
    link_present: bool = False


def _verdict_for(entity_type: str, field: str) -> tuple[str, str]:
    if field not in KNOWN_FIELDS:
        return "unrecognized", (f"'{field}' is not in the known-field taxonomy; "
                                f"cannot confirm a legitimate need")
    row = APPROPRIATENESS_MATRIX[entity_type]
    verdict = row.get(field, DEFAULT_VERDICT[entity_type])
    reasons = {
        "expected": (f"a {entity_type} entity legitimately needs '{field}' "
                     f"for its normal business"),
        "plausible": (f"a {entity_type} entity may legitimately need '{field}' "
                      f"in some verified flows"),
        "inappropriate": (f"a {entity_type} entity has NO legitimate need for "
                          f"'{field}' — a classic identity-theft tell"),
    }
    return verdict, reasons[verdict]


def assess_legitimacy(req: RequestLegitimacyAssessRequest) -> dict[str, Any]:
    """Same deterministic scoring as intel-service; sandbox note appended."""
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
        if req.link_present and verdict == "expected" and field in CREDENTIAL_FIELDS:
            verdict = "plausible"
            reason += ("; downgraded because the request arrives via a link — "
                       "navigate directly to the organisation's official site "
                       "instead")
        if field == "otp":
            otp_requested = True
            if verdict != "inappropriate":
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
        "note": ("sandbox synthetic — same documented heuristic matrix as "
                 "intel-service; entity-TYPE based scoring, never vouches for "
                 "a specific sender"),
        **SANDBOX_MARKERS,
    }


# ---------------------------------------------------------------------------
# Cultural score (mirrors intel-service app/cultural.py shape)
# ---------------------------------------------------------------------------

CULTURAL_FRAUD_WEIGHTS = {
    "temporal_anomaly": 0.20,
    "network_anomaly": 0.25,
    "cultural_inconsistency": 0.20,
    "amount_anomaly": 0.15,
    "communication_anomaly": 0.10,
    "urgency": 0.10,
}


class AjoAssessRequest(BaseModel):
    """Mirror of intel-service AjoAssessRequest."""
    n_members: int = Field(ge=2, le=500)
    contribution_cv: float = Field(ge=0.0, le=10.0)
    cadence_cv: float = Field(ge=0.0, le=10.0)
    rotation_coverage: float = Field(ge=0.0, le=1.0)
    payout_ratio: float = Field(ge=0.0, le=100.0)
    tenure_days: float = Field(ge=0.0, le=100000.0)


class CulturalScoreRequest(BaseModel):
    """Mirror of intel-service CulturalScoreRequest."""
    model_config = {"populate_by_name": True}
    indicators: dict[str, float] = Field(default_factory=dict)
    claimed_event: str | None = None
    date_: date | None = Field(None, alias="date")
    state: str | None = None
    network_consistent_with_claimed_norm: bool = False
    ajo_pattern: AjoAssessRequest | None = None


def _synthetic_event_active(claimed_event: str, on_date: date) -> bool:
    """Small static synthetic calendar (the artifact-backed calendar in
    intel-service is replaced here; documented in README):
      detty_december: Dec 15-31 · christmas: Dec 24-26 · new_year: Dec 31-Jan 2
      salary_week: 25th-2nd of any month · independence_day: Oct 1."""
    claim = claimed_event.lower()
    md = (on_date.month, on_date.day)
    if claim in ("detty_december", "detty"):
        return on_date.month == 12 and on_date.day >= 15
    if claim == "christmas":
        return on_date.month == 12 and 24 <= on_date.day <= 26
    if claim == "new_year":
        return md in ((12, 31), (1, 1), (1, 2))
    if claim == "independence_day":
        return md == (10, 1)
    if claim == "salary_week":
        return on_date.day >= 25 or on_date.day <= 2
    if claim in ("ajo", "esusu", "adashe", "cooperative"):
        return True  # rotating savings run year-round
    return False


def cultural_score(req: CulturalScoreRequest) -> dict[str, Any]:
    indicators = {k: min(max(float(v), 0.0), 1.0)
                  for k, v in req.indicators.items()}
    unknown = sorted(set(indicators) - set(CULTURAL_FRAUD_WEIGHTS))
    if unknown:
        from fastapi import HTTPException
        raise HTTPException(status_code=422,
                            detail=f"unknown indicators: {unknown}")
    raw = sum(CULTURAL_FRAUD_WEIGHTS[k] * v for k, v in indicators.items())
    discount = 0.0
    notes: list[str] = []
    if req.claimed_event and req.date_ is not None:
        if _synthetic_event_active(req.claimed_event, req.date_):
            discount += 0.05
            notes.append("claimed event window matches the (synthetic sandbox) "
                         "cultural calendar")
        else:
            raw = min(1.0, raw + 0.10)
            notes.append("CLAIMED EVENT IS OUT OF ITS CULTURAL WINDOW "
                         "(calendar inconsistency)")
    if req.network_consistent_with_claimed_norm:
        discount += 0.05
        notes.append("network structure consistent with the claimed norm")
    if (req.ajo_pattern is not None and req.claimed_event
            and req.claimed_event.lower() in ("ajo", "esusu", "adashe",
                                              "cooperative")):
        rp = req.ajo_pattern
        # Simplified deterministic heuristic (artifact logistic model is
        # unavailable in the sandbox): plausible ajo pattern = full rotation
        # coverage, low cadence variance, payout ratio near 1.
        plausible = (rp.rotation_coverage >= 0.9 and rp.cadence_cv <= 0.5
                     and 0.8 <= rp.payout_ratio <= 1.2)
        if plausible:
            discount += 0.05
            notes.append("rotation pattern consistent with legitimate ajo "
                         "(sandbox heuristic)")
        else:
            notes.append("rotation pattern INCONSISTENT with legitimate ajo "
                         "(sandbox heuristic)")
    discount = min(discount, 0.15)
    final = min(max(raw - discount, 0.0), 1.0)
    return {
        "cultural_fraud_score": round(final, 4),
        "risk_band": risk_band(final),
        "indicator_breakdown": {
            k: {"severity": indicators.get(k, 0.0),
                "weight": CULTURAL_FRAUD_WEIGHTS[k],
                "contribution": round(indicators.get(k, 0.0)
                                      * CULTURAL_FRAUD_WEIGHTS[k], 4)}
            for k in CULTURAL_FRAUD_WEIGHTS},
        "authenticity_discount": round(discount, 4),
        "authenticity_notes": notes,
        "weights_source": ("canonical normalisation of the domain documents' "
                           "indicator weights (NIGERIAN_CULTURAL_FRAUD_PATTERNS_*) "
                           "— sandbox synthetic"),
        "provenance": "sandbox_synthetic — static calendar, no artifact",
        **SANDBOX_MARKERS,
    }
