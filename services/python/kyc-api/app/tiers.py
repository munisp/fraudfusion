"""CBN tiered KYC state machine (Tier 1 / 2 / 3).

Encodes the Central Bank of Nigeria three-tier KYC framework transaction
limits and enforces evidence requirements on tier assignment:

  Tier 1 — basic identity (BVN/NIN + phone):
      ₦50,000 per transaction, ₦300,000 per day.
  Tier 2 — verified ID document + address:
      ₦200,000 per transaction, ₦500,000 per day.
  Tier 3 — full KYC with enhanced due diligence (PEP + sanctions screening,
      credit-bureau check attempted):
      ₦5,000,000 per transaction, no daily cap.

`assign_tier` refuses an upgrade when the required evidence is missing, so a
tier is never a bare label: limits travel with the tier and
`check_transaction` enforces them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class TierLimits:
    tier: str
    single_transaction_ngn: int
    daily_ngn: Optional[int]  # None = unlimited
    requirements: tuple[str, ...]


TIER_LIMITS: dict[str, TierLimits] = {
    "tier_1": TierLimits(
        tier="tier_1",
        single_transaction_ngn=50_000,
        daily_ngn=300_000,
        requirements=("bvn_or_nin",),
    ),
    "tier_2": TierLimits(
        tier="tier_2",
        single_transaction_ngn=200_000,
        daily_ngn=500_000,
        requirements=("bvn_or_nin", "id_document"),
    ),
    "tier_3": TierLimits(
        tier="tier_3",
        single_transaction_ngn=5_000_000,
        daily_ngn=None,  # unlimited daily, subject to enhanced due diligence
        requirements=("bvn_or_nin", "id_document", "enhanced_due_diligence"),
    ),
}

# Verification level offered by each /kyc/verify/* endpoint.
LEVEL_TO_TIER = {"basic": "tier_1", "enhanced": "tier_2", "premium": "tier_3"}


# ---------------------------------------------------------------------------
# Address-verification evidence model (CBN: verify the customer's address and
# maintain physical contact at least every 3 months; electronic-only
# verification is weaker in the deepfake era).
# ---------------------------------------------------------------------------

# Accepted verification methods. 'physical_visit' is an in-person contact;
# 'utility_bill' is documentary; 'electronic' is data-only (weakest).
ADDRESS_VERIFICATION_METHODS = (
    "physical_visit",
    "utility_bill",
    "agent_confirmation",
    "electronic",
)

# Methods that provide no documentary or physical evidence at all.
ELECTRONIC_ONLY_METHODS = ("electronic",)

# CBN quarterly-contact cadence: address evidence older than this is stale.
ADDRESS_EVIDENCE_MAX_AGE_DAYS = 90

# Tiers at which electronic-only address verification is too weak to stand
# alone and must trigger a re-verification review.
ADDRESS_RIGOR_TIERS = ("tier_2", "tier_3")


def parse_verified_at(value: str) -> datetime:
    """Parse an ISO-8601 date/datetime into an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"verified_at is not an ISO-8601 date/datetime: {value!r}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def validate_address_evidence(method: str, verified_at: str) -> dict:
    """Validate one address-evidence record; returns the normalized record."""
    if method not in ADDRESS_VERIFICATION_METHODS:
        raise ValueError(
            f"unknown address verification method {method!r}; "
            f"known: {', '.join(ADDRESS_VERIFICATION_METHODS)}"
        )
    dt = parse_verified_at(verified_at)
    return {"method": method, "verified_at": dt.isoformat()}


def address_evidence_age_days(verified_at: str, now: datetime | None = None) -> int:
    """Whole days since the address was verified (negative -> 0)."""
    dt = parse_verified_at(verified_at)
    now = now or datetime.now(timezone.utc)
    return max(0, (now - dt).days)


def address_review_required(
    tier: str,
    method: Optional[str],
    verified_at: Optional[str],
    now: datetime | None = None,
) -> dict:
    """Decide whether an address re-verification review item is required.

    Rules (documented, deterministic):
      * Tier 2+ with NO address evidence at all -> required
        ('no_address_evidence').
      * Evidence older than ADDRESS_EVIDENCE_MAX_AGE_DAYS (90d) -> required
        at every tier ('address_evidence_stale'); CBN expects physical
        contact at least every 3 months.
      * Tier 2+ whose latest evidence is electronic-only -> required
        ('electronic_only_method'); data-only verification is too weak to
        stand alone at elevated tiers.
    """
    reasons: list[str] = []
    age_days: Optional[int] = None
    if not method or not verified_at:
        if tier in ADDRESS_RIGOR_TIERS:
            reasons.append("no_address_evidence")
    else:
        age_days = address_evidence_age_days(verified_at, now)
        if age_days > ADDRESS_EVIDENCE_MAX_AGE_DAYS:
            reasons.append(
                f"address_evidence_stale ({age_days}d > {ADDRESS_EVIDENCE_MAX_AGE_DAYS}d; "
                "CBN quarterly contact cadence)"
            )
        if tier in ADDRESS_RIGOR_TIERS and method in ELECTRONIC_ONLY_METHODS:
            reasons.append("electronic_only_method (weaker than physical/documentary at tier 2+)")
    return {
        "required": bool(reasons),
        "reasons": reasons,
        "method": method,
        "verified_at": verified_at,
        "age_days": age_days,
        "max_age_days": ADDRESS_EVIDENCE_MAX_AGE_DAYS,
    }


class TierAssignmentError(ValueError):
    """Raised when evidence does not satisfy the target tier requirements."""

    def __init__(self, tier: str, missing: list[str]):
        self.tier = tier
        self.missing = missing
        super().__init__(
            f"cannot assign {tier}: missing evidence: {', '.join(missing)}"
        )


def limits_for(tier: str) -> TierLimits:
    try:
        return TIER_LIMITS[tier]
    except KeyError:
        raise ValueError(f"unknown CBN KYC tier: {tier!r}") from None


def assign_tier(level: str, evidence: dict) -> TierLimits:
    """Assign the CBN tier for a verification level, enforcing evidence.

    evidence keys: bvn_or_nin (bool), id_document (bool),
    enhanced_due_diligence (bool — PEP + sanctions screening performed).
    """
    try:
        tier = LEVEL_TO_TIER[level]
    except KeyError:
        raise ValueError(f"unknown verification level: {level!r}") from None
    limits = TIER_LIMITS[tier]
    missing = [req for req in limits.requirements if not evidence.get(req)]
    if missing:
        raise TierAssignmentError(tier, missing)
    return limits


def check_transaction(tier: str, amount_ngn: float, daily_total_ngn: float = 0.0) -> dict:
    """Enforce tier limits on a proposed transaction.

    Returns {allowed, reason, tier, single_limit_ngn, daily_limit_ngn}.
    """
    limits = limits_for(tier)
    if amount_ngn <= 0:
        return {"allowed": False, "reason": "amount must be positive",
                "tier": tier, "single_limit_ngn": limits.single_transaction_ngn,
                "daily_limit_ngn": limits.daily_ngn}
    if amount_ngn > limits.single_transaction_ngn:
        return {
            "allowed": False,
            "reason": f"exceeds {tier} single-transaction limit of "
                      f"₦{limits.single_transaction_ngn:,}",
            "tier": tier,
            "single_limit_ngn": limits.single_transaction_ngn,
            "daily_limit_ngn": limits.daily_ngn,
        }
    if limits.daily_ngn is not None and daily_total_ngn + amount_ngn > limits.daily_ngn:
        return {
            "allowed": False,
            "reason": f"exceeds {tier} daily limit of ₦{limits.daily_ngn:,}",
            "tier": tier,
            "single_limit_ngn": limits.single_transaction_ngn,
            "daily_limit_ngn": limits.daily_ngn,
        }
    return {
        "allowed": True,
        "reason": "within tier limits",
        "tier": tier,
        "single_limit_ngn": limits.single_transaction_ngn,
        "daily_limit_ngn": limits.daily_ngn,
    }
