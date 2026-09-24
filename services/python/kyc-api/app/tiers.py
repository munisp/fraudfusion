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
