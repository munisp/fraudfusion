"""Explainable composite risk scoring (Round 13, feature 6).

Every signal the land module records contributes a weighted penalty to a
0-100 risk score, with each factor reported so a reviewer (or a partner's
underwriting UI) can see exactly WHY a parcel scores as it does. The band
maps to the existing verdict vocabulary:

    0-19  clear      20-49  caution      50+  high_risk
    registry unreachable -> unavailable (score omitted)

Weights are deliberate: proven facts about the ground (registry mismatch,
overlap conflicts, uncompensated revocation) outweigh process gaps (consent
outstanding, young notice period).
"""

from __future__ import annotations

from typing import Any

WEIGHTS: dict[str, int] = {
    "owner_mismatch": 45,
    "geospatial_overlap": 40,
    "uncompensated_revocation": 40,
    "multiple_claimants": 35,
    "registry_not_found": 30,
    "objection_open": 25,
    "serial_seller": 25,
    "open_dispute": 15,
    "sla_breached": 10,
    "consent_incomplete": 15,
    "notice_period_active": 10,
    "title_chain": 0,  # penalty supplied by title_chain.analyze (0-60)
}

BANDS = ((50, "high_risk"), (20, "caution"), (0, "clear"))


def score_factors(factors: list[dict[str, Any]]) -> dict[str, Any]:
    """factors: [{code, penalty?, detail}] — penalty defaults to WEIGHTS[code]."""
    total = 0
    out = []
    for f in factors:
        penalty = f.get("penalty", WEIGHTS.get(f["code"], 10))
        total += penalty
        out.append({"code": f["code"], "penalty": penalty, "detail": f.get("detail", "")})
    total = min(total, 100)
    band = next(label for threshold, label in BANDS if total >= threshold)
    return {"risk_score": total, "band": band, "factors": out}
