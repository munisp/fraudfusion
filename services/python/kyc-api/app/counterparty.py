"""Counterparty verification-rigor registry.

Accounts opened at institutions that skip CBN biometric BVN verification are
higher risk: transactions with counterparties at such institutions inherit an
onboarding-quality gap. This module is the registry + lookup + risk-flag
wiring; the scoring contribution itself stays in the existing rules-based
risk endpoints in app/main.py.

Rigor levels (documented, coarse on purpose):
  * 'cbn_full_biometric' — institution performs full CBN biometric BVN
    verification at account opening;
  * 'cbn_basic' — CBN KYC performed but without full biometric verification;
  * 'unverified' — institution is known NOT to perform CBN biometric BVN
    verification;
  * 'unknown' — no registry entry; FAIL-CLOSED default. An unknown
    institution is never silently treated as strongly verified.

Risk contribution (applied in app/main.py risk rules):
  * 'unverified' -> +0.15 with flag `counterparty_verification_gap`
  * 'unknown'    -> +0.10 with flag `counterparty_verification_gap`
  * others       -> no contribution
"""

from __future__ import annotations

from typing import Any, Optional

RIGOR_LEVELS = ("cbn_full_biometric", "cbn_basic", "unverified", "unknown")

# Documented rule contributions for the risk endpoints.
RISK_CONTRIB_BY_RIGOR = {"unverified": 0.15, "unknown": 0.10}
GAP_FLAG = "counterparty_verification_gap"


def lookup_rigor(db, institution_code: Optional[str]) -> dict[str, Any]:
    """Look up a counterparty institution's verification rigor.

    Fail-closed: an absent/unknown institution resolves to rigor 'unknown'
    with source 'default_unknown' and an explicit reason — never silently
    treated as strong."""
    if not institution_code:
        return {
            "institution_code": None,
            "rigor_level": "unknown",
            "source": "not_provided",
            "reason": "no counterparty institution supplied",
        }
    code = institution_code.strip()
    row = db.query_one(
        "SELECT institution_code, institution_name, rigor_level, source_note, updated_at"
        " FROM counterparty_rigor_registry WHERE institution_code = :c",
        {"c": code},
    )
    if not row:
        return {
            "institution_code": code,
            "rigor_level": "unknown",
            "source": "default_unknown",
            "reason": "institution not present in counterparty rigor registry; "
                      "failing closed to 'unknown'",
        }
    return {
        "institution_code": row["institution_code"],
        "institution_name": row["institution_name"],
        "rigor_level": row["rigor_level"],
        "source": "registry",
        "source_note": row.get("source_note") or "",
        "updated_at": str(row.get("updated_at") or ""),
    }


def risk_enrichment(rigor_result: dict[str, Any]) -> dict[str, Any]:
    """Translate a rigor lookup into the documented risk contribution.

    Returns {flag: bool, flag_name, contribution, factor} — factor is the
    human-readable rules entry appended to the risk endpoint's factor list.
    """
    rigor = rigor_result.get("rigor_level", "unknown")
    contribution = RISK_CONTRIB_BY_RIGOR.get(rigor, 0.0)
    flagged = contribution > 0
    factor = None
    if flagged:
        factor = (
            f"{GAP_FLAG}: counterparty institution "
            f"{rigor_result.get('institution_code')} verification rigor is "
            f"'{rigor}' (+{contribution:.2f})"
        )
    return {
        "flag": flagged,
        "flag_name": GAP_FLAG if flagged else None,
        "contribution": contribution,
        "factor": factor,
    }
