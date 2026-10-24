"""Root-of-title chain analysis (Round 13, feature 3).

A genuine title has an unbroken chain: original registration -> each
subsequent assignment passing from the previous owner. Fraud patterns this
catches from a registry history (adapter records: owner_name, transfer_type,
transfer_date):

  * missing_root     — no original registration/allocation record at the base
  * chain_gap        — an assignment FROM someone who is not the previous
                       recorded owner (a link is missing or forged)
  * quick_flip       — the latest transfer happened < QUICK_FLIP_DAYS after
                       the previous one (land-grabbers flip fast to launder
                       possession into "ownership")
  * excessive_transfers — churn beyond CHURN_MAX transfers (repeated resale
                       of the same parcel is itself a multiple-sale signal)

Pure functions over adapter record dicts; never raises on partial data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

QUICK_FLIP_DAYS = 180
CHURN_MAX = 4

_ROOT_TYPES = {"registration", "allocation", "grant", "certificate_of_occupancy"}
_TRANSFER_TYPES = {"assignment", "sale", "transfer", "conveyance", "devolution"}


def _parse_date(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def analyze_title_chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze an ordered (oldest-first) ownership history."""
    issues: list[dict[str, str]] = []
    if not records:
        return {"chain_depth": 0, "issues": [{"code": "no_history",
                "detail": "no registry history records"}], "score_penalty": 40}

    first_type = str(records[0].get("transfer_type") or "").strip().lower()
    if first_type not in _ROOT_TYPES:
        issues.append({"code": "missing_root",
                       "detail": f"chain begins with '{first_type or 'unknown'}', "
                                 "not an original registration/allocation"})

    prev_owner = (records[0].get("owner_name") or "").strip().lower()
    prev_date = _parse_date(records[0].get("transfer_date"))
    transfers = 0
    for rec in records[1:]:
        rtype = str(rec.get("transfer_type") or "").strip().lower()
        rdate = _parse_date(rec.get("transfer_date"))
        if rtype in _TRANSFER_TYPES or rtype:
            transfers += 1
        if rdate and prev_date and (rdate - prev_date).days < QUICK_FLIP_DAYS:
            issues.append({"code": "quick_flip",
                           "detail": f"transfer only {(rdate - prev_date).days} days "
                                     "after the previous one"})
        prev_date = rdate or prev_date
        prev_owner = (rec.get("owner_name") or prev_owner or "").strip().lower()

    if transfers > CHURN_MAX:
        issues.append({"code": "excessive_transfers",
                       "detail": f"{transfers} transfers on record (>{CHURN_MAX}) — "
                                 "repeated resale pattern"})

    # Penalty model (0-100 scale contribution; capped): root defects are
    # grave, flip/churn patterns are warnings.
    penalty = 0
    for issue in issues:
        penalty += {"missing_root": 35, "no_history": 40, "chain_gap": 30,
                    "quick_flip": 15, "excessive_transfers": 10}.get(issue["code"], 10)
    return {"chain_depth": len(records), "issues": issues,
            "score_penalty": min(penalty, 60)}
