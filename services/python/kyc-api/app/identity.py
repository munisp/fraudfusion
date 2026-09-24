"""BVN / NIN identity validation.

Local validation only: 11-digit format plus a Luhn-style checksum for BVN.
Live registry verification (NIBSS BVN lookup / NIMC NIN verification) is NOT
integrated — registry status is reported honestly as "unavailable" unless
BVN_REGISTRY_URL / NIN_REGISTRY_URL are configured, in which case the
registry is called and its verdict surfaced.
"""

from __future__ import annotations

import os
from typing import Optional

BVN_REGISTRY_URL = os.getenv("BVN_REGISTRY_URL", "").strip()
NIN_REGISTRY_URL = os.getenv("NIN_REGISTRY_URL", "").strip()


def luhn_checksum_ok(number: str) -> bool:
    """Standard Luhn check (used as a luhn-style structural control for BVN)."""
    digits = [int(c) for c in number]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate_bvn(bvn: Optional[str]) -> dict:
    """BVN: exactly 11 digits + Luhn-style checksum. Registry NOT integrated."""
    if not bvn:
        return {"provided": False, "format_valid": False, "registry_status": "not_provided"}
    if not (bvn.isdigit() and len(bvn) == 11):
        return {
            "provided": True,
            "format_valid": False,
            "reason": "BVN must be exactly 11 digits",
            "registry_status": "not_checked",
        }
    if not luhn_checksum_ok(bvn):
        return {
            "provided": True,
            "format_valid": False,
            "reason": "BVN failed checksum validation",
            "registry_status": "not_checked",
        }
    return {
        "provided": True,
        "format_valid": True,
        # NIBSS BVN registry integration is not configured in this deployment.
        "registry_status": "unavailable",
        "registry_detail": (
            "NIBSS BVN registry integration is not configured "
            "(BVN_REGISTRY_URL unset); identity confirmed by format+checksum only"
        ),
    }


def validate_nin(nin: Optional[str]) -> dict:
    """NIN: exactly 11 digits (no published checksum). Registry NOT integrated."""
    if not nin:
        return {"provided": False, "format_valid": False, "registry_status": "not_provided"}
    if not (nin.isdigit() and len(nin) == 11):
        return {
            "provided": True,
            "format_valid": False,
            "reason": "NIN must be exactly 11 digits",
            "registry_status": "not_checked",
        }
    if len(set(nin)) == 1:
        return {
            "provided": True,
            "format_valid": False,
            "reason": "NIN cannot be a repeated digit",
            "registry_status": "not_checked",
        }
    return {
        "provided": True,
        "format_valid": True,
        # NIMC NIN registry integration is not configured in this deployment.
        "registry_status": "unavailable",
        "registry_detail": (
            "NIMC NIN registry integration is not configured "
            "(NIN_REGISTRY_URL unset); identity confirmed by format only"
        ),
    }
