"""Cross-field semantic consistency (Round 14).

A forger editing ONE field of a genuine document (a date, a name, a number)
almost never updates every dependent field. These checks look for the seams:

  * name consistency — the surname on the visual zone should recur in any
    secondary name field; complete disjointness suggests a patched field.
  * MRZ vs visual zone — passport number / DOB / expiry printed on the visual
    zone must equal the MRZ-encoded values (a patched visual field leaves
    the MRZ betraying it).
  * date logic — delegated to checksums.date_logic_issues.

Pure functions over extracted-field dicts; never raise.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from checksums import parse_date, validate_passport_mrz

_TOK = re.compile(r"[A-Za-z]{2,}")


def _tokens(value: Optional[str]) -> set[str]:
    return {t.lower() for t in _TOK.findall(value or "")}


def name_consistency(fields: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Compare `name` against any second name-ish field present."""
    primary = _tokens(fields.get("name"))
    if not primary:
        return None
    for other_key in ("holder_name", "surname", "father_name", "next_of_kin"):
        other = _tokens(fields.get(other_key))
        if not other:
            continue
        if other_key == "surname" and not (other & primary):
            return {"consistent": False,
                    "detail": f"surname '{fields[other_key]}' does not appear "
                              f"in the printed name — patched field suspected"}
        if other_key != "surname" and not (other & primary):
            return {"consistent": False,
                    "detail": f"'{other_key}' shares no token with the printed "
                              f"name — fields come from different identities"}
    return {"consistent": True}


def mrz_visual_consistency(fields: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Passport: MRZ-encoded values must match the visual-zone fields."""
    mrz1, mrz2 = fields.get("mrz_line1"), fields.get("mrz_line2")
    if not (mrz1 and mrz2):
        return None
    result = validate_passport_mrz(mrz1, mrz2)
    if not result.get("format_ok"):
        return {"consistent": False, "detail": "MRZ format invalid"}
    mismatches: list[str] = []
    mrz2 = mrz2.strip().upper()
    doc_no_mrz = mrz2[0:9].replace("<", "")
    doc_no_visual = re.sub(r"\s", "", str(fields.get("passport_number", ""))).upper()
    if doc_no_visual and doc_no_mrz and doc_no_visual != doc_no_mrz:
        mismatches.append("passport number: visual zone != MRZ")
    dob_mrz = parse_date(mrz2[13:19])
    dob_visual = parse_date(fields.get("date_of_birth"))
    if dob_mrz and dob_visual and dob_mrz != dob_visual:
        mismatches.append("date of birth: visual zone != MRZ")
    exp_mrz = parse_date(mrz2[21:27])
    exp_visual = parse_date(fields.get("expiry_date"))
    if exp_mrz and exp_visual and exp_mrz != exp_visual:
        mismatches.append("expiry date: visual zone != MRZ")
    return {"consistent": not mismatches,
            "mismatches": mismatches,
            "mrz_checks": result.get("checks"),
            "mrz_all_valid": result.get("all_valid")}


def run(fields: dict[str, Any], doc_type: Optional[str] = None) -> dict[str, Any]:
    """All semantic-consistency checks; returns a list of issue dicts."""
    issues: list[dict[str, str]] = []
    name = name_consistency(fields)
    if name and not name["consistent"]:
        issues.append({"code": "name_inconsistency", "detail": name["detail"]})
    mrz = mrz_visual_consistency(fields)
    if mrz and not mrz["consistent"]:
        for m in mrz.get("mismatches", ["MRZ invalid"]):
            issues.append({"code": "mrz_visual_mismatch", "detail": m})
    return {"issues": issues,
            "checked": {"name": name is not None, "mrz": mrz is not None},
            "mrz": mrz}
