"""Machine-checkable checksums and date logic (Round 14).

Regex says a number LOOKS right; a checksum says it was COMPUTED right.
Forgers type plausible numbers — they rarely recompute check digits.

  * ICAO 9303 MRZ check digits (Nigerian e-passports): weights 7-3-1 over
    A=10..Z=35, 0-9 face value, '<' filler = 0.
  * Date parsing across Nigerian print formats + impossibility checks.

Pure functions; never raise.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Optional

_MRZ_WEIGHTS = (7, 3, 1)
_MRZ_VALUES = {c: i for i, c in enumerate("0123456789")}
_MRZ_VALUES.update({chr(ord("A") + i): 10 + i for i in range(26)})
_MRZ_VALUES["<"] = 0


def mrz_check_digit(data: str) -> int:
    """ICAO 9303 check digit for one MRZ data element."""
    total = sum(_MRZ_VALUES.get(ch.upper(), 0) * _MRZ_WEIGHTS[i % 3]
                for i, ch in enumerate(data))
    return total % 10


def validate_mrz_field(data: str, check: str) -> bool:
    """data: the protected field; check: single check digit."""
    check = check.strip()
    if not (check.isdigit() and len(check) == 1):
        return False
    return mrz_check_digit(data) == int(check)


def validate_passport_mrz(line1: str, line2: str) -> dict[str, Any]:
    """TD3 passport MRZ (2 x 44 chars). Validates all four check digits and
    the composite. Returns per-digit results — never raises on bad input."""
    line1, line2 = line1.strip().upper(), line2.strip().upper()
    if len(line1) != 44 or len(line2) != 44:
        return {"format_ok": False, "all_valid": False,
                "detail": "TD3 MRZ lines must be exactly 44 characters"}
    doc_number, doc_check = line2[0:9], line2[9]
    dob, dob_check = line2[13:19], line2[19]
    expiry, exp_check = line2[21:27], line2[27]
    personal, pers_check = line2[28:42], line2[42]
    composite_data = line2[0:10] + line2[13:20] + line2[21:43]
    results = {
        "document_number": validate_mrz_field(doc_number, doc_check),
        "date_of_birth": validate_mrz_field(dob, dob_check),
        "expiry": validate_mrz_field(expiry, exp_check),
        "personal_number": (validate_mrz_field(personal, pers_check)
                            if pers_check.isdigit() else pers_check == "<"),
        "composite": validate_mrz_field(composite_data, line2[43]),
    }
    return {"format_ok": True, "checks": results,
            "all_valid": all(results.values()),
            "detail": "ICAO 9303 check digits"}


_DATE_FORMATS = ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d %B %Y", "%d %b %Y",
                 "%y%m%d")


def parse_date(value: Any) -> Optional[date]:
    if not value:
        return None
    s = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    m = re.match(r"^(\d{2})(\d{2})(\d{2})$", s)  # MRZ YYMMDD
    if m:
        yy, mm, dd = map(int, m.groups())
        year = 2000 + yy if yy <= 49 else 1900 + yy
        try:
            return date(year, mm, dd)
        except ValueError:
            return None
    return None


def date_logic_issues(fields: dict[str, Any],
                      today: Optional[date] = None) -> list[dict[str, str]]:
    """Cross-date impossibilities a forger editing one field rarely fixes."""
    today = today or date.today()
    issues: list[dict[str, str]] = []
    dob = parse_date(fields.get("date_of_birth"))
    issue = parse_date(fields.get("issue_date"))
    expiry = parse_date(fields.get("expiry_date"))

    if dob:
        age_days = (today - dob).days
        if dob > today:
            issues.append({"code": "dob_in_future",
                           "detail": "date of birth is in the future"})
        elif age_days > 130 * 365:
            issues.append({"code": "dob_implausible",
                           "detail": f"age {age_days // 365} exceeds human lifespan"})
    if issue and issue > today:
        issues.append({"code": "issue_in_future",
                       "detail": "issue date is in the future"})
    if issue and expiry and expiry <= issue:
        issues.append({"code": "expiry_before_issue",
                       "detail": "expiry date is not after the issue date"})
    if dob and issue:
        age_at_issue = (issue - dob).days / 365.25
        if age_at_issue < 0:
            issues.append({"code": "issued_before_birth",
                           "detail": "document issued before the holder was born"})
        elif age_at_issue < 16 and fields.get("_doc_kind") == "adult_id":
            issues.append({"code": "issued_to_minor",
                           "detail": f"adult identity document issued at age "
                                     f"{int(age_at_issue)}"})
    return issues
