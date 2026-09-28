"""Nigerian identity document registry.

Per document type this module declares:
  * the fields the extraction layer is expected to produce,
  * regex validators for machine-checkable fields,
  * layout hints passed to the vision-language model so its structured
    extraction prompt can be grounded in the real document layout.

Validator regexes are deliberately documented approximations of the official
formats (NIMC / FRSC / INEC / NIS do not publish formal grammars); they are
tuned against the publicly documented number shapes and are conservative —
a field that fails validation routes the document to manual review, it never
auto-rejects on format alone.
"""

from __future__ import annotations

import re
from typing import Any

# --- field validators --------------------------------------------------------

# NIN: exactly 11 digits (NIMC).
NIN_RE = re.compile(r"^\d{11}$")
# Nigerian passport number: one letter + eight digits (NIS e-passport).
PASSPORT_RE = re.compile(r"^[A-Z]\d{8}$")
# FRSC driver's licence number: 2-3 letters followed by 6-12 alphanumerics
# (formats have changed across issues; this accepts both legacy and current).
DRIVERS_LICENSE_RE = re.compile(r"^[A-Z]{2,3}[A-Z0-9]{6,12}$")
# INEC permanent voter's card: 19-char alphanumeric VIN, or the legacy
# state/lga/registration-area numeric form (e.g. 12/34/5678).
VOTERS_CARD_RES = (
    re.compile(r"^[A-Z0-9]{19}$"),
    re.compile(r"^\d{1,3}/\d{1,3}/\d{1,5}$"),
)
# Legacy national ID card numbers vary by issue; accept 8-20 alphanumerics.
NATIONAL_ID_RE = re.compile(r"^[A-Z0-9]{8,20}$")

# Dates as printed on Nigerian documents: DD/MM/YYYY, DD-MM-YYYY, DD MMM YYYY,
# or ISO YYYY-MM-DD (MRZ-derived).
DATE_RE = re.compile(
    r"^("
    r"\d{4}-\d{2}-\d{2}"
    r"|\d{2}[/-]\d{2}[/-]\d{4}"
    r"|\d{2}\s+[A-Za-z]{3,9}\s+\d{4}"
    r")$"
)

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z' ,.-]{1,119}$")


def _multi_regex_ok(value: str, regexes) -> bool:
    return any(r.match(value) for r in regexes)


def validate_date(value: str) -> bool:
    return bool(DATE_RE.match(value.strip()))


def validate_name(value: str) -> bool:
    return bool(NAME_RE.match(value.strip()))


DOC_TYPES: dict[str, dict[str, Any]] = {
    "nin_slip": {
        "display": "NIMC NIN slip",
        "required_fields": ["name", "nin", "date_of_birth"],
        "optional_fields": ["gender", "phone", "address", "issue_date"],
        "validators": {
            "nin": lambda v: bool(NIN_RE.match(re.sub(r"\s", "", v))),
            "date_of_birth": validate_date,
            "name": validate_name,
        },
        "layout_hints": (
            "NIMC slip: the 11-digit NIN is printed prominently top-right or "
            "below the portrait; name is 'SURNAME, First Middle'; date of "
            "birth appears as DD/MM/YYYY near the NIN."
        ),
    },
    "national_id": {
        "display": "National ID card (NIMC)",
        "required_fields": ["name", "nin", "date_of_birth"],
        "optional_fields": ["gender", "expiry_date", "card_number"],
        "validators": {
            "nin": lambda v: bool(NIN_RE.match(re.sub(r"\s", "", v))),
            "card_number": lambda v: bool(NATIONAL_ID_RE.match(v.strip().upper())),
            "date_of_birth": validate_date,
            "expiry_date": validate_date,
            "name": validate_name,
        },
        "layout_hints": (
            "NIMC national e-ID card: name top-left, 11-digit NIN beside the "
            "portrait, expiry on the front bottom-right."
        ),
    },
    "drivers_license": {
        "display": "FRSC driver's licence",
        "required_fields": ["name", "license_number", "date_of_birth", "expiry_date"],
        "optional_fields": ["class_of_license", "issue_date", "state"],
        "validators": {
            "license_number": lambda v: bool(
                DRIVERS_LICENSE_RE.match(re.sub(r"[\s-]", "", v).upper())),
            "date_of_birth": validate_date,
            "expiry_date": validate_date,
            "issue_date": validate_date,
            "name": validate_name,
        },
        "layout_hints": (
            "FRSC licence: licence number (letters then digits) top-left under "
            "'DRIVER'S LICENCE', class of licence and expiry bottom row."
        ),
    },
    "voters_card": {
        "display": "INEC permanent voter's card",
        "required_fields": ["name", "vin", "date_of_birth"],
        "optional_fields": ["polling_unit", "state", "lga", "occupation"],
        "validators": {
            "vin": lambda v: _multi_regex_ok(re.sub(r"\s", "", v).upper(),
                                             VOTERS_CARD_RES),
            "date_of_birth": validate_date,
            "name": validate_name,
        },
        "layout_hints": (
            "INEC PVC: VIN (19 characters, may be grouped) printed vertically "
            "or bottom-left; name and polling unit centre; date of birth "
            "sometimes year-only — record it as printed."
        ),
    },
    "intl_passport": {
        "display": "Nigerian international passport",
        "required_fields": ["name", "passport_number", "date_of_birth", "expiry_date"],
        "optional_fields": ["issue_date", "issuing_authority", "mrz"],
        "validators": {
            "passport_number": lambda v: bool(
                PASSPORT_RE.match(v.strip().upper())),
            "date_of_birth": validate_date,
            "expiry_date": validate_date,
            "issue_date": validate_date,
            "name": validate_name,
        },
        "layout_hints": (
            "NIS e-passport data page: passport number (1 letter + 8 digits) "
            "top-right, name/DOB/expiry in the visual zone, two-line MRZ at "
            "the bottom — transcribe MRZ verbatim if legible."
        ),
    },
}

# Frontend/legacy aliases accepted by kyc-api, mapped to the registry keys.
DOC_TYPE_ALIASES = {
    "international_passport": "intl_passport",
    "passport": "intl_passport",
    "nin": "nin_slip",
    "driver_license": "drivers_license",
    "drivers_licence": "drivers_license",
    "voter_card": "voters_card",
    "voters_card": "voters_card",
    "national_id_card": "national_id",
}


def canonical_doc_type(doc_type: str) -> str | None:
    """Map an incoming document_type string to a registry key, or None."""
    key = doc_type.strip().lower()
    if key in DOC_TYPES:
        return key
    return DOC_TYPE_ALIASES.get(key)


def get_spec(doc_type: str) -> dict[str, Any] | None:
    key = canonical_doc_type(doc_type)
    return DOC_TYPES[key] if key else None


def extraction_schema(doc_type: str) -> dict[str, str] | None:
    """JSON-schema-ish {field: description} for the VLM extraction prompt."""
    spec = get_spec(doc_type)
    if not spec:
        return None
    descriptions = {
        "name": "full name exactly as printed",
        "nin": "11-digit National Identification Number",
        "date_of_birth": "date of birth as printed (DD/MM/YYYY or DD MMM YYYY)",
        "expiry_date": "document expiry date as printed",
        "issue_date": "document issue date as printed",
        "license_number": "driver's licence number",
        "vin": "voter identification number",
        "card_number": "card serial number",
        "passport_number": "passport number (1 letter + 8 digits)",
        "gender": "gender as printed (M/F)",
        "phone": "phone number if printed",
        "address": "address if printed",
        "class_of_license": "licence class (e.g. B)",
        "state": "state of issue/residence",
        "lga": "local government area",
        "polling_unit": "polling unit code",
        "occupation": "occupation if printed",
        "issuing_authority": "issuing authority",
        "mrz": "machine-readable zone lines, verbatim",
    }
    fields = spec["required_fields"] + spec["optional_fields"]
    return {f: descriptions.get(f, f) for f in fields}


def validate_fields(doc_type: str, fields: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Validate extracted fields against the registry validators.

    Returns {field: {"value": v, "valid": bool, "checked": bool}}. Fields
    without a validator are reported checked=False (never silently trusted).
    """
    spec = get_spec(doc_type)
    out: dict[str, dict[str, Any]] = {}
    for field, value in fields.items():
        validator = (spec or {}).get("validators", {}).get(field)
        if validator is None:
            out[field] = {"value": value, "valid": None, "checked": False}
            continue
        try:
            ok = bool(validator(str(value)))
        except Exception:
            ok = False
        out[field] = {"value": value, "valid": ok, "checked": True}
    return out


def missing_required(doc_type: str, fields: dict[str, str]) -> list[str]:
    spec = get_spec(doc_type)
    if not spec:
        return []
    return [f for f in spec["required_fields"] if not fields.get(f)]
