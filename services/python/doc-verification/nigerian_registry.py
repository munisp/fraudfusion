"""Comprehensive Nigerian government document registry (Round 14).

The machine-checkable knowledge base of federal and state government-issued
documents — the "training data" of the document intelligence engine. Every
entry declares, per document class:

  * issuing_authority   — the ONLY body that can lawfully issue it
  * level               — federal | state | federal_state (issued federally,
                          administered by states)
  * states              — for state-level docs: which states issue variants
  * required/optional fields + per-field validators
  * checksum            — machine-checkable integrity ("mrz_td3", None)
  * security_features   — physical/digital features a genuine specimen
                          carries (hologram, QR, guilloche, microtext...)
  * markers             — text strings that MUST appear somewhere on a
                          genuine specimen (OCR/VLM searchable)
  * verification        — the official verification channel (informational)
  * aliases             — names integrators actually use

Honesty note: validators are conservative public-format approximations (the
issuing authorities publish no formal grammars). A spec failure routes to
manual review; it never auto-rejects on format alone.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from checksums import validate_passport_mrz
from nigerian_docs import validate_date, validate_name

NIGERIAN_STATES = [
    "abia", "adamawa", "akwa_ibom", "anambra", "bauchi", "bayelsa", "benue",
    "borno", "cross_river", "delta", "ebonyi", "edo", "ekiti", "enugu",
    "gombe", "imo", "jigawa", "kaduna", "kano", "katsina", "kebbi", "kogi",
    "kwara", "lagos", "nasarawa", "niger", "ogun", "ondo", "osun", "oyo",
    "plateau", "rivers", "sokoto", "taraba", "yobe", "zamfara", "fct",
]

_DIGITS = lambda n: re.compile(rf"^\d{{{n}}}$")  # noqa: E731


def _re(pattern: str):
    rx = re.compile(pattern)
    return lambda v: bool(rx.match(str(v).strip()))


# ---------------------------------------------------------------------------
# Federal identity documents
# ---------------------------------------------------------------------------

FEDERAL_IDENTITY: dict[str, dict[str, Any]] = {
    "nin_slip": {
        "display": "NIN slip (National Identity Number)",
        "issuing_authority": "National Identity Management Commission (NIMC)",
        "level": "federal",
        "required_fields": ["name", "nin", "date_of_birth"],
        "optional_fields": ["gender", "phone", "address", "issue_date"],
        "validators": {"nin": _re(r"^\d{11}$"),
                       "date_of_birth": validate_date, "name": validate_name},
        "checksum": None,
        "security_features": ["qr_code", "nin_barcode", "nimc_logo",
                              "tracking_id", "digital_signature"],
        "markers": ["national identity", "nimc"],
        "verification": "NIMC verification service / NINAuth",
        "aliases": ["nin", "nin_slip", "national_identity_number_slip"],
    },
    "national_id_card": {
        "display": "National e-ID card",
        "issuing_authority": "National Identity Management Commission (NIMC)",
        "level": "federal",
        "required_fields": ["name", "nin", "date_of_birth"],
        "optional_fields": ["gender", "card_number", "expiry_date", "address"],
        "validators": {"nin": _re(r"^\d{11}$"), "date_of_birth": validate_date,
                       "name": validate_name},
        "checksum": None,
        "security_features": ["chip", "hologram", "guilloche", "microtext",
                              "uv_print", "mrz_like_zone", "qr_code"],
        "markers": ["federal republic of nigeria", "national identity card"],
        "verification": "NIMC card verification",
        "aliases": ["national_id", "eid_card", "nimc_card"],
    },
    "passport_standard": {
        "display": "Nigerian e-passport (standard, 32/64-page)",
        "issuing_authority": "Nigeria Immigration Service (NIS)",
        "level": "federal",
        "required_fields": ["name", "passport_number", "date_of_birth",
                            "expiry_date", "mrz_line1", "mrz_line2"],
        "optional_fields": ["issue_date", "issuing_office", "gender",
                            "place_of_birth", "nationality"],
        "validators": {"passport_number": _re(r"^[A-Z]\d{8}$"),
                       "date_of_birth": validate_date,
                       "expiry_date": validate_date, "name": validate_name},
        "checksum": "mrz_td3",
        "security_features": ["mrz", "chip_epassport", "hologram", "uv_print",
                              "guilloche", "watermark", "laser_engraving",
                              "ghost_image"],
        "markers": ["federal republic of nigeria", "passport"],
        "verification": "NIS e-passport verification portal",
        "aliases": ["passport", "e_passport", "international_passport"],
    },
    "passport_official": {
        "display": "Nigerian official passport",
        "issuing_authority": "Nigeria Immigration Service (NIS)",
        "level": "federal",
        "required_fields": ["name", "passport_number", "date_of_birth",
                            "expiry_date", "mrz_line1", "mrz_line2"],
        "optional_fields": ["issue_date", "rank_or_office"],
        "validators": {"passport_number": _re(r"^[A-Z]\d{8}$"),
                       "date_of_birth": validate_date,
                       "expiry_date": validate_date, "name": validate_name},
        "checksum": "mrz_td3",
        "security_features": ["mrz", "chip_epassport", "hologram", "uv_print"],
        "markers": ["official passport", "federal republic of nigeria"],
        "verification": "NIS verification",
        "aliases": ["official_passport"],
    },
    "passport_diplomatic": {
        "display": "Nigerian diplomatic passport",
        "issuing_authority": "Nigeria Immigration Service (NIS)",
        "level": "federal",
        "required_fields": ["name", "passport_number", "date_of_birth",
                            "expiry_date", "mrz_line1", "mrz_line2"],
        "optional_fields": ["issue_date", "rank_or_office"],
        "validators": {"passport_number": _re(r"^[A-Z]\d{8}$"),
                       "date_of_birth": validate_date,
                       "expiry_date": validate_date, "name": validate_name},
        "checksum": "mrz_td3",
        "security_features": ["mrz", "chip_epassport", "hologram", "uv_print"],
        "markers": ["diplomatic passport", "federal republic of nigeria"],
        "verification": "NIS verification",
        "aliases": ["diplomatic_passport"],
    },
    "drivers_license": {
        "display": "Driver's licence",
        "issuing_authority": "Federal Road Safety Corps (FRSC)",
        "level": "federal_state",
        "required_fields": ["name", "license_number", "date_of_birth",
                            "expiry_date"],
        "optional_fields": ["class_of_vehicle", "issue_date", "state_of_issue",
                            "blood_group", "height"],
        "validators": {
            "license_number": _re(r"^[A-Z]{2,3}[A-Z0-9]{6,12}$"),
            "date_of_birth": validate_date, "expiry_date": validate_date,
            "name": validate_name},
        "checksum": None,
        "security_features": ["hologram", "uv_print", "microtext",
                              "barcode", "guilloche", "ghost_image"],
        "markers": ["federal road safety", "driver"],
        "verification": "FRSC national driver's licence portal (ndl.frsc.gov.ng)",
        "aliases": ["drivers_license", "driving_licence", "frsc_license"],
    },
    "voters_card": {
        "display": "Permanent Voter's Card (PVC)",
        "issuing_authority": "Independent National Electoral Commission (INEC)",
        "level": "federal",
        "required_fields": ["name", "vin"],
        "optional_fields": ["date_of_birth", "state", "lga", "ward",
                            "polling_unit"],
        "validators": {"vin": lambda v: bool(re.match(r"^[A-Z0-9]{19}$", v))
                       or bool(re.match(r"^\d{1,3}/\d{1,3}/\d{1,5}$", v)),
                       "name": validate_name},
        "checksum": None,
        "security_features": ["hologram", "qr_code", "microtext", "uv_print"],
        "markers": ["inec", "voter"],
        "verification": "INEC Voter Verification System / BVAS lookup",
        "aliases": ["voters_card", "pvc", "inec_card"],
    },
    "birth_certificate": {
        "display": "National birth certificate / attestation of birth",
        "issuing_authority": "National Population Commission (NPC)",
        "level": "federal_state",
        "required_fields": ["name", "date_of_birth", "place_of_birth",
                            "registration_number"],
        "optional_fields": ["father_name", "mother_name", "sex",
                            "date_of_registration", "entry_number"],
        "validators": {"name": validate_name, "date_of_birth": validate_date,
                       "registration_number": _re(r"^[A-Z0-9/-]{6,25}$")},
        "checksum": None,
        "security_features": ["watermark", "embossed_seal", "serial_number",
                              "uv_print"],
        "markers": ["national population commission", "birth"],
        "verification": "NPC e-birth verification portal",
        "aliases": ["birth_certificate", "attestation_of_birth",
                    "declaration_of_age"],
    },
    "death_certificate": {
        "display": "Death certificate",
        "issuing_authority": "National Population Commission (NPC)",
        "level": "federal_state",
        "required_fields": ["name", "date_of_death", "place_of_death",
                            "registration_number"],
        "optional_fields": ["cause_of_death", "informant", "age_at_death"],
        "validators": {"name": validate_name, "date_of_death": validate_date},
        "checksum": None,
        "security_features": ["watermark", "embossed_seal", "serial_number"],
        "markers": ["national population commission", "death"],
        "verification": "NPC verification",
        "aliases": ["death_certificate"],
    },
    "marriage_certificate": {
        "display": "Statutory marriage certificate (Form E)",
        "issuing_authority": "Federal Marriage Registry (Ministry of Interior) "
                             "/ Local Government marriage registries",
        "level": "federal_state",
        "required_fields": ["groom_name", "bride_name", "marriage_date",
                            "registry_name"],
        "optional_fields": ["certificate_number", "witness_1", "witness_2",
                            "officiating_registrar"],
        "validators": {"groom_name": validate_name, "bride_name": validate_name,
                       "marriage_date": validate_date},
        "checksum": None,
        "security_features": ["embossed_seal", "watermark", "serial_number",
                              "security_paper"],
        "markers": ["marriage", "registry"],
        "verification": "issuing marriage registry (manual)",
        "aliases": ["marriage_certificate", "form_e"],
    },
    "nysc_certificate": {
        "display": "NYSC discharge certificate",
        "issuing_authority": "National Youth Service Corps (NYSC)",
        "level": "federal",
        "required_fields": ["name", "certificate_number", "passing_out_date"],
        "optional_fields": ["state_of_service", "course", "institution",
                            "call_up_number"],
        "validators": {"certificate_number": _re(r"^[A-Z0-9/-]{8,25}$"),
                       "name": validate_name,
                       "passing_out_date": validate_date},
        "checksum": None,
        "security_features": ["watermark", "guilloche", "serial_number",
                              "security_paper", "signature_panel"],
        "markers": ["national youth service corps"],
        "verification": "NYSC certificate verification portal",
        "aliases": ["nysc", "nysc_certificate", "nysc_discharge"],
    },
    "nysc_exemption": {
        "display": "NYSC exemption / exclusion certificate",
        "issuing_authority": "National Youth Service Corps (NYSC)",
        "level": "federal",
        "required_fields": ["name", "certificate_number"],
        "optional_fields": ["issue_date", "reason"],
        "validators": {"certificate_number": _re(r"^[A-Z0-9/-]{8,25}$"),
                       "name": validate_name},
        "checksum": None,
        "security_features": ["watermark", "guilloche", "serial_number"],
        "markers": ["national youth service corps", "exempt"],
        "verification": "NYSC verification portal",
        "aliases": ["nysc_exemption", "nysc_exclusion"],
    },
    "police_character_certificate": {
        "display": "Police character (clearance) certificate",
        "issuing_authority": "Nigeria Police Force (Central Criminal Registry)",
        "level": "federal",
        "required_fields": ["name", "certificate_number", "issue_date"],
        "optional_fields": ["passport_number", "destination_country",
                            "fingerprint_reference"],
        "validators": {"name": validate_name, "issue_date": validate_date},
        "checksum": None,
        "security_features": ["watermark", "seal", "serial_number",
                              "qr_code"],
        "markers": ["nigeria police", "character"],
        "verification": "NPF POSSAP portal",
        "aliases": ["police_clearance", "police_character_certificate"],
    },
}

# ---------------------------------------------------------------------------
# Federal corporate / commercial documents
# ---------------------------------------------------------------------------

FEDERAL_CORPORATE: dict[str, dict[str, Any]] = {
    "cac_certificate": {
        "display": "CAC certificate of incorporation",
        "issuing_authority": "Corporate Affairs Commission (CAC)",
        "level": "federal",
        "required_fields": ["company_name", "rc_number", "incorporation_date"],
        "optional_fields": ["company_type", "registered_address", "share_capital"],
        "validators": {"rc_number": _re(r"^(RC|BN|IT|LP|LLP)?\d{4,8}$"),
                       "incorporation_date": validate_date},
        "checksum": None,
        "security_features": ["qr_code", "watermark", "embossed_seal",
                              "security_paper", "serial_number"],
        "markers": ["corporate affairs commission"],
        "verification": "CAC public search portal",
        "aliases": ["cac", "certificate_of_incorporation", "rc_certificate"],
    },
    "cac_status_report": {
        "display": "CAC status report (form CAC 1.1)",
        "issuing_authority": "Corporate Affairs Commission (CAC)",
        "level": "federal",
        "required_fields": ["company_name", "rc_number"],
        "optional_fields": ["directors", "shareholders", "registered_address"],
        "validators": {"rc_number": _re(r"^(RC|BN|IT|LP|LLP)?\d{4,8}$")},
        "checksum": None,
        "security_features": ["qr_code", "watermark"],
        "markers": ["corporate affairs commission"],
        "verification": "CAC public search portal",
        "aliases": ["cac_status_report", "cac_1_1", "status_report"],
    },
    "firs_tax_clearance": {
        "display": "FIRS / state tax clearance certificate (TCC)",
        "issuing_authority": "Federal Inland Revenue Service (FIRS) or State "
                             "Internal Revenue Service",
        "level": "federal_state",
        "states": NIGERIAN_STATES,
        "required_fields": ["taxpayer_name", "tin", "year_of_assessment"],
        "optional_fields": ["tax_paid", "expiry_date", "issuing_office"],
        "validators": {"tin": _re(r"^\d{8}(-\d{4})?$"),
                       "year_of_assessment": _re(r"^(19|20)\d{2}$")},
        "checksum": None,
        "security_features": ["qr_code", "watermark", "serial_number"],
        "markers": ["tax clearance"],
        "verification": "FIRS TCC verification portal / state IRS portal",
        "aliases": ["tax_clearance", "tcc", "firs_tcc", "state_tcc"],
    },
    "scuml_certificate": {
        "display": "SCUML certificate (DNFBP registration)",
        "issuing_authority": "Special Control Unit against Money Laundering (EFCC)",
        "level": "federal",
        "required_fields": ["business_name", "rc_number", "certificate_number"],
        "optional_fields": ["issue_date", "business_type"],
        "validators": {"rc_number": _re(r"^(RC|BN|IT)?\d{4,8}$")},
        "checksum": None,
        "security_features": ["qr_code", "watermark", "serial_number"],
        "markers": ["scuml", "money laundering"],
        "verification": "SCUML verification desk",
        "aliases": ["scuml"],
    },
}

# ---------------------------------------------------------------------------
# Land / property documents (state-issued — 36 states + FCT variants)
# ---------------------------------------------------------------------------

LAND_DOCUMENTS: dict[str, dict[str, Any]] = {
    "certificate_of_occupancy": {
        "display": "Certificate of Occupancy (C of O)",
        "issuing_authority": "State Lands Bureau / Ministry of Lands "
                             "(Governor's signature)",
        "level": "state",
        "states": NIGERIAN_STATES,
        "required_fields": ["holder_name", "certificate_number",
                            "parcel_description", "term_years"],
        "optional_fields": ["registration_number", "plan_number",
                            "issue_date", "commencement_date", "lga",
                            "land_use"],
        "validators": {"holder_name": validate_name,
                       "certificate_number": _re(r"^[A-Z0-9/-]{6,30}$"),
                       "term_years": _re(r"^\d{1,3}$")},
        "checksum": None,
        "security_features": ["embossed_seal", "watermark", "security_paper",
                              "guilloche", "serial_number",
                              "governor_signature_panel"],
        "markers": ["certificate of occupancy", "land use act"],
        "verification": "state lands bureau registry search (CTC comparison)",
        "aliases": ["c_of_o", "certificate_of_occupancy", "cofo"],
    },
    "right_of_occupancy": {
        "display": "Right of Occupancy (R of O) — FCT/Northern-state variant",
        "issuing_authority": "FCT Administration (AGIS) / state ministry of lands",
        "level": "state",
        "states": ["fct", "kaduna", "kano", "katsina", "sokoto", "zamfara",
                   "kebbi", "borno", "yobe", "bauchi", "gombe", "jigawa",
                   "niger", "plateau", "nasarawa", "taraba", "adamawa"],
        "required_fields": ["holder_name", "file_number", "parcel_description"],
        "optional_fields": ["term_years", "plot_number", "layout", "district"],
        "validators": {"holder_name": validate_name,
                       "file_number": _re(r"^[A-Z0-9/-]{6,30}$")},
        "checksum": None,
        "security_features": ["embossed_seal", "watermark", "serial_number"],
        "markers": ["right of occupancy", "land use act"],
        "verification": "AGIS / state lands registry search",
        "aliases": ["r_of_o", "right_of_occupancy"],
    },
    "deed_of_assignment": {
        "display": "Registered deed of assignment",
        "issuing_authority": "State lands registry (registration); parties "
                             "(execution); Governor (consent, s.22 LUA)",
        "level": "state",
        "states": NIGERIAN_STATES,
        "required_fields": ["assignor_name", "assignee_name", "consideration",
                            "parcel_description"],
        "optional_fields": ["registration_number", "governors_consent_date",
                            "survey_plan_number", "witnesses"],
        "validators": {"assignor_name": validate_name,
                       "assignee_name": validate_name},
        "checksum": None,
        "security_features": ["registry_stamp", "embossed_seal",
                              "registration_endorsement"],
        "markers": ["deed of assignment", "assigns"],
        "verification": "state lands registry search + CTC comparison",
        "aliases": ["deed_of_assignment", "registered_deed", "deed"],
    },
    "deed_of_gift": {
        "display": "Registered deed of gift",
        "issuing_authority": "State lands registry",
        "level": "state",
        "states": NIGERIAN_STATES,
        "required_fields": ["donor_name", "donee_name", "parcel_description"],
        "optional_fields": ["registration_number", "governors_consent_date"],
        "validators": {"donor_name": validate_name, "donee_name": validate_name},
        "checksum": None,
        "security_features": ["registry_stamp", "embossed_seal"],
        "markers": ["deed of gift"],
        "verification": "state lands registry search",
        "aliases": ["deed_of_gift"],
    },
    "deed_of_mortgage": {
        "display": "Registered deed of legal mortgage",
        "issuing_authority": "State lands registry",
        "level": "state",
        "states": NIGERIAN_STATES,
        "required_fields": ["mortgagor_name", "mortgagee_name",
                            "parcel_description"],
        "optional_fields": ["registration_number", "loan_amount",
                            "governors_consent_date"],
        "validators": {"mortgagor_name": validate_name,
                       "mortgagee_name": validate_name},
        "checksum": None,
        "security_features": ["registry_stamp", "embossed_seal"],
        "markers": ["mortgage"],
        "verification": "state lands registry search",
        "aliases": ["deed_of_mortgage", "legal_mortgage"],
    },
    "survey_plan": {
        "display": "Registered survey plan (beacon plan)",
        "issuing_authority": "Surveyor-General of the state; drawn by a "
                             "SURCON-licensed surveyor",
        "level": "state",
        "states": NIGERIAN_STATES,
        "required_fields": ["plan_number", "surveyor_name", "parcel_description"],
        "optional_fields": ["beacons", "scale", "lga", "surcon_license",
                            "registration_number", "date_of_survey"],
        "validators": {"plan_number": _re(r"^[A-Z0-9/-]{5,30}$"),
                       "surveyor_name": validate_name,
                       "surcon_license": _re(r"^[A-Z0-9/]{4,25}$")},
        "checksum": None,
        "security_features": ["surveyor_seal", "surcon_stamp", "registry_stamp"],
        "markers": ["survey", "beacon"],
        "verification": "Office of the Surveyor-General (plan lodgment check)",
        "aliases": ["survey_plan", "survey", "red_copy_survey"],
    },
    "governors_consent": {
        "display": "Governor's consent (Land Use Act s.21-22)",
        "issuing_authority": "State Governor / Commissioner for Lands",
        "level": "state",
        "states": NIGERIAN_STATES,
        "required_fields": ["holder_name", "parcel_description",
                            "consent_date"],
        "optional_fields": ["instrument_reference", "registration_number"],
        "validators": {"holder_name": validate_name,
                       "consent_date": validate_date},
        "checksum": None,
        "security_features": ["embossed_seal", "signature_panel"],
        "markers": ["consent", "land use act"],
        "verification": "state lands registry",
        "aliases": ["governors_consent", "consent_letter"],
    },
    "registry_search_report": {
        "display": "Land registry search report / certified true copy (CTC)",
        "issuing_authority": "State lands registry",
        "level": "state",
        "states": NIGERIAN_STATES,
        "required_fields": ["search_date", "registry_name"],
        "optional_fields": ["registered_owner", "encumbrances",
                            "registration_number", "ctc_number"],
        "validators": {"search_date": validate_date},
        "checksum": None,
        "security_features": ["registry_stamp", "officer_signature",
                              "serial_number"],
        "markers": ["search", "registry"],
        "verification": "issuing registry",
        "aliases": ["search_report", "ctc", "certified_true_copy"],
    },
}

# ---------------------------------------------------------------------------
# State-issued identity / residency documents
# ---------------------------------------------------------------------------

STATE_IDENTITY: dict[str, dict[str, Any]] = {
    "state_residency_card": {
        "display": "State residency / citizens' card",
        "issuing_authority": "State residents registration agency "
                             "(e.g. LASSRA Lagos, KADSRAP Kaduna)",
        "level": "state",
        "states": ["lagos", "kaduna", "rivers", "oyo", "enugu", "anambra"],
        "required_fields": ["name", "card_number"],
        "optional_fields": ["address", "lga", "expiry_date"],
        "validators": {"name": validate_name,
                       "card_number": _re(r"^[A-Z0-9/-]{6,25}$")},
        "checksum": None,
        "security_features": ["hologram", "qr_code", "uv_print"],
        "markers": ["residency"],
        "verification": "state registration agency portal",
        "aliases": ["lassra_card", "residency_card", "state_id_card"],
    },
}

# ---------------------------------------------------------------------------
# Government examination / admission documents
# ---------------------------------------------------------------------------

EXAM_DOCUMENTS: dict[str, dict[str, Any]] = {
    "waec_certificate": {
        "display": "WAEC certificate / statement of result",
        "issuing_authority": "West African Examinations Council (WAEC)",
        "level": "federal_state",
        "required_fields": ["name", "exam_number", "exam_year"],
        "optional_fields": ["subjects", "center_number", "date_of_birth"],
        "validators": {"exam_number": _re(r"^\d{10}$"),
                       "exam_year": _re(r"^(19|20)\d{2}$"),
                       "name": validate_name},
        "checksum": None,
        "security_features": ["watermark", "guilloche", "microtext",
                              "uv_print", "security_paper", "embossed_seal"],
        "markers": ["west african examinations council"],
        "verification": "WAEC result verification portal (scratch card)",
        "aliases": ["waec", "waec_certificate", "wassce"],
    },
    "neco_certificate": {
        "display": "NECO certificate / statement of result",
        "issuing_authority": "National Examinations Council (NECO)",
        "level": "federal",
        "required_fields": ["name", "exam_number", "exam_year"],
        "optional_fields": ["subjects", "center_number"],
        "validators": {"exam_number": _re(r"^[A-Z0-9]{8,12}$"),
                       "exam_year": _re(r"^(19|20)\d{2}$"),
                       "name": validate_name},
        "checksum": None,
        "security_features": ["watermark", "guilloche", "uv_print"],
        "markers": ["national examinations council"],
        "verification": "NECO result verification portal",
        "aliases": ["neco", "neco_certificate"],
    },
    "jamb_result": {
        "display": "JAMB result slip / admission letter",
        "issuing_authority": "Joint Admissions and Matriculation Board (JAMB)",
        "level": "federal",
        "required_fields": ["name", "registration_number", "exam_year"],
        "optional_fields": ["score", "institution", "course"],
        "validators": {"registration_number": _re(r"^\d{8}[A-Z]{2}$"),
                       "exam_year": _re(r"^(19|20)\d{2}$"),
                       "name": validate_name},
        "checksum": None,
        "security_features": ["qr_code", "watermark", "barcode"],
        "markers": ["joint admissions and matriculation board"],
        "verification": "JAMB e-facility portal",
        "aliases": ["jamb", "jamb_result", "jamb_admission_letter"],
    },
}

DOCUMENT_REGISTRY: dict[str, dict[str, Any]] = {
    **FEDERAL_IDENTITY, **FEDERAL_CORPORATE, **LAND_DOCUMENTS,
    **STATE_IDENTITY, **EXAM_DOCUMENTS,
}

_ALIAS_INDEX: dict[str, str] = {}
for _key, _spec in DOCUMENT_REGISTRY.items():
    _ALIAS_INDEX[_key] = _key
    for _alias in _spec.get("aliases", []):
        _ALIAS_INDEX[_alias.lower()] = _key


def canonical_doc_type(doc_type: str, state: Optional[str] = None) -> Optional[str]:
    """Resolve an integrator's doc_type (alias or canonical) to a registry key.
    For state-level docs, optionally validate the issuing state."""
    key = _ALIAS_INDEX.get((doc_type or "").strip().lower())
    if key is None:
        return None
    if state is not None:
        spec = DOCUMENT_REGISTRY[key]
        if spec.get("level") == "state" and \
                state.strip().lower() not in spec.get("states", NIGERIAN_STATES):
            return None
    return key


def get_spec(doc_type: str, state: Optional[str] = None) -> Optional[dict[str, Any]]:
    key = canonical_doc_type(doc_type, state)
    return DOCUMENT_REGISTRY.get(key) if key else None


def spec_conformance(doc_type: str, fields: dict[str, Any],
                     text_corpus: str = "",
                     state: Optional[str] = None) -> dict[str, Any]:
    """Machine-checkable conformance of extracted fields against the spec.

    Returns missing/invalid fields, marker coverage (strings a genuine
    specimen carries, searched in OCR/VLM text), checksum results, and the
    issuing-authority claim. NEVER raises; unknown doc types report
    spec_known: false."""
    spec = get_spec(doc_type, state)
    if spec is None:
        return {"spec_known": False,
                "detail": f"'{doc_type}' not in the Nigerian document registry"
                          + (f" (state '{state}' does not issue it)" if state else "")}
    out: dict[str, Any] = {"spec_known": True, "display": spec["display"],
                           "issuing_authority": spec["issuing_authority"],
                           "level": spec["level"],
                           "security_features_expected": spec["security_features"],
                           "verification_channel": spec["verification"]}
    present = {k for k, v in fields.items() if str(v or "").strip()}
    out["missing_required"] = [f for f in spec["required_fields"]
                               if f not in present]
    invalid = []
    for field, validator in spec["validators"].items():
        if field in present and not validator(str(fields[field])):
            invalid.append(field)
    out["invalid_fields"] = invalid
    corpus = text_corpus.lower()
    out["markers_found"] = [m for m in spec["markers"] if m in corpus]
    out["markers_missing"] = [m for m in spec["markers"] if m not in corpus]
    if spec.get("checksum") == "mrz_td3" and \
            fields.get("mrz_line1") and fields.get("mrz_line2"):
        mrz = validate_passport_mrz(str(fields["mrz_line1"]),
                                    str(fields["mrz_line2"]))
        out["checksum"] = {"type": "mrz_td3", **mrz}
    return out


def list_document_types() -> dict[str, Any]:
    """Integrator-facing catalogue, grouped by issuing level."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for key, spec in DOCUMENT_REGISTRY.items():
        groups.setdefault(spec["level"], []).append({
            "doc_type": key, "display": spec["display"],
            "issuing_authority": spec["issuing_authority"],
            "states": spec.get("states"),
            "checksum": spec.get("checksum"),
            "aliases": spec.get("aliases", []),
        })
    return {"document_count": len(DOCUMENT_REGISTRY),
            "state_count": len(NIGERIAN_STATES), "groups": groups}
