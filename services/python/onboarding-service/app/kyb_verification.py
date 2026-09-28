"""KYB document-content verification pipeline.

Verifies the CONTENT of submitted KYB documents (not just their format):

- cac_certificate: extract company name / RC number / registration date;
  cross-check the extracted RC against the submitted cacNumber and the
  extracted name against the submitted business name (fuzzy).
- memart: extract company name; cross-document consistency with the CAC
  certificate name.
- utility_bill: extract address + bill date; flag bills older than 90 days;
  address plausibility (Nigerian state / LGA keyword).
- board_resolution: signatory block (>= 2 names after signed/director cues)
  and a date.
- image content: routed to the doc-verification service's local_cv forensics
  when importable; otherwise structural checks only with an honest
  'image_forensics_unavailable' note.

Honesty rules (no fabricated extraction):
- text-based PDFs: docling (via doc-verification, lazy/optional) if present,
  else pypdf raw text extraction; if neither backend exists the document
  verdict is 'engine_unavailable'.
- scanned PDFs with no text layer: 'no_text_layer' -> manual_review.
- if doc-verification (Lane D) is not importable, image forensics degrade to
  structural checks and the provenance says so.

Document bytes are NEVER logged or persisted here — only SHA-256 hashes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("onboarding-service.kyb-verification")

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # mirrors kyc-api MAX_UPLOAD_BYTES

UTILITY_BILL_MAX_AGE_DAYS = 90

# Nigerian states + FCT plus generic address cues, for utility-bill address
# plausibility. Deliberately small and embedded (no external dependency).
NIGERIAN_STATES = {
    "abia", "adamawa", "akwa ibom", "anambra", "bauchi", "bayelsa", "benue",
    "borno", "cross river", "delta", "ebonyi", "edo", "ekiti", "enugu",
    "gombe", "imo", "jigawa", "kaduna", "kano", "katsina", "kebbi", "kogi",
    "kwara", "lagos", "nasarawa", "niger", "ogun", "ondo", "osun", "oyo",
    "plateau", "rivers", "sokoto", "taraba", "yobe", "zamfara",
    "abuja", "fct",
}
ADDRESS_CUES = NIGERIAN_STATES | {"lga", "street", "close", "avenue", "road",
                                  "layout", "estate", "district"}

# Corporate suffixes stripped before fuzzy name comparison.
_CORP_SUFFIXES = {"ltd", "limited", "plc", "llp", "lp", "inc", "incorporated",
                  "co", "company", "ng", "nig", "nigeria", "enterprises",
                  "ventures", "and", "&", "the"}

_RC_RE = re.compile(r"\bRC\s?(\d{6,8})\b", re.IGNORECASE)
_DATE_RES = [
    re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"),                       # ISO
    re.compile(r"\b(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})\b"),            # d/m/yyyy
    re.compile(r"\b(\d{1,2})\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)"
               r"[a-z]*\s+(\d{4})\b", re.IGNORECASE),                # 12 March 2024
]
_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
           "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

_NAME_CUES = re.compile(
    r"(?:certify that|company name|name of (?:the )?company|registered name|"
    r"business name|incorporated(?: under)?(?:\s+the\s+name)?)\s*[:\-]?\s*(.+)",
    re.IGNORECASE,
)
_ADDRESS_CUE = re.compile(r"(?:address|service address|billing address|premises)"
                          r"\s*[:\-]\s*(.+)", re.IGNORECASE)
_SIGN_CUE = re.compile(r"\b(signed|director|signature|resolved|attest)\b",
                       re.IGNORECASE)
_NAME_LINE = re.compile(r"^([A-Z][a-zA-Z'\-\.]+(?:\s+[A-Z][a-zA-Z'\-\.]+){1,3})\s*$")


# ---------------------------------------------------------------------------
# Optional backends — all imports are defensive so this module is fully
# functional (and testable) with NONE of them installed.
# ---------------------------------------------------------------------------

def _bootstrap_doc_verification_path() -> None:
    """Add services/python/doc-verification (Lane D) to sys.path if present,
    the same shape Lane D uses to import its own package."""
    dv_dir = Path(__file__).resolve().parents[2] / "doc-verification"
    if dv_dir.is_dir() and str(dv_dir) not in sys.path:
        sys.path.insert(0, str(dv_dir))


def _load_docling_adapter():
    """doc-verification's DoclingAdapter (lazy docling import). Returns
    (adapter_callable_or_none, provenance_note)."""
    _bootstrap_doc_verification_path()
    for modname in ("doc_verification", "adapters"):
        try:
            mod = importlib.import_module(modname)
            adapter = getattr(mod, "DoclingAdapter", None)
            if adapter is not None:
                inst = adapter() if isinstance(adapter, type) else adapter
                if hasattr(inst, "parse_pdf"):
                    return inst.parse_pdf, f"doc-verification:{modname}.DoclingAdapter"
        except ImportError:
            continue
        except Exception as exc:  # adapter exists but failed to init
            logger.info("docling adapter unavailable: %s", type(exc).__name__)
            return None, "engine_unavailable"
    return None, None


def _load_local_cv():
    """doc-verification's local_cv image-forensics module, if importable."""
    _bootstrap_doc_verification_path()
    for modname in ("local_cv", "doc_verification.local_cv"):
        try:
            return importlib.import_module(modname)
        except ImportError:
            continue
        except Exception:
            return None
    return None


def _load_pypdf():
    try:
        return importlib.import_module("pypdf")
    except ImportError:
        try:
            return importlib.import_module("PyPDF2")
        except ImportError:
            return None


def available_engines() -> dict:
    """Introspection for tests/diagnostics: which backends are usable."""
    parse_pdf, _ = _load_docling_adapter()
    return {
        "docling": parse_pdf is not None,
        "pypdf": _load_pypdf() is not None,
        "local_cv": _load_local_cv() is not None,
    }


# ---------------------------------------------------------------------------
# Format sniffing + text extraction
# ---------------------------------------------------------------------------

def sniff_format(data: bytes) -> str:
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    return "unknown"


def extract_pdf_text(data: bytes, engines: list[str]) -> tuple[str | None, str]:
    """Return (text_or_none, note). text=None means no backend could run;
    text=='' means a backend ran but the PDF has no text layer."""
    parse_pdf, provenance = _load_docling_adapter()
    if parse_pdf is not None:
        try:
            result = parse_pdf(data)
            # Lane D's DoclingAdapter is fail-closed: {"status": "ok",
            # "blocks": [{"text": ...}]} or {"status": "unavailable", ...}.
            if isinstance(result, dict):
                if result.get("status") == "ok" and "blocks" in result:
                    text = "\n".join(b.get("text", "") for b in result["blocks"])
                    engines.append(provenance)
                    return text, "docling"
                if "text" in result and "status" not in result:
                    engines.append(provenance)
                    return result["text"] or "", "docling"
                logger.info("docling unavailable (%s); falling back to pypdf",
                            result.get("reason", "unknown"))
            else:
                engines.append(provenance)
                return str(result) or "", "docling"
        except Exception as exc:
            logger.info("docling parse failed (%s); falling back to pypdf",
                        type(exc).__name__)
    pypdf = _load_pypdf()
    if pypdf is None:
        return None, "no_pdf_parser"
    try:
        import io
        reader = pypdf.PdfReader(io.BytesIO(data))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        engines.append("pypdf")
        return text, "pypdf"
    except Exception as exc:
        logger.info("pypdf extraction failed: %s", type(exc).__name__)
        return None, "pdf_parse_error"


# ---------------------------------------------------------------------------
# Field extraction + fuzzy matching (local, no new deps)
# ---------------------------------------------------------------------------

def _normalize_name(name: str) -> str:
    tokens = re.sub(r"[^a-z0-9\s]", " ", name.lower()).split()
    return " ".join(t for t in tokens if t not in _CORP_SUFFIXES)


def _levenshtein(a: str, b: str) -> int:
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def name_similarity(a: str, b: str) -> float:
    """Fuzzy company-name similarity in [0,1]: max of normalized Levenshtein
    similarity and token-set Jaccard, after suffix/case normalization."""
    na, nb = _normalize_name(a), _normalize_name(b)
    if not na or not nb:
        return 0.0
    lev = 1.0 - _levenshtein(na, nb) / max(len(na), len(nb))
    ta, tb = set(na.split()), set(nb.split())
    jaccard = len(ta & tb) / len(ta | tb)
    return max(lev, jaccard)


def extract_rc_number(text: str) -> str | None:
    m = _RC_RE.search(text)
    return f"RC{m.group(1)}" if m else None


def _parse_date_match(m: re.Match) -> datetime | None:
    try:
        if "jan" in m.re.pattern:
            return datetime(int(m.group(3)), _MONTHS[m.group(2)[:3].lower()],
                            int(m.group(1)), tzinfo=timezone.utc)
        if m.re.pattern.startswith(r"\b(\d{4})"):
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            tzinfo=timezone.utc)
        # d/m/yyyy (Nigerian convention is day-first)
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return datetime(y, mo, d, tzinfo=timezone.utc)
    except (ValueError, KeyError):
        return None


def extract_dates(text: str) -> list[str]:
    """All parseable dates in the text, as ISO date strings, in order."""
    found: list[str] = []
    for rx in _DATE_RES:
        for m in rx.finditer(text):
            dt = _parse_date_match(m)
            if dt and 1950 <= dt.year <= 2100:
                iso = dt.date().isoformat()
                if iso not in found:
                    found.append(iso)
    return found


def extract_company_name(text: str) -> str | None:
    for line in text.splitlines():
        m = _NAME_CUES.search(line)
        if m:
            candidate = m.group(1).strip().strip(".,")
            candidate = re.split(r"\b(?:is|was|having|with rc|hereby)\b",
                                 candidate, flags=re.IGNORECASE)[0].strip().strip(".,")
            if len(candidate) >= 3:
                return candidate
    return None


def extract_address(text: str) -> str | None:
    m = _ADDRESS_CUE.search(text)
    if m and len(m.group(1).strip()) >= 5:
        return m.group(1).strip()
    # fallback: the most address-like line (contains a state/LGA keyword)
    for line in text.splitlines():
        low = line.lower()
        if any(k in low for k in NIGERIAN_STATES) and len(line.strip()) >= 10:
            return line.strip()
    return None


def address_plausible(address: str) -> bool:
    low = address.lower()
    return bool(address.strip()) and any(k in low for k in ADDRESS_CUES)


def extract_signatories(text: str) -> list[str]:
    """Names appearing on/after lines with signing cues ('signed', 'director',
    'resolved'...). Needs >= 2 to constitute a board signatory block."""
    lines = text.splitlines()
    names: list[str] = []
    active = False
    for line in lines:
        if _SIGN_CUE.search(line):
            active = True
            # cue line itself may carry a name: "Signed: Chidi Okafor"
            tail = re.split(r"[:：]", line, maxsplit=1)
            candidate = tail[1] if len(tail) == 2 else ""
            for piece in (candidate,):
                m = _NAME_LINE.match(piece.strip())
                if m and m.group(1).lower() not in {n.lower() for n in names}:
                    names.append(m.group(1))
            continue
        if active:
            m = _NAME_LINE.match(line.strip())
            if m and m.group(1).lower() not in {n.lower() for n in names}:
                names.append(m.group(1))
    return names

# ---------------------------------------------------------------------------
# Per-document verification
# ---------------------------------------------------------------------------

NAME_MATCH_THRESHOLD = 0.8


def _doc_result(doc_type: str, reference: str, sha256: str | None) -> dict:
    return {
        "type": doc_type,
        "reference": reference,
        "content_sha256": sha256,
        "verdict": "manual_review",
        "checks": [],
        "extracted": {},
        "notes": [],
    }


def _check(result: dict, name: str, passed: bool, detail: str = "") -> None:
    result["checks"].append({"check": name, "passed": passed, "detail": detail})


def _verify_image(doc: dict, data: bytes, fmt: str, engines: list[str]) -> dict:
    """Image content: doc-verification local_cv forensics when importable,
    otherwise structural checks only with an honest unavailability note."""
    result = _doc_result(doc["type"], doc["reference"],
                         hashlib.sha256(data).hexdigest())
    result["extracted"]["format"] = fmt
    result["extracted"]["size_bytes"] = len(data)
    _check(result, "non_empty", len(data) > 0)
    _check(result, "size_within_limit", len(data) <= MAX_UPLOAD_BYTES)
    _check(result, "recognized_format", fmt != "unknown")

    local_cv = _load_local_cv()
    if local_cv is not None:
        try:
            # Lane D's real entry point is analyze_document_image(); the other
            # names are tolerated in case the package layout shifts.
            analyze = (getattr(local_cv, "analyze_document_image", None)
                       or getattr(local_cv, "analyze_image", None)
                       or getattr(local_cv, "forensics", None))
            if analyze is not None:
                forensics = analyze(data)
                engines.append("doc-verification:local_cv")
                result["forensics"] = forensics
                # Undecodable or poor-quality capture -> reject; otherwise
                # forensics inform but a human still confirms the document.
                flagged = bool(
                    isinstance(forensics, dict)
                    and (forensics.get("tamper_detected")
                         or forensics.get("decode_ok") is False
                         or forensics.get("quality") == "poor"))
                detail = "; ".join(forensics.get("verdict_reasons", [])) \
                    if isinstance(forensics, dict) else ""
                _check(result, "image_forensics", not flagged,
                       detail or "local_cv analysis")
                result["verdict"] = "rejected" if flagged else "manual_review"
                if flagged:
                    result["notes"].append("local_cv flagged the image: "
                                           + (detail or "tamper/quality"))
                return result
        except Exception as exc:
            logger.info("local_cv failed: %s", type(exc).__name__)
            result["notes"].append("image_forensics_error: local_cv raised; "
                                   "structural checks only")
    else:
        result["notes"].append("image_forensics_unavailable: doc-verification "
                               "package not importable; structural checks only")
    # Degraded path: structural checks cannot verify content -> manual review.
    result["verdict"] = ("manual_review"
                         if all(c["passed"] for c in result["checks"])
                         else "rejected")
    return result


def _verify_cac_certificate(doc: dict, text: str, engines: list[str],
                            business_name: str, cac_number: str) -> dict:
    result = _doc_result(doc["type"], doc["reference"],
                         hashlib.sha256(doc["_bytes"]).hexdigest())
    rc = extract_rc_number(text)
    name = extract_company_name(text)
    dates = extract_dates(text)
    result["extracted"] = {
        "rc_number": rc,
        "company_name": name,
        "registration_date": dates[0] if dates else None,
        "all_dates": dates,
    }
    _check(result, "rc_number_found", rc is not None,
           rc or "no RC<number> pattern in extracted text")
    rc_format_ok = bool(rc and re.fullmatch(r"RC\d{6,8}", rc))
    _check(result, "rc_format_valid", rc_format_ok)
    rc_matches = rc == cac_number
    _check(result, "rc_matches_submission", rc_matches,
           f"extracted={rc} submitted={cac_number}")
    if name is None:
        _check(result, "company_name_found", False,
               "no company-name cue in extracted text")
        name_sim = 0.0
    else:
        _check(result, "company_name_found", True, name)
        name_sim = name_similarity(name, business_name)
        _check(result, "name_matches_submission", name_sim >= NAME_MATCH_THRESHOLD,
               f"similarity={name_sim:.2f} extracted='{name}' submitted='{business_name}'")
    _check(result, "registration_date_found", bool(dates),
           dates[0] if dates else "no parseable date in extracted text")

    critical = ["rc_number_found", "rc_format_valid", "rc_matches_submission"]
    if any(not c["passed"] for c in result["checks"] if c["check"] in critical):
        result["verdict"] = "rejected"
        result["notes"].append("RC number on certificate does not match the "
                               "submitted CAC number (or is unreadable)")
    elif not name or name_sim < NAME_MATCH_THRESHOLD or not dates:
        result["verdict"] = "manual_review"
    else:
        result["verdict"] = "verified"
    return result


def _verify_memart(doc: dict, text: str, cac_extracted_name: str | None,
                   business_name: str) -> dict:
    result = _doc_result(doc["type"], doc["reference"],
                         hashlib.sha256(doc["_bytes"]).hexdigest())
    name = extract_company_name(text)
    result["extracted"] = {"company_name": name}
    _check(result, "company_name_found", name is not None,
           name or "no company-name cue in extracted text")
    sim_sub = name_similarity(name, business_name) if name else 0.0
    _check(result, "name_matches_submission", sim_sub >= NAME_MATCH_THRESHOLD,
           f"similarity={sim_sub:.2f}")
    if cac_extracted_name:
        sim_cac = name_similarity(name, cac_extracted_name) if name else 0.0
        _check(result, "cross_doc_consistency_cac",
               sim_cac >= NAME_MATCH_THRESHOLD,
               f"similarity_to_cac_certificate={sim_cac:.2f} "
               f"cac_name='{cac_extracted_name}'")
    elif name:
        result["notes"].append("cross-doc consistency not evaluated: CAC "
                               "certificate name unavailable")
    if name is None:
        result["verdict"] = "manual_review"
    elif any(not c["passed"] for c in result["checks"]):
        result["verdict"] = "rejected"
        result["notes"].append("memart company name conflicts with the "
                               "submission or the CAC certificate")
    else:
        result["verdict"] = "verified"
    return result


def _verify_utility_bill(doc: dict, text: str, now: datetime) -> dict:
    result = _doc_result(doc["type"], doc["reference"],
                         hashlib.sha256(doc["_bytes"]).hexdigest())
    address = extract_address(text)
    dates = extract_dates(text)
    bill_date = dates[0] if dates else None
    result["extracted"] = {"address": address, "bill_date": bill_date,
                           "all_dates": dates}
    _check(result, "address_found", address is not None,
           address or "no address cue or Nigerian state keyword found")
    plausible = address_plausible(address) if address else False
    _check(result, "address_plausible", plausible,
           "contains Nigerian state/LGA keyword" if plausible
           else "no Nigerian state or LGA keyword in address")
    _check(result, "bill_date_found", bill_date is not None,
           bill_date or "no parseable date in extracted text")
    if bill_date:
        age = (now.date() - datetime.fromisoformat(bill_date).date()).days
        result["extracted"]["bill_age_days"] = age
        _check(result, "bill_recent_90d", age <= UTILITY_BILL_MAX_AGE_DAYS,
               f"bill is {age} days old (max {UTILITY_BILL_MAX_AGE_DAYS})")
    failed = {c["check"] for c in result["checks"] if not c["passed"]}
    if not failed:
        result["verdict"] = "verified"
    elif failed <= {"bill_recent_90d", "bill_date_found"}:
        result["verdict"] = "manual_review"
        result["notes"].append("utility bill older than 90 days or undated "
                               "— acceptable only with fresh evidence")
    else:
        result["verdict"] = "manual_review"
        result["notes"].append("address unreadable or implausible — needs "
                               "human review")
    return result


def _verify_board_resolution(doc: dict, text: str) -> dict:
    result = _doc_result(doc["type"], doc["reference"],
                         hashlib.sha256(doc["_bytes"]).hexdigest())
    signatories = extract_signatories(text)
    dates = extract_dates(text)
    result["extracted"] = {"signatories": signatories,
                           "signatory_count": len(signatories),
                           "date": dates[0] if dates else None}
    _check(result, "signatory_block_present", len(signatories) >= 2,
           f"{len(signatories)} signatories found after signed/director cues "
           "(need >= 2)")
    _check(result, "date_present", bool(dates),
           dates[0] if dates else "no parseable date in extracted text")
    result["verdict"] = ("verified"
                         if all(c["passed"] for c in result["checks"])
                         else "manual_review")
    if result["verdict"] != "verified":
        result["notes"].append("board resolution lacks a >=2-signatory block "
                               "or a date — needs human review")
    return result


# ---------------------------------------------------------------------------
# Aggregate pipeline
# ---------------------------------------------------------------------------

def decode_document_content(document: dict) -> tuple[bytes | None, str | None]:
    """Decode a KybDocument's base64 content. Returns (bytes, error). The
    schema already validated base64, so an error here means something was
    mutated post-validation."""
    content = document.get("content")
    if content is None:
        return None, None
    try:
        data = base64.b64decode(content, validate=True)
    except (binascii.Error, ValueError):
        return None, "content is not valid base64"
    if not data:
        return None, "content decodes to empty bytes"
    if len(data) > MAX_UPLOAD_BYTES:
        return None, "content exceeds 10MB limit"
    return data, None


def verify_kyb_documents(documents: list[dict], business_name: str,
                         cac_number: str,
                         now: datetime | None = None) -> dict:
    """Run the full KYB verification pipeline over the submitted documents.

    `documents` are KybDocument-shaped dicts (type/reference[/content]).
    Never logs or returns document content — only SHA-256 hashes and
    extracted fields.
    """
    now = now or datetime.now(timezone.utc)
    engines: list[str] = []
    per_doc: list[dict] = []
    with_content = 0
    cac_name: str | None = None

    # First pass: verify each document independently.
    deferred_memarts: list[tuple[dict, int]] = []
    for doc in documents:
        data, err = decode_document_content(doc)
        if data is None:
            res = _doc_result(doc["type"], doc["reference"], None)
            res["verdict"] = "skipped"
            res["notes"].append(err or "no content provided; reference-only "
                                "document — content verification skipped")
            per_doc.append(res)
            continue
        with_content += 1
        doc = {**doc, "_bytes": data}
        fmt = sniff_format(data)
        if fmt != "pdf":
            per_doc.append(_verify_image(doc, data, fmt, engines))
            continue
        text, backend = extract_pdf_text(data, engines)
        if text is None:
            res = _doc_result(doc["type"], doc["reference"],
                              hashlib.sha256(data).hexdigest())
            res["verdict"] = "engine_unavailable"
            res["notes"].append(f"no PDF text-extraction backend available "
                                f"({backend})")
            per_doc.append(res)
            continue
        if not text.strip():
            res = _doc_result(doc["type"], doc["reference"],
                              hashlib.sha256(data).hexdigest())
            res["verdict"] = "manual_review"
            res["notes"].append(f"no_text_layer: {backend} extracted no text; "
                                "likely a scanned image PDF — manual review")
            per_doc.append(res)
            continue
        dtype = doc["type"]
        if dtype == "cac_certificate":
            res = _verify_cac_certificate(doc, text, engines, business_name,
                                          cac_number)
            cac_name = cac_name or res["extracted"].get("company_name")
            per_doc.append(res)
        elif dtype == "memart":
            # Defer so cross-doc consistency can use the CAC name even when
            # the memart precedes the certificate in the payload.
            deferred_memarts.append((doc, len(per_doc)))
            per_doc.append(None)  # placeholder, filled in second pass
        elif dtype == "utility_bill":
            per_doc.append(_verify_utility_bill(doc, text, now))
        else:  # board_resolution
            per_doc.append(_verify_board_resolution(doc, text))

    # Second pass: memart cross-document consistency.
    for doc, idx in deferred_memarts:
        text, _backend = extract_pdf_text(doc["_bytes"], engines)
        res = _verify_memart(doc, text or "", cac_name, business_name)
        if not cac_name:
            res["notes"].append("cross-doc consistency not evaluated: CAC "
                                "certificate company name unavailable")
        per_doc[idx] = res

    # Aggregate verdict.
    content_verdicts = [d["verdict"] for d in per_doc if d["verdict"] != "skipped"]
    if not documents or with_content == 0:
        verdict = "skipped"
        reason = ("no document content provided; format-only validation "
                  "performed (reference-only submission)")
    elif all(v == "engine_unavailable" for v in content_verdicts):
        verdict = "engine_unavailable"
        reason = "no extraction backend could process any submitted document"
    elif "rejected" in content_verdicts:
        verdict = "rejected"
        reasons = [f"{d['type']}: {n}" for d in per_doc
                   if d["verdict"] == "rejected" for n in d["notes"]]
        reason = "; ".join(reasons) or "one or more documents failed verification"
    elif all(v == "verified" for v in content_verdicts):
        verdict = "verified"
        reason = "all submitted document content verified and consistent"
    else:
        verdict = "manual_review"
        reason = "one or more documents need human review (see per-document notes)"

    return {
        "verdict": verdict,
        "reason": reason,
        "documents": per_doc,
        "documents_with_content": with_content,
        "documents_total": len(documents),
        "consistency": {
            "cac_rc_matches_submission": next(
                (c["passed"] for d in per_doc if d and d["type"] == "cac_certificate"
                 for c in d["checks"] if c["check"] == "rc_matches_submission"), None),
            "memart_cac_name_consistent": next(
                (c["passed"] for d in per_doc if d and d["type"] == "memart"
                 for c in d["checks"] if c["check"] == "cross_doc_consistency_cac"),
                None),
        },
        "provenance": {
            "engines": sorted(set(engines)) if engines else [],
            "doc_verification_importable": _load_local_cv() is not None,
            "pypdf_available": _load_pypdf() is not None,
        },
        "verified_at": now.isoformat(),
    }
