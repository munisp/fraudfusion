"""Document Intelligence Engine (Round 14) — composite authenticity verdict.

Layers (each reports provenance; none fabricates):

  1. pipeline.verify_document     — existing capture/quality/replay + OCR/VLM
  2. forensics.analyze            — ELA splice, noise inconsistency, copy-move,
                                    JPEG ghost (pixel-level forgery detection)
  3. metadata_forensics           — EXIF / PDF byte forensics
  4. checksums + cross_field      — ICAO 9303 check digits, date impossibility,
                                    MRZ-vs-visual seams (caller-supplied or
                                    VLM-extracted fields)
  5. fingerprint registry         — byte-hash + perceptual near-duplicate
                                    against every document this tenant has
                                    registered; revocation list

Composite: every signal is a weighted factor -> 0-100 authenticity risk
score with bands (>=50 forgery_suspected/rejected, >=20 manual_review,
else clean) — same explainable shape as the land risk engine. The headline
verdict is the STRICTER of the base pipeline status and the score band.

Every verification is appended to a hash-chained log (tamper-evident, like
the land evidence chain) and returned as a verification certificate
(certificate_id + document sha256 + score + factors) that the submitting
party can later prove was issued.

Endpoints (service-to-service convention, DB-backed):
  POST /api/v1/documents/intelligence          verify (+ optional register)
  POST /api/v1/documents/register              fingerprint-only registration
  GET  /api/v1/documents/{doc_hash}            registry entry + verdicts
  GET  /api/v1/documents/{doc_hash}/similar    perceptual near-duplicates
  POST /api/v1/documents/{doc_hash}/revoke     revoke a registered document
  GET  /api/v1/documents/{doc_hash}/chain      verification chain + validity
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

import cross_field
import fingerprint
import forensics
import metadata_forensics
import nigerian_docs
import nigerian_registry
import pipeline
from checksums import date_logic_issues, validate_passport_mrz

router = APIRouter()

# ---------------------------------------------------------------------------
# Authenticity risk model — weights mirror the land engine's philosophy:
# proven tampering outweighs process gaps.
# ---------------------------------------------------------------------------

WEIGHTS: dict[str, int] = {
    "revoked_document": 100,
    "copy_move": 45,
    "mrz_checksum_fail": 40,
    "same_document_resubmitted": 40,
    "ela_splice": 35,
    "date_impossible": 35,
    "noise_inconsistency": 30,
    "near_duplicate_known": 30,
    "metadata_editor": 25,
    "pdf_editor_producer": 25,
    "mrz_visual_mismatch": 25,
    "name_inconsistency": 20,
    "pdf_incremental_update": 15,
    "double_compression": 15,
    "metadata_no_device": 10,
    "pdf_date_impossible": 15,
    "metadata_time_anomaly": 15,
    "screen_replay": 40,
    "printed_cutout": 15,
    "quality_poor": 25,
    "extraction_unconfirmed": 10,
    "spec_missing_required": 15,
    "spec_field_invalid": 20,
    "spec_marker_missing": 10,
}

BANDS = ((50, "forgery_suspected"), (20, "manual_review"), (0, "clean"))


def score_factors(factors: list[dict[str, Any]]) -> dict[str, Any]:
    total = 0
    out = []
    for f in factors:
        penalty = f.get("penalty", WEIGHTS.get(f["code"], 10))
        total += penalty
        out.append({"code": f["code"], "penalty": penalty,
                    "detail": f.get("detail", "")})
    total = min(total, 100)
    band = next(label for threshold, label in BANDS if total >= threshold)
    return {"authenticity_score": total, "band": band, "factors": out}


# ---------------------------------------------------------------------------
# Data store — SQLite dev/test; canonical PG migration for production
# (database/20261028_document_intelligence.sql)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS doc_registry (
    doc_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    doc_type TEXT,
    dhash TEXT,
    phash TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    revoke_reason TEXT,
    registered_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS doc_verification_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    doc_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

GENESIS = "GENESIS"


class DocIntelStore:
    def __init__(self, sqlite_path: Optional[str] = None):
        path = sqlite_path or os.getenv(
            "DOC_INTEL_DB", os.path.join(os.path.dirname(__file__), "docintel.db"))
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def query(self, sql: str, params: dict[str, Any] = {}) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def query_one(self, sql: str, params: dict[str, Any] = {}) -> Optional[dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: dict[str, Any] = {}) -> None:
        self.conn.execute(sql, params)
        self.conn.commit()

    # -- hash-chained verification log --------------------------------------
    def append_event(self, doc_hash: str, event_type: str,
                     payload: dict[str, Any]) -> dict[str, Any]:
        last = self.query_one(
            "SELECT entry_hash FROM doc_verification_chain"
            " WHERE tenant_id = 'default' AND doc_hash = :d"
            " ORDER BY id DESC LIMIT 1", {"d": doc_hash})
        prev = last["entry_hash"] if last else GENESIS
        payload_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        entry_hash = hashlib.sha256(
            f"{prev}|{payload_hash}|{event_type}|{doc_hash}".encode()).hexdigest()
        self.execute(
            "INSERT INTO doc_verification_chain (tenant_id, doc_hash, event_type,"
            " payload_hash, prev_hash, entry_hash, created_at)"
            " VALUES ('default', :d, :e, :p, :pr, :h, :t)",
            {"d": doc_hash, "e": event_type, "p": payload_hash, "pr": prev,
             "h": entry_hash, "t": datetime.utcnow().isoformat()})
        return {"prev_hash": prev, "entry_hash": entry_hash,
                "payload_hash": payload_hash}

    def get_chain(self, doc_hash: str) -> list[dict[str, Any]]:
        return self.query(
            "SELECT * FROM doc_verification_chain WHERE tenant_id = 'default'"
            " AND doc_hash = :d ORDER BY id", {"d": doc_hash})

    @staticmethod
    def verify_chain(entries: list[dict[str, Any]], doc_hash: str) -> bool:
        prev = GENESIS
        for e in entries:
            expect = hashlib.sha256(
                f"{prev}|{e['payload_hash']}|{e['event_type']}|{doc_hash}".encode()
            ).hexdigest()
            if e["entry_hash"] != expect or e["prev_hash"] != prev:
                return False
            prev = e["entry_hash"]
        return True


_store: Optional[DocIntelStore] = None


def get_store() -> DocIntelStore:
    global _store
    if _store is None:
        _store = DocIntelStore()
    return _store


def reset_store_for_tests(store: Optional[DocIntelStore]) -> None:
    global _store
    _store = store


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class IntelligenceInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    image_base64: Optional[str] = None
    pdf_base64: Optional[str] = None
    doc_type: Optional[str] = None
    fields: dict[str, Any] = {}          # pre-extracted fields (or VLM output)
    state: Optional[str] = None          # issuing state (state-level docs)
    register_document: bool = Field(default=False, alias="register")
    reference: Optional[str] = None      # caller's case reference


class RegisterInput(BaseModel):
    image_base64: Optional[str] = None
    pdf_base64: Optional[str] = None
    doc_type: Optional[str] = None
    reference: Optional[str] = None


def _payload_bytes(payload: IntelligenceInput | RegisterInput) -> tuple[bytes, str]:
    if payload.image_base64:
        return base64.b64decode(payload.image_base64), "image"
    if payload.pdf_base64:
        return base64.b64decode(payload.pdf_base64), "pdf"
    raise HTTPException(status_code=422,
                        detail="image_base64 or pdf_base64 is required")


def _registry_check(store: DocIntelStore, doc_hash: str,
                    fp: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Byte-hash + perceptual near-duplicate + revocation checks."""
    factors: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    exact = store.query_one(
        "SELECT * FROM doc_registry WHERE doc_hash = :d", {"d": doc_hash})
    if exact:
        if exact["status"] == "revoked":
            factors.append({"code": "revoked_document",
                            "detail": f"this exact document was revoked: "
                                      f"{exact.get('revoke_reason') or 'no reason'}"})
        else:
            factors.append({"code": "same_document_resubmitted",
                            "detail": "byte-identical document already registered "
                                      f"at {exact['registered_at']}"})
        matches.append({"doc_hash": doc_hash, "distance": 0,
                        "status": exact["status"]})
    if fp.get("dhash") is not None:
        for row in store.query("SELECT * FROM doc_registry"):
            if row["doc_hash"] == doc_hash:
                continue
            dist = fingerprint.distance(
                fp, {"dhash": int(row["dhash"]), "phash": int(row["phash"])}) \
                if row.get("dhash") and row.get("phash") else None
            if dist is None:
                continue
            if dist <= fingerprint.SAME_DOCUMENT_THRESHOLD:
                factors.append({"code": "same_document_resubmitted",
                                "detail": f"perceptually identical to a registered "
                                          f"document (distance {dist})",
                                "penalty": WEIGHTS["same_document_resubmitted"]})
                matches.append({"doc_hash": row["doc_hash"], "distance": dist,
                                "status": row["status"]})
            elif dist <= fingerprint.SIMILAR_THRESHOLD:
                factors.append({"code": "near_duplicate_known",
                                "detail": f"suspiciously similar to a registered "
                                          f"document (distance {dist})"})
                matches.append({"doc_hash": row["doc_hash"], "distance": dist,
                                "status": row["status"]})
    return factors, matches


def run_intelligence(store: DocIntelStore, payload: IntelligenceInput) -> dict[str, Any]:
    raw, kind = _payload_bytes(payload)
    doc_hash = hashlib.sha256(raw).hexdigest()
    doc_type = (payload.doc_type or "unknown").strip()
    canonical = (nigerian_registry.canonical_doc_type(doc_type, payload.state)
                 or (nigerian_docs.canonical_doc_type(doc_type)
                     if doc_type != "unknown" else None))
    factors: list[dict[str, Any]] = []
    provenance: list[dict[str, Any]] = []

    base: dict[str, Any] = {}
    if kind == "image":
        # Layer 1 — existing pipeline (quality, replay, OCR/VLM extraction)
        base = pipeline.verify_document(raw, doc_type)
        provenance.append({"layer": "pipeline", "status": "ran",
                           "detail": f"verdict={base['status']}"})
        replay = base["authenticity"].get("screen_replay_integrity")
        cutout = base["authenticity"].get("printed_cutout_integrity")
        if base["quality"] == "poor":
            factors.append({"code": "quality_poor",
                            "detail": "capture quality insufficient"})
        if replay is not None and replay < pipeline.SCREEN_REPLAY_REJECT_THRESHOLD:
            factors.append({"code": "screen_replay",
                            "detail": "moire signature — photo of a screen"})
        if cutout is not None and cutout < pipeline.PRINTED_CUTOUT_REVIEW_THRESHOLD:
            factors.append({"code": "printed_cutout",
                            "detail": "weak physical-document signal"})
        if base["status"] == "manual_review":
            factors.append({"code": "extraction_unconfirmed",
                            "detail": "fields could not be confirmed automatically"})
        # Layer 2 — pixel forensics
        pix = forensics.analyze(raw)
        provenance.append({"layer": "pixel_forensics", "status": "ran",
                           "detail": f"{len(pix['signals'])} signal(s)"})
        factors.extend(pix["signals"])
        # Layer 3a — EXIF
        meta = metadata_forensics.analyze_image_metadata(raw)
        provenance.append({"layer": "metadata", "status": "ran",
                           "detail": f"{len(meta['signals'])} signal(s)"})
        factors.extend(meta["signals"])
        merged_fields = {**(base.get("extracted_fields") or {}), **payload.fields}
    else:
        # PDF path — byte forensics + optional docling parse
        pdf = pipeline.verify_pdf(raw)
        provenance.append({"layer": "pipeline_pdf", "status":
                           "ran" if pdf.get("status") != "unavailable" else "unavailable",
                           "detail": pdf.get("reason")})
        meta = metadata_forensics.analyze_pdf_metadata(raw)
        provenance.append({"layer": "metadata", "status": "ran",
                           "detail": f"{len(meta['signals'])} signal(s)"})
        factors.extend(meta["signals"])
        merged_fields = dict(payload.fields)

    # Layer 4 — checksums + semantic seams
    if merged_fields:
        if merged_fields.get("mrz_line1") and merged_fields.get("mrz_line2"):
            mrz = validate_passport_mrz(str(merged_fields["mrz_line1"]),
                                        str(merged_fields["mrz_line2"]))
            if mrz.get("format_ok") and not mrz["all_valid"]:
                bad = [k for k, v in mrz["checks"].items() if v is False]
                factors.append({"code": "mrz_checksum_fail",
                                "detail": "ICAO 9303 check digits failed: "
                                          + ", ".join(bad)})
        for issue in date_logic_issues(merged_fields):
            factors.append({"code": "date_impossible", "detail": issue["detail"]})
        seams = cross_field.run(merged_fields, canonical)
        for issue in seams["issues"]:
            factors.append(issue)
        provenance.append({"layer": "semantic_checks", "status": "ran",
                           "detail": f"{len(factors)} cumulative factor(s)"})
    else:
        provenance.append({"layer": "semantic_checks", "status": "skipped",
                           "detail": "no extracted fields available"})

    # Layer 4b — Nigerian registry spec conformance: required fields, marker
    # strings a genuine specimen carries (searched in OCR text), and the
    # issuing-authority claim. Unknown doc types are reported honestly.
    ocr_corpus = " ".join(
        str(l.get("text", "")) for l in (base.get("ocr_lines") or []))
    if payload.fields:
        ocr_corpus += " " + " ".join(str(v) for v in payload.fields.values())
    spec = nigerian_registry.spec_conformance(
        doc_type, merged_fields if kind == "image" else dict(payload.fields),
        ocr_corpus, payload.state)
    fields_available = bool((merged_fields if kind == "image" else payload.fields))
    if spec["spec_known"] and fields_available:
        for f in spec["missing_required"]:
            factors.append({"code": "spec_missing_required",
                            "detail": f"required field '{f}' missing for "
                                      f"{spec['display']}"})
        for f in spec["invalid_fields"]:
            factors.append({"code": "spec_field_invalid",
                            "detail": f"field '{f}' fails the {spec['display']} "
                                      f"format validator"})
        if ocr_corpus.strip() and spec["markers_missing"]:
            factors.append({"code": "spec_marker_missing",
                            "detail": "expected genuine-document marker(s) not "
                                      "found: " + ", ".join(spec["markers_missing"])})
        provenance.append({"layer": "registry_spec", "status": "ran",
                           "detail": f"{spec['display']}"})
    elif spec["spec_known"]:
        provenance.append({"layer": "registry_spec", "status": "skipped",
                           "detail": "spec known but no extracted fields "
                                     "to conform"})
    else:
        provenance.append({"layer": "registry_spec", "status": "unknown_type",
                           "detail": spec["detail"]})

    # Layer 5 — fingerprint registry
    fp = fingerprint.fingerprint(raw) if kind == "image" else {"dhash": None, "phash": None}
    reg_factors, matches = _registry_check(store, doc_hash, fp)
    factors.extend(reg_factors)
    provenance.append({"layer": "registry", "status": "ran",
                       "detail": f"{len(matches)} registry match(es)"})

    scored = score_factors(factors)

    # Headline verdict: STRICTER of base pipeline status and score band.
    rank = {"verified": 0, "clean": 0, "manual_review": 1,
            "forgery_suspected": 2, "rejected": 2, "unavailable": 3}
    base_status = base.get("status") if kind == "image" else (
        "manual_review" if not factors else "verified")
    verdict = (base_status if base_status and rank[base_status] >= rank[scored["band"]]
               else ("rejected" if scored["band"] == "forgery_suspected"
                     else scored["band"]))
    if verdict == "clean":
        verdict = "verified"

    if payload.register_document:
        _register_doc(store, doc_hash, doc_type, fp)

    chain_entry = store.append_event(doc_hash, "verification_completed", {
        "verdict": verdict, "score": scored["authenticity_score"],
        "reference": payload.reference,
        "factors": [f["code"] for f in scored["factors"]]})

    return {
        "verdict": verdict,
        "authenticity_score": scored["authenticity_score"],
        "band": scored["band"],
        "factors": scored["factors"],
        "document_sha256": doc_hash,
        "document_type": doc_type,
        "document_type_canonical": canonical,
        "registry_matches": matches,
        "provenance": provenance,
        "spec_conformance": spec,
        "base_pipeline": base or None,
        "verification_certificate": {
            "certificate_id": str(uuid.uuid4()),
            "document_sha256": doc_hash,
            "verdict": verdict,
            "authenticity_score": scored["authenticity_score"],
            "chain_entry_hash": chain_entry["entry_hash"],
            "issued_at": datetime.utcnow().isoformat(),
            "note": "hash-only certificate; the chain proves it was issued "
                    "and has not been rewritten",
        },
    }


def _register_doc(store: DocIntelStore, doc_hash: str, doc_type: str,
                  fp: dict[str, Any]) -> dict[str, Any]:
    existing = store.query_one(
        "SELECT doc_hash FROM doc_registry WHERE doc_hash = :d", {"d": doc_hash})
    if existing:
        return store.query_one("SELECT * FROM doc_registry WHERE doc_hash = :d",
                               {"d": doc_hash})
    store.execute(
        "INSERT INTO doc_registry (doc_hash, tenant_id, doc_type, dhash, phash,"
        " status, registered_at) VALUES (:d, 'default', :t, :dh, :ph, 'active', :r)",
        {"d": doc_hash, "t": doc_type,
         "dh": str(fp.get("dhash")) if fp.get("dhash") is not None else None,
         "ph": str(fp.get("phash")) if fp.get("phash") is not None else None,
         "r": datetime.utcnow().isoformat()})
    store.append_event(doc_hash, "document_registered", {"doc_type": doc_type})
    return store.query_one("SELECT * FROM doc_registry WHERE doc_hash = :d",
                           {"d": doc_hash})


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/v1/documents/intelligence")
def document_intelligence(payload: IntelligenceInput,
                          store: DocIntelStore = Depends(get_store)) -> dict[str, Any]:
    return run_intelligence(store, payload)


@router.post("/api/v1/documents/register", status_code=201)
def register_document(payload: RegisterInput,
                      store: DocIntelStore = Depends(get_store)) -> dict[str, Any]:
    raw, kind = _payload_bytes(payload)
    doc_hash = hashlib.sha256(raw).hexdigest()
    fp = fingerprint.fingerprint(raw) if kind == "image" else {"dhash": None, "phash": None}
    return _register_doc(store, doc_hash, payload.doc_type or "unknown", fp)


@router.get("/api/v1/documents/{doc_hash}")
def get_document(doc_hash: str,
                 store: DocIntelStore = Depends(get_store)) -> dict[str, Any]:
    row = store.query_one("SELECT * FROM doc_registry WHERE doc_hash = :d",
                          {"d": doc_hash})
    chain = store.get_chain(doc_hash)
    if not row and not chain:
        raise HTTPException(status_code=404, detail="document not registered")
    return {"registry": row, "verifications": len(chain),
            "chain_valid": DocIntelStore.verify_chain(chain, doc_hash)}


@router.get("/api/v1/documents/{doc_hash}/similar")
def similar_documents(doc_hash: str,
                      store: DocIntelStore = Depends(get_store)) -> dict[str, Any]:
    row = store.query_one("SELECT * FROM doc_registry WHERE doc_hash = :d",
                          {"d": doc_hash})
    if not row or not row.get("dhash"):
        raise HTTPException(status_code=404,
                            detail="document not registered or has no fingerprint")
    fp = {"dhash": int(row["dhash"]), "phash": int(row["phash"])}
    out = []
    for other in store.query("SELECT * FROM doc_registry"):
        if other["doc_hash"] == doc_hash or not other.get("dhash"):
            continue
        dist = fingerprint.distance(fp, {"dhash": int(other["dhash"]),
                                         "phash": int(other["phash"])})
        if dist is not None and dist <= fingerprint.SIMILAR_THRESHOLD:
            out.append({"doc_hash": other["doc_hash"], "distance": dist,
                        "status": other["status"],
                        "doc_type": other.get("doc_type")})
    return {"doc_hash": doc_hash, "similar": out}


@router.post("/api/v1/documents/{doc_hash}/revoke")
def revoke_document(doc_hash: str, reason: str = "revoked",
                    store: DocIntelStore = Depends(get_store)) -> dict[str, Any]:
    row = store.query_one("SELECT * FROM doc_registry WHERE doc_hash = :d",
                          {"d": doc_hash})
    if not row:
        raise HTTPException(status_code=404, detail="document not registered")
    if row["status"] == "revoked":
        raise HTTPException(status_code=409, detail="document already revoked")
    store.execute(
        "UPDATE doc_registry SET status = 'revoked', revoke_reason = :r,"
        " revoked_at = :t WHERE doc_hash = :d",
        {"r": reason, "t": datetime.utcnow().isoformat(), "d": doc_hash})
    store.append_event(doc_hash, "document_revoked", {"reason": reason})
    return store.query_one("SELECT * FROM doc_registry WHERE doc_hash = :d",
                           {"d": doc_hash})


@router.get("/api/v1/documents/{doc_hash}/chain")
def verification_chain(doc_hash: str,
                       store: DocIntelStore = Depends(get_store)) -> dict[str, Any]:
    chain = store.get_chain(doc_hash)
    if not chain:
        raise HTTPException(status_code=404, detail="no verification chain")
    return {"doc_hash": doc_hash, "entries": chain, "entry_count": len(chain),
            "chain_valid": DocIntelStore.verify_chain(chain, doc_hash)}


@router.get("/api/v1/document-types")
def document_types() -> dict[str, Any]:
    """The full Nigerian government document knowledge base — every federal
    and state document class the engine is trained on, with issuing
    authority, validators, checksums, and expected security features."""
    return nigerian_registry.list_document_types()


def create_app() -> FastAPI:
    app = FastAPI(title="FraudFusion Document Intelligence Engine",
                  version="2.0.0")
    app.include_router(router)
    return app
