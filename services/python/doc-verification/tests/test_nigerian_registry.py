"""Round 14 tests: comprehensive Nigerian government document registry.

Coverage of the knowledge base itself (every federal + state document class)
and engine integration of spec conformance.

Run: python3 -m pytest tests/test_nigerian_registry.py -q
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "integration"))

import nigerian_registry as reg  # noqa: E402
from doc_intelligence import (DocIntelStore, create_app,  # noqa: E402
                              reset_store_for_tests)
from embedded_pg import clone_migrated  # noqa: E402


def _b64(img: np.ndarray) -> str:
    ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    return base64.b64encode(enc.tobytes()).decode()


def _img(seed: int = 3) -> np.ndarray:
    rng = np.random.default_rng(seed)
    img = rng.normal(225, 6, (384, 512, 3)).clip(0, 255).astype(np.uint8)
    y = 40
    while y < 320:
        cv2.rectangle(img, (40, y), (40 + int(rng.integers(200, 420)), y + 14),
                      (40, 40, 40), -1)
        y += int(rng.integers(28, 55))
    return img


class TestRegistryCoverage:
    def test_all_federal_identity_documents_present(self):
        for key in ("nin_slip", "national_id_card", "passport_standard",
                    "passport_official", "passport_diplomatic",
                    "drivers_license", "voters_card", "birth_certificate",
                    "death_certificate", "marriage_certificate",
                    "nysc_certificate", "nysc_exemption",
                    "police_character_certificate"):
            assert key in reg.DOCUMENT_REGISTRY, key

    def test_corporate_and_exam_documents_present(self):
        for key in ("cac_certificate", "cac_status_report",
                    "firs_tax_clearance", "scuml_certificate",
                    "waec_certificate", "neco_certificate", "jamb_result"):
            assert key in reg.DOCUMENT_REGISTRY, key

    def test_state_land_documents_cover_all_states(self):
        land_docs = [k for k, s in reg.DOCUMENT_REGISTRY.items()
                     if s["level"] == "state"]
        assert {"certificate_of_occupancy", "deed_of_assignment",
                "survey_plan", "governors_consent"} <= set(land_docs)
        c_of_o = reg.DOCUMENT_REGISTRY["certificate_of_occupancy"]
        assert set(c_of_o["states"]) == set(reg.NIGERIAN_STATES)
        assert len(reg.NIGERIAN_STATES) == 37  # 36 states + FCT

    def test_every_spec_is_well_formed(self):
        for key, spec in reg.DOCUMENT_REGISTRY.items():
            assert spec["issuing_authority"], key
            assert spec["required_fields"], key
            assert spec["security_features"], key
            assert spec["markers"], key
            assert spec["verification"], key
            for validator in spec["validators"].values():
                assert callable(validator), key

    def test_alias_resolution(self):
        assert reg.canonical_doc_type("pvc") == "voters_card"
        assert reg.canonical_doc_type("c_of_o") == "certificate_of_occupancy"
        assert reg.canonical_doc_type("Passport") == "passport_standard"
        assert reg.canonical_doc_type("fictional_document") is None

    def test_state_gating(self):
        # R of O is not a Lagos instrument; C of O is valid everywhere.
        assert reg.canonical_doc_type("right_of_occupancy", state="lagos") is None
        assert reg.canonical_doc_type("right_of_occupancy", state="fct") is not None
        assert reg.canonical_doc_type("certificate_of_occupancy",
                                      state="lagos") is not None

    def test_spec_conformance_fields(self):
        spec = reg.spec_conformance("cac_certificate", {
            "company_name": "Efficacy Development PLC",
            "rc_number": "RC1234567",
            "incorporation_date": "12/03/2010"})
        assert spec["spec_known"] is True
        assert spec["missing_required"] == [] and spec["invalid_fields"] == []
        bad = reg.spec_conformance("cac_certificate", {
            "company_name": "X", "rc_number": "not-a-number"})
        assert "rc_number" in bad["invalid_fields"]
        assert "incorporation_date" in bad["missing_required"]

    def test_spec_conformance_markers(self):
        spec = reg.spec_conformance(
            "passport_standard", {"name": "A"}, "FEDERAL REPUBLIC OF NIGERIA e-passport")
        assert "federal republic of nigeria" in spec["markers_found"]
        unknown = reg.spec_conformance("drivers_licence_typo", {})
        assert unknown["spec_known"] is False


@pytest.fixture()
def store(tmp_path):
    s = DocIntelStore(database_url=clone_migrated("docintel"))
    reset_store_for_tests(s)
    yield s
    reset_store_for_tests(None)


@pytest.fixture()
def client(store):
    return TestClient(create_app())


class TestEngineRegistryIntegration:
    def test_document_types_catalogue(self, client):
        r = client.get("/api/v1/document-types")
        assert r.status_code == 200
        body = r.json()
        assert body["document_count"] == len(reg.DOCUMENT_REGISTRY)
        assert body["state_count"] == 37
        levels = set(body["groups"].keys())
        assert {"federal", "state", "federal_state"} <= levels

    def test_spec_factor_on_invalid_document_number(self, client):
        r = client.post("/api/v1/documents/intelligence", json={
            "image_base64": _b64(_img()), "doc_type": "passport",
            "fields": {"name": "Adewale Okafor",
                       "passport_number": "99-BADXX",   # fails ^[A-Z]\d{8}$
                       "date_of_birth": "01/01/1990",
                       "expiry_date": "01/01/2031",
                       "mrz_line1": "", "mrz_line2": ""}})
        body = r.json()
        codes = {f["code"] for f in body["factors"]}
        assert "spec_field_invalid" in codes
        assert body["spec_conformance"]["spec_known"] is True

    def test_state_mismatch_reported(self, client):
        r = client.post("/api/v1/documents/intelligence", json={
            "image_base64": _b64(_img()), "doc_type": "right_of_occupancy",
            "state": "lagos", "fields": {"holder_name": "A B"}})
        assert r.json()["spec_conformance"]["spec_known"] is False

    def test_land_document_spec(self, client):
        r = client.post("/api/v1/documents/intelligence", json={
            "image_base64": _b64(_img()), "doc_type": "c_of_o", "state": "lagos",
            "fields": {"holder_name": "Efficacy Development PLC",
                       "certificate_number": "LS/452/2001",
                       "parcel_description": "Plot 452, Badore, Eti-Osa",
                       "term_years": "99"}})
        body = r.json()
        spec = body["spec_conformance"]
        assert spec["spec_known"] is True
        assert spec["missing_required"] == []
        assert spec["issuing_authority"].startswith("State Lands Bureau")
