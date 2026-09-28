"""Tests for the AML service calibration/model version-consistency check
(mlops/serving/aml_service.py).

The shipped Bayesian calibration posterior was fit on fraud_net/v3 score
distributions. Serving a different model version must surface loudly:
calibration_status="version_mismatch" in /health plus a WARNING log —
while still serving honestly labeled scores.
"""
from __future__ import annotations

import importlib.util
import logging
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SERVICE_PATH = REPO / "mlops" / "serving" / "aml_service.py"
REAL_CALIB_DIR = REPO / "ml" / "artifacts" / "bayesian_calibration" / "v1"

pytestmark = pytest.mark.skipif(not SERVICE_PATH.exists(),
                                reason="aml_service.py not present")


def load_service_module():
    spec = importlib.util.spec_from_file_location("aml_service_under_test",
                                                  SERVICE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_model_version_is_v3():
    """AML_MODEL_VERSION default must be v3 (matches the calibration
    artifact's base model). Checked in a clean subprocess with the env var
    unset."""
    code = (
        "import importlib.util, os, sys;"
        "os.environ.pop('AML_MODEL_VERSION', None);"
        f"spec = importlib.util.spec_from_file_location('m', r'{SERVICE_PATH}');"
        "m = importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(m);"
        "sys.stdout.write(m.MODEL_VERSION)"
    )
    env = dict(__import__("os").environ)
    env.pop("AML_MODEL_VERSION", None)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "v3"


def test_parse_base_model_version():
    m = load_service_module()
    parse = m.ScoreCalibrator._parse_base_model_version
    assert parse({"base_model": "fraud_net/v3"}) == "v3"
    assert parse({"base_model_version": "v2"}) == "v2"
    assert parse({}) is None


def test_check_consistency_match_vs_mismatch(caplog):
    m = load_service_module()
    m.CALIBRATION_DIR = REAL_CALIB_DIR
    cal = m.ScoreCalibrator()
    assert cal.calibration_mode == "bayesian"
    assert cal.base_model_version == "v3"

    with caplog.at_level(logging.WARNING):
        assert cal.check_consistency("v3") == "ok"
    assert "VERSION MISMATCH" not in caplog.text
    caplog.clear()

    with caplog.at_level(logging.WARNING):
        assert cal.check_consistency("v1") == "version_mismatch"
    assert "CALIBRATION VERSION MISMATCH" in caplog.text


def test_check_consistency_unavailable(tmp_path):
    m = load_service_module()
    m.CALIBRATION_DIR = tmp_path  # no artifact
    cal = m.ScoreCalibrator()
    assert cal.calibration_mode == "uncalibrated_fallback"
    assert cal.check_consistency("v3") == "unavailable"


@pytest.mark.parametrize("serving_version,expected_status", [
    ("v3", "ok"),
    ("v1", "version_mismatch"),
])
def test_health_reports_calibration_status(serving_version, expected_status):
    httpx = pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    m = load_service_module()
    m.MODEL_VERSION = serving_version
    m.CALIBRATION_DIR = REAL_CALIB_DIR
    with TestClient(m.app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["calibration_status"] == expected_status
        assert body["calibration_base_model_version"] == "v3"
        # still serves, honestly labeled
        resp = client.post("/v1/aml/score_calibrated", json={
            "transaction_id": "t1", "user_id": "u1", "amount": 5000.0})
        assert resp.status_code == 200
        assert resp.json()["calibration_mode"] == "bayesian"
