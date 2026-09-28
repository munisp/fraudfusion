"""Tests for the NDPA pseudonymisation audit job."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root

from mlops.compliance.ndpa_audit import (AuditResult, main, render_markdown,  # noqa: E402
                                         scan_dir)

pd = pytest.importorskip("pandas")


META = {"processing_purpose": "fraud_detection_model_training",
        "lawful_basis": "legitimate_interest", "pii_redacted": True}


def _write(df, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        df.to_parquet(path)
    except ImportError:
        pytest.skip("no parquet engine (pyarrow/fastparquet) installed")


def test_clean_export_passes(tmp_path):
    df = pd.DataFrame({
        "customer_id": ["pii_" + "a" * 32, "pii_" + "b" * 32],
        "log_amount": [3.1, 4.2],
        **META,
    })
    _write(df, tmp_path / "transactions/dt=2026-09-01/part.parquet")
    res = AuditResult()
    scan_dir(tmp_path, res)
    assert res.ok, res.findings
    assert res.files_scanned == 1 and res.rows_scanned == 2


def test_raw_bvn_detected_as_high(tmp_path):
    df = pd.DataFrame({
        "customer_id": ["pii_" + "a" * 32],
        "note": ["verify bvn 22223334444 soon"],  # embedded 11-digit alone is fine
        **META,
    })
    _write(df, tmp_path / "t.parquet")
    res = AuditResult()
    scan_dir(tmp_path, res)
    assert res.ok  # embedded in prose is not an exact-11-digit value

    df2 = pd.DataFrame({"customer_id": ["pii_" + "a" * 32],
                        "bvn_ref": ["22223334444"], **META})
    _write(df2, tmp_path / "t2.parquet")
    res2 = AuditResult()
    scan_dir(tmp_path, res2)
    assert not res2.ok
    assert any(f.check == "raw_identifier" for f in res2.findings)


def test_unpseudonymised_sensitive_column_flagged(tmp_path):
    df = pd.DataFrame({
        "customer_id": ["pii_" + "a" * 32],
        "customer_phone": ["+2348012345678"],  # must be pseudonymised
        **META,
    })
    _write(df, tmp_path / "t.parquet")
    res = AuditResult()
    scan_dir(tmp_path, res)
    assert not res.ok
    assert any(f.check == "unpseudonymised_column" for f in res.findings)


def test_missing_metadata_is_medium_not_high(tmp_path):
    df = pd.DataFrame({"customer_id": ["pii_" + "a" * 32], "log_amount": [1.0]})
    # metadata contract applies to lakehouse export partitions (dt=...)
    _write(df, tmp_path / "transactions/dt=2026-09-01/t.parquet")
    res = AuditResult()
    scan_dir(tmp_path, res)
    assert res.ok  # MEDIUM findings do not fail the audit
    assert sum(f.severity == "MEDIUM" for f in res.findings) == 3

    # non-partition files (KG store etc.) are exempt from the metadata contract
    res2 = AuditResult()
    _write(df, tmp_path / "kg/entities.parquet")
    scan_dir(tmp_path / "kg", res2)
    assert not any(f.check == "ndpa_metadata" for f in res2.findings)


def test_salt_leak_detected(tmp_path):
    (tmp_path / "meta.json").write_text('{"pii_salt": "super-secret"}')
    res = AuditResult()
    scan_dir(tmp_path, res)
    assert not res.ok
    assert any(f.check == "salt_leak" for f in res.findings)


def test_main_exit_codes(tmp_path):
    df = pd.DataFrame({"customer_id": ["pii_" + "a" * 32], **META})
    _write(df, tmp_path / "ok/t.parquet")
    assert main(["--lakehouse", str(tmp_path / "ok"),
                 "--out", str(tmp_path / "out")]) == 0
    assert (tmp_path / "out/ndpa_audit.json").exists()
    assert (tmp_path / "out/ndpa_audit.md").exists()

    df2 = pd.DataFrame({"customer_id": ["pii_" + "a" * 32],
                        "nin": ["12345678901"], **META})
    _write(df2, tmp_path / "bad/t.parquet")
    assert main(["--lakehouse", str(tmp_path / "bad"),
                 "--out", str(tmp_path / "out2")]) == 1


def test_main_no_targets_exit_2(tmp_path):
    assert main(["--lakehouse", str(tmp_path / "nope")]) == 2


def test_markdown_renders_verdict(tmp_path):
    res = AuditResult(files_scanned=1, rows_scanned=5)
    md = render_markdown(res, ["x"])
    assert "PASS" in md and "not anonymisation" in md
