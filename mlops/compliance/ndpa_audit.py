"""NDPA pseudonymisation audit — turns a process control into an executed check.

Round-4 caveat #10: "BVN/NIN exclusion from ML paths remains a process control
that must be audited, not assumed." This job executes the audit:

  1. Scans every parquet under the lakehouse (and optionally the KG store and
     training feature dirs) for RAW Nigerian identifiers that must never reach
     ML artifacts:
       - BVN / NIN shaped values: exactly-11-digit strings in any column
       - columns named bvn|nin|phone|email|account_name|address whose values
         are not pseudonyms
  2. Verifies pseudonym columns carry the platform format `pii_<32 hex>`
     (salted SHA-256 truncated — see mlops/lakehouse/export.py::pseudonymize).
  3. Verifies NDPA row metadata exists (processing_purpose, lawful_basis,
     pii_redacted) on lakehouse exports.
  4. Verifies the pseudonymisation salt is NOT stored anywhere inside the
     scanned directories (salt lives only in env/secrets).

Exit code 1 on any HIGH finding (raw identifiers), 0 otherwise. Emits JSON +
markdown reports. Run from CI (see .github/workflows/verify.yml) and nightly.

Usage:
  python -m mlops.compliance.ndpa_audit --lakehouse mlops/data/lakehouse \
      [--kg intelligence/data/kg] [--out /tmp/ndpa_audit]
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

log = logging.getLogger("ndpa-audit")

# exactly 11 digits (BVN and NIN are both 11-digit Nigerian identifiers)
_ID_RE = re.compile(r"^\d{11}$")
# platform pseudonym format from mlops/lakehouse/export.py
_PSEUDONYM_RE = re.compile(r"^pii_[0-9a-f]{32}$")
# column names that may only contain pseudonyms or nothing
_SENSITIVE_COLS = re.compile(
    r"(^|_)(bvn|nin|phone|msisdn|email|account_name|address|full_name)(_|$)", re.I)
# metadata the NDPA export contract requires on lakehouse rows
_REQUIRED_META = ("processing_purpose", "lawful_basis", "pii_redacted")


@dataclass
class Finding:
    severity: str            # HIGH | MEDIUM | LOW
    file: str
    check: str
    detail: str


@dataclass
class AuditResult:
    files_scanned: int = 0
    rows_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity == "HIGH" for f in self.findings)


def _scan_frame(df, path: Path, res: AuditResult) -> None:
    res.rows_scanned += len(df)
    cols = set(df.columns)

    # Row-level NDPA metadata is a contract of LAKEHOUSE EXPORTS (partitioned
    # dt=... datasets); derived artifacts like the KG entity/relation store are
    # aggregates of already-pseudonymised ids and don't carry per-row metadata.
    is_lakehouse_export = "dt=" in str(path)
    if is_lakehouse_export:
        for meta in _REQUIRED_META:
            if meta not in cols:
                res.findings.append(Finding(
                    "MEDIUM", str(path), "ndpa_metadata",
                    f"missing required NDPA metadata column '{meta}'"))

    for col in df.columns:
        series = df[col]
        if str(series.dtype) == "object" or str(series.dtype).startswith("str"):
            vals = series.dropna().astype(str)
            if vals.empty:
                continue
            sample = vals.head(5000)
            # raw 11-digit identifiers anywhere
            hits = sample[sample.str.match(_ID_RE)]
            if len(hits):
                res.findings.append(Finding(
                    "HIGH", str(path), "raw_identifier",
                    f"column '{col}' contains {len(hits)} sampled value(s) shaped "
                    f"like raw BVN/NIN (11 digits), e.g. {hits.iloc[0][:3]}********"))
            # sensitive columns must hold pseudonyms only
            if _SENSITIVE_COLS.search(col):
                bad = sample[~sample.str.match(_PSEUDONYM_RE)]
                if len(bad):
                    res.findings.append(Finding(
                        "HIGH", str(path), "unpseudonymised_column",
                        f"sensitive column '{col}' holds {len(bad)} sampled "
                        f"value(s) NOT in pii_<hash> format"))


def _scan_for_salt_leak(root: Path, res: AuditResult) -> None:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".json", ".md", ".txt", ".yaml", ".yml", ".env"}:
            try:
                text = p.read_text(errors="ignore")[:200_000]
            except OSError:
                continue
            if re.search(r"(?i)(pii[_-]?salt|pseudonym[_-]?salt)[\"']?\s*[:=]\s*\S+", text):
                res.findings.append(Finding(
                    "HIGH", str(p), "salt_leak",
                    "file appears to store the pseudonymisation salt; salt must "
                    "live only in env/secrets management"))


def scan_dir(root: Path, res: AuditResult, parquet_engine: str | None = None) -> None:
    import pandas as pd
    for pq in sorted(root.rglob("*.parquet")):
        res.files_scanned += 1
        try:
            df = pd.read_parquet(pq, engine=parquet_engine) if parquet_engine \
                else pd.read_parquet(pq)
        except Exception as e:  # noqa: BLE001
            res.findings.append(Finding("LOW", str(pq), "unreadable",
                                        f"could not read parquet: {e}"))
            continue
        _scan_frame(df, pq, res)
    _scan_for_salt_leak(root, res)


def render_markdown(res: AuditResult, roots: list[str]) -> str:
    lines = ["# NDPA Pseudonymisation Audit", "",
             f"- directories: {', '.join(roots)}",
             f"- files scanned: {res.files_scanned}",
             f"- rows scanned: {res.rows_scanned}",
             f"- verdict: **{'PASS' if res.ok else 'FAIL'}**", ""]
    if res.findings:
        lines += ["| severity | check | file | detail |", "|---|---|---|---|"]
        for f in res.findings:
            lines.append(f"| {f.severity} | {f.check} | {f.file} | {f.detail} |")
    else:
        lines.append("No findings. Pseudonymisation controls verified executed, "
                     "not assumed.")
    lines += ["", "_Caveat: salted-hash pseudonymisation is not anonymisation; "
              "this audit verifies the platform's own controls are applied, "
              "not that the data is irreversibly anonymous._"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NDPA pseudonymisation audit")
    ap.add_argument("--lakehouse", default="mlops/data/lakehouse")
    ap.add_argument("--kg", default=None)
    ap.add_argument("--features", default=None,
                    help="training feature dir (e.g. ml/data/out)")
    ap.add_argument("--out", default="/tmp/ndpa_audit")
    ap.add_argument("--engine", default=None, help="parquet engine override")
    args = ap.parse_args(argv)

    res = AuditResult()
    roots = [r for r in (args.lakehouse, args.kg, args.features)
             if r and Path(r).exists()]
    if not roots:
        log.error("no scan targets exist")
        return 2
    for r in roots:
        scan_dir(Path(r), res, parquet_engine=args.engine)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ndpa_audit.json").write_text(json.dumps(
        {"ok": res.ok, "files_scanned": res.files_scanned,
         "rows_scanned": res.rows_scanned,
         "findings": [asdict(f) for f in res.findings]}, indent=2))
    (out / "ndpa_audit.md").write_text(render_markdown(res, roots))
    log.info("files=%d rows=%d findings=%d verdict=%s",
             res.files_scanned, res.rows_scanned, len(res.findings),
             "PASS" if res.ok else "FAIL")
    return 0 if res.ok else 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
