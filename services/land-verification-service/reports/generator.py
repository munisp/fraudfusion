"""
Verification report generator.

Produces a PDF report via reportlab when installed; otherwise falls back to a
small built-in PDF writer so the service never hard-depends on reportlab.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

OUTPUT_DIR = Path(os.getenv("LAND_VERIFY_REPORT_DIR", str(Path(__file__).resolve().parent / "output")))

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas as rl_canvas

    HAS_REPORTLAB = True
except ImportError:  # pragma: no cover - depends on environment
    HAS_REPORTLAB = False


def _flatten(data: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for key, value in data.items():
        label = f"{prefix}{key}".replace("_", " ")
        if isinstance(value, dict):
            rows.extend(_flatten(value, f"{label}."))
        else:
            rows.append((label, str(value)))
    return rows


def _report_lines(result: dict[str, Any]) -> list[str]:
    lines = [
        "FraudFusion - Land Document Verification Report",
        f"Generated: {datetime.utcnow().isoformat()}Z",
        "",
        f"Verification ID: {result.get('verification_id', '-')}",
        f"Status: {result.get('status', '-')}",
        f"Document type: {result.get('document_type', '-')}",
        f"OCR confidence: {result.get('ocr_confidence', '-')}",
        f"Processing time: {result.get('processing_time_seconds', '-')} s",
        "",
    ]
    for section in (
        "extracted_data",
        "registry_verification",
        "cac_verification",
        "surveyor_verification",
        "coordinate_verification",
        "fraud_detection",
    ):
        value = result.get(section)
        if value:
            lines.append(section.replace("_", " ").title())
            if isinstance(value, dict):
                for label, row in _flatten(value, "  "):
                    lines.append(f"  {label}: {row}")
            else:
                lines.append(f"  {value}")
            lines.append("")
    return lines


def _write_pdf_reportlab(path: Path, lines: list[str]) -> None:
    c = rl_canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    y = height - 20 * mm
    c.setFont("Helvetica-Bold", 14)
    first = True
    for line in lines:
        if y < 20 * mm:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 20 * mm
        if first:
            c.drawString(15 * mm, y, line)
            c.setFont("Helvetica", 10)
            first = False
        else:
            c.drawString(15 * mm, y, line[:110])
        y -= 6 * mm
    c.save()


def _write_pdf_fallback(path: Path, lines: list[str]) -> None:
    """Minimal, valid single-font PDF writer (used when reportlab is absent)."""

    def esc(text: str) -> str:
        return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

    pages: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        current.append(line)
        if len(current) >= 45:
            pages.append(current)
            current = []
    if current or not pages:
        pages.append(current)

    objects: list[bytes] = []
    kids = " ".join(f"{3 + i} 0 R" for i in range(len(pages)))
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())

    content_ids = []
    for i, page_lines in enumerate(pages):
        content_id = 3 + len(pages) + i
        content_ids.append(content_id)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {3 + 2 * len(pages)} 0 R >> >> "
            f"/Contents {content_id} 0 R >>".encode()
        )
    for i, page_lines in enumerate(pages):
        stream_lines = ["BT", "/F1 10 Tf", "14 TL", "40 800 Td"]
        for line in page_lines:
            stream_lines.append(f"({esc(line[:110])}) Tj")
            stream_lines.append("T*")
        stream_lines.append("ET")
        stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
        )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    path.write_bytes(bytes(out))


class ReportGenerator:
    def __init__(self, output_dir: Path = OUTPUT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, result: dict[str, Any], filename: str) -> Path:
        """Generate a PDF report for a verification result dict.

        Safe against path traversal: only the basename is used.
        """
        safe_name = Path(filename).name
        if not safe_name.endswith(".pdf"):
            safe_name += ".pdf"
        path = self.output_dir / safe_name
        lines = _report_lines(result)
        if HAS_REPORTLAB:
            _write_pdf_reportlab(path, lines)
        else:  # pragma: no cover - depends on environment
            _write_pdf_fallback(path, lines)
        return path


_generator: Optional[ReportGenerator] = None


def get_generator() -> ReportGenerator:
    global _generator
    if _generator is None:
        _generator = ReportGenerator()
    return _generator
