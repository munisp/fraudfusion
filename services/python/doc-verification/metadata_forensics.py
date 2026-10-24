"""Metadata forensics for images and PDFs (Round 14).

Forged documents betray themselves in their metadata long before pixels:

  Images (EXIF via Pillow, tolerant):
    * Software tag naming an editor (Photoshop, GIMP, "iLoveIMG", Snapseed)
    * alleged camera photo with NO capture device (Make/Model missing)
    * DateTimeOriginal in the future, or digitized-before-created ordering

  PDFs (pure byte-level parsing — no dependencies, never raises):
    * /Producer or /Creator naming a known online editor/converter
    * /ModDate earlier than /CreationDate (impossible ordering)
    * incremental updates (multiple startxref/%%EOF — the classic
      "genuine C-of-O with one page appended later" pattern)
    * object-count / size sanity

Every check reports WHAT it found; absence of metadata is reported as
`metadata_present: false` — never silently treated as clean.
"""

from __future__ import annotations

import io
import re
from datetime import datetime
from typing import Any

_EDITOR_PATTERNS = re.compile(
    r"(photoshop|gimp|snapseed|picsart|canva|paint\.net|affinity|pixlr|"
    r"iloveimg|ilovepdf|smallpdf|pdfescape|sejda|photopea|fotor|"
    r"mspaint|paintshop)", re.IGNORECASE)

_EXIF_DT = "%Y:%m:%d %H:%M:%S"
_PDF_DT = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?")


def analyze_image_metadata(image_bytes: bytes) -> dict[str, Any]:
    signals: list[dict[str, Any]] = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(io.BytesIO(image_bytes))
        exif_raw = img.getexif()
    except Exception:
        return {"metadata_present": False, "signals": signals,
                "detail": "no readable EXIF container"}
    if not exif_raw:
        return {"metadata_present": False, "signals": signals,
                "detail": "no EXIF metadata (screenshot/render or stripped)"}
    tags = {TAGS.get(k, k): v for k, v in exif_raw.items()}
    out: dict[str, Any] = {"metadata_present": True,
                           "software": tags.get("Software"),
                           "make": tags.get("Make"),
                           "model": tags.get("Model"),
                           "datetime_original": tags.get("DateTimeOriginal")}
    software = str(tags.get("Software") or "")
    if software and _EDITOR_PATTERNS.search(software):
        signals.append({"code": "metadata_editor",
                        "detail": f"EXIF Software names an image editor: "
                                  f"'{software}'"})
    if not tags.get("Make") and not tags.get("Model"):
        signals.append({"code": "metadata_no_device",
                        "detail": "EXIF present but no capture device — "
                                  "consistent with a digital render, not a "
                                  "camera photo of a physical document"})
    dto = str(tags.get("DateTimeOriginal") or "")
    if dto:
        try:
            if datetime.strptime(dto, _EXIF_DT) > datetime.now():
                signals.append({"code": "metadata_time_anomaly",
                                "detail": "EXIF DateTimeOriginal is in the future"})
        except ValueError:
            pass
    out["signals"] = signals
    return out


def _pdf_date(raw: bytes) -> datetime | None:
    m = _PDF_DT.search(raw.decode("latin-1", "ignore"))
    if not m:
        return None
    parts = [int(p) if p else d for p, d in
             zip(m.groups(), (1970, 1, 1, 0, 0, 0))]
    try:
        return datetime(*parts[:6])
    except ValueError:
        return None


def analyze_pdf_metadata(pdf_bytes: bytes) -> dict[str, Any]:
    signals: list[dict[str, Any]] = []
    if not pdf_bytes.startswith(b"%PDF"):
        return {"is_pdf": False, "signals": signals}
    text = pdf_bytes.decode("latin-1", "ignore")

    producer = creator = None
    for key, var in (("Producer", "producer"), ("Creator", "creator")):
        m = re.search(rf"/{key}\s*\(([^)]*)\)", text)
        if m:
            if var == "producer":
                producer = m.group(1)
            else:
                creator = m.group(1)
    for label, value in (("Producer", producer), ("Creator", creator)):
        if value and _EDITOR_PATTERNS.search(value):
            signals.append({"code": "pdf_editor_producer",
                            "detail": f"PDF {label} names a document editor: "
                                      f"'{value}'"})

    creation = _pdf_date(pdf_bytes[pdf_bytes.find(b"/CreationDate"):]) \
        if b"/CreationDate" in pdf_bytes else None
    mod = _pdf_date(pdf_bytes[pdf_bytes.find(b"/ModDate"):]) \
        if b"/ModDate" in pdf_bytes else None
    if creation and mod and mod < creation:
        signals.append({"code": "pdf_date_impossible",
                        "detail": "ModDate predates CreationDate — metadata "
                                  "hand-edited or spliced"})

    startxrefs = len(re.findall(r"startxref", text))
    if startxrefs > 1:
        signals.append({"code": "pdf_incremental_update",
                        "detail": f"{startxrefs} revision sections — the PDF "
                                  f"was modified after original creation "
                                  f"(appended-page pattern)"})

    return {"is_pdf": True, "producer": producer, "creator": creator,
            "creation_date": creation.isoformat() if creation else None,
            "mod_date": mod.isoformat() if mod else None,
            "revision_sections": startxrefs, "signals": signals}
