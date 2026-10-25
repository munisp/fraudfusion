"""Shared test environment for kyc-api.

The doc-verification pipeline's PaddleOCR backend is heavy (paddlex models
need >1GB RAM) and optional. Tests assert the *honest unavailable* behavior
when no OCR backend is configured, so the default battery pins it off; the
live backend is covered in doc-verification's opt-in probe
(PADDLEOCR_LIVE_TEST=1).
"""

import os

os.environ.setdefault("PADDLEOCR_ENABLED", "false")

# --- embedded PostgreSQL bootstrap (Postgres-only platform) ---------------
import sys as _sys

_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "..", "integration"))
from embedded_pg import fresh_database  # noqa: E402

os.environ["DATABASE_URL"] = fresh_database("kycenv")
