"""Shared test environment for kyc-api.

The doc-verification pipeline's PaddleOCR backend is heavy (paddlex models
need >1GB RAM) and optional. Tests assert the *honest unavailable* behavior
when no OCR backend is configured, so the default battery pins it off; the
live backend is covered in doc-verification's opt-in probe
(PADDLEOCR_LIVE_TEST=1).
"""

import os

os.environ.setdefault("PADDLEOCR_ENABLED", "false")
