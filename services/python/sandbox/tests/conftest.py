"""Shared fixtures for the sandbox test suite.

Run: python3 -m pytest tests/ -q   (from services/python/sandbox)
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

TEST_KEY = "ffk_test_pytest"
AUTH = {"X-API-Key": TEST_KEY}

# 1x1 PNG (valid magic bytes, tiny) — same fixture style as kyc-api tests.
PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)
PDF_BYTES = b"%PDF-1.4 synthetic-sandbox-pdf\n%%EOF\n" + b"0" * 128


@pytest.fixture()
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c
        c.app.state.rate_limiter.reset()
