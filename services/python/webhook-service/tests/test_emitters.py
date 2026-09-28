"""Emitter contract tests (no-op / fired) for the per-service emitters.

Both emitter modules are loaded by path (they are deliberately duplicated
~40-line modules; the repo has no shared python package convention) and
exercised against an httpx.MockTransport intake.

Run: python3 -m pytest tests/test_emitters.py -q
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[4]
EMITTER_PATHS = [
    REPO / "services/python/onboarding-service/app/webhook_emitter.py",
    REPO / "services/python/identity-theft-detector/webhook_emitter.py",
]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=EMITTER_PATHS, ids=[p.parents[1].name for p in EMITTER_PATHS])
def emitter(request):
    return _load(request.param, f"emitter_{request.param.parents[1].name}")


def test_noop_when_url_unset(emitter, monkeypatch, caplog):
    monkeypatch.delenv("WEBHOOK_SERVICE_URL", raising=False)
    with caplog.at_level("DEBUG"):
        assert emitter.emit_event("kyb.verification.completed", "default", {}) is False
    assert "WEBHOOK_SERVICE_URL unset" in caplog.text


def test_fired_posts_envelope_with_internal_token(emitter, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SERVICE_URL", "http://webhook-svc:8088/")
    monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", "tok-123")
    captured = {}

    def intake(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["token"] = request.headers.get("X-Internal-Token")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"status": "accepted"})

    ok = emitter.emit_event("identity.exposure.detected", "tenant-7",
                            {"alert_id": "exp-1"},
                            transport=httpx.MockTransport(intake))
    assert ok is True
    assert captured["path"] == "/internal/events"
    assert captured["token"] == "tok-123"
    env = captured["body"]
    assert set(env) == {"id", "type", "created_at", "tenant_id", "data"}
    assert env["id"].startswith("evt_")
    assert env["type"] == "identity.exposure.detected"
    assert isinstance(env["created_at"], int)
    assert env["tenant_id"] == "tenant-7"
    assert env["data"] == {"alert_id": "exp-1"}


def test_never_raises_on_error_status_or_unreachable(emitter, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SERVICE_URL", "http://webhook-svc:8088")
    monkeypatch.setenv("WEBHOOK_INTERNAL_TOKEN", "tok")
    assert emitter.emit_event(
        "x.y", "default", {},
        transport=httpx.MockTransport(lambda r: httpx.Response(503))) is False

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    assert emitter.emit_event("x.y", "default", {},
                              transport=httpx.MockTransport(boom)) is False
