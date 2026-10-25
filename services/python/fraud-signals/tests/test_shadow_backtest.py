"""Shadow-mode endpoints + backtest harness tests."""
from __future__ import annotations

import json
import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backtest  # noqa: E402
from main import app  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "fixtures", "backtest_cases.jsonl")


class TestShadowMode:
    def test_shadow_eval_audited_but_event_not_recorded(self, fresh_store):
        client = TestClient(app)
        r = client.post("/api/v1/signals/shadow/app_scam", json={
            "subject_id": "acct-shadow",
            "payload": {"payee_is_new": True, "payee_age_hours": 0.2,
                        "session_seconds": 10}})
        assert r.status_code == 200
        body = r.json()
        assert body["mode"] == "shadow"
        assert body["audit"] == "ok"

        # the eval row is tagged shadow
        rows = fresh_store.query(
            "SELECT mode FROM signal_evals WHERE subject_id = :s",
            {"s": "acct-shadow"})
        assert rows and all(r["mode"] == "shadow" for r in rows)
        # the triggering event was NOT recorded (history stays clean)
        events = fresh_store.query(
            "SELECT id FROM signal_events WHERE subject_id = :s",
            {"s": "acct-shadow"})
        assert events == []

    def test_enforce_eval_still_records_event(self, fresh_store):
        client = TestClient(app)
        client.post("/api/v1/signals/app_scam", json={
            "subject_id": "acct-enf", "payload": {"payee_is_new": True}})
        modes = [r["mode"] for r in fresh_store.query(
            "SELECT mode FROM signal_evals WHERE subject_id = :s",
            {"s": "acct-enf"})]
        assert modes == ["enforce"]
        assert fresh_store.query(
            "SELECT id FROM signal_events WHERE subject_id = :s",
            {"s": "acct-enf"})

    def test_score_distribution_endpoint_separates_modes(self, fresh_store):
        client = TestClient(app)
        for sub in ("s1", "s2"):
            client.post("/api/v1/signals/shadow/mule", json={
                "subject_id": sub, "payload": {}, "record_event": False})
        client.post("/api/v1/signals/mule", json={
            "subject_id": "e1", "payload": {}, "record_event": False})
        shadow = client.get("/api/v1/signals/scores/mule").json()
        enforce = client.get("/api/v1/signals/scores/mule?mode=enforce").json()
        assert shadow["count"] == 2 and enforce["count"] == 1

    def test_shadow_chain_still_verifies(self, fresh_store):
        client = TestClient(app)
        client.post("/api/v1/signals/shadow/agent", json={
            "subject_id": "a1", "payload": {}})
        client.post("/api/v1/signals/agent", json={
            "subject_id": "a2", "payload": {}})
        chain = client.get("/api/v1/signals/chain/agent").json()
        assert chain["valid"] is True and chain["entries"] == 2


class TestBacktestHarness:
    def test_fixture_metrics_are_honest(self):
        with open(FIXTURE) as fh:
            cases = [json.loads(line) for line in fh if line.strip()]
        report = backtest.backtest(cases)
        assert report["overall"]["cases"] == 32
        assert report["skipped_cases"] == 0
        # every detector has both fraud and legit coverage
        for name, d in report["detectors"].items():
            assert d["fraud"] >= 1 and d["legit"] >= 1, name
        # review band catches all labeled fraud on this fixture
        assert report["overall"]["review_band"]["recall"] == 1.0
        # block band recall is reported, not rounded into looking perfect
        assert 0.0 < report["overall"]["block_band"]["recall"] <= 1.0

    def test_unknown_detectors_are_counted_not_crashing(self):
        report = backtest.backtest([
            {"detector": "nope", "label": "fraud", "payload": {}},
            {"detector": "mule", "label": "maybe", "payload": {}},
        ])
        assert report["skipped_cases"] == 2
        assert report["overall"]["cases"] == 0

    def test_render_text_runs(self):
        with open(FIXTURE) as fh:
            cases = [json.loads(line) for line in fh if line.strip()]
        text = backtest.render_text(backtest.backtest(cases))
        assert "OVERALL" in text and "precision" in text
