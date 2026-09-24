"""Tests for the ransomware-pattern detector (simulated bursts).

Run: python3 -m pytest services/python/ransomware_guard/ -q
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from services.python.ransomware_guard import (
    RansomwareGuard,
    GuardConfig,
    GuardEvent,
    shannon_entropy,
)


def make_guard(tmp_path, **overrides):
    cfg = GuardConfig(
        lockdown_state_path=str(tmp_path / "lockdown.json"),
        metrics_path=str(tmp_path / "guard.prom"),
        webhook_url="",  # no webhook in tests
        **overrides,
    )
    emitted = []
    guard = RansomwareGuard(config=cfg,
                            audit_emit=lambda name, details: emitted.append((name, details)))
    guard.emitted = emitted
    return guard


class TestEntropy:
    def test_plaintext_low_entropy(self):
        assert shannon_entropy(b"aaaaaaaaaaaaaaaaaaaa") < 1.0
        assert shannon_entropy(b"hello world, this is a normal document " * 5) < 5.5

    def test_encrypted_blob_high_entropy(self):
        assert shannon_entropy(os.urandom(4096)) > 7.5

    def test_empty(self):
        assert shannon_entropy(b"") == 0.0


class TestDeleteRate:
    def test_below_threshold_no_action(self, tmp_path):
        guard = make_guard(tmp_path)
        for _ in range(19):
            assert guard.observe_delete("svc-a", "bucket/obj") is None
        assert not guard.is_locked_down()

    def test_alert_threshold(self, tmp_path):
        guard = make_guard(tmp_path)
        result = None
        for _ in range(20):
            result = guard.observe_delete("svc-a", "bucket/obj")
        assert result == "alert"
        assert not guard.is_locked_down()

    def test_mass_delete_triggers_lockdown(self, tmp_path):
        guard = make_guard(tmp_path)
        result = None
        for i in range(100):
            result = guard.observe_delete("rogue-insider", f"bucket/obj{i}")
        assert result == "lockdown"
        assert guard.is_locked_down()

        # lockdown state file flipped to read-only
        state = json.loads((tmp_path / "lockdown.json").read_text())
        assert state["read_only"] is True
        assert "delete_rate" in state["reason"]

        # CRITICAL audit event emitted
        assert any(name == "ransomware_lockdown" for name, _ in guard.emitted)

        # prometheus metrics written
        prom = (tmp_path / "guard.prom").read_text()
        assert "storage_lockdown_active 1" in prom
        assert "ransomware_guard_lockdowns_total 1" in prom

    def test_sliding_window_expires(self, tmp_path):
        t = [1000.0]
        cfg = GuardConfig(lockdown_state_path=str(tmp_path / "l.json"),
                          metrics_path="", webhook_url="", window_seconds=60)
        guard = RansomwareGuard(config=cfg, audit_emit=lambda n, d: None,
                                clock=lambda: t[0])
        for i in range(99):
            guard.observe_delete("svc", f"k{i}")
        assert not guard.is_locked_down()
        t[0] += 120  # two minutes later: window emptied
        for i in range(50):
            assert guard.observe_delete("svc", f"kx{i}") != "lockdown"
        assert not guard.is_locked_down()


class TestOverwriteAndEntropy:
    def test_mass_overwrite_triggers_lockdown(self, tmp_path):
        guard = make_guard(tmp_path)
        result = None
        for i in range(200):
            result = guard.observe_overwrite("svc", f"bucket/doc{i}.pdf")
        assert result == "lockdown"

    def test_entropy_spike_triggers_lockdown(self, tmp_path):
        guard = make_guard(tmp_path)
        result = None
        for i in range(10):
            result = guard.observe_upload("svc", f"bucket/doc{i}.pdf", os.urandom(2048))
        assert result == "lockdown"
        state = json.loads((tmp_path / "lockdown.json").read_text())
        assert "high_entropy_uploads" in state["reason"]

    def test_normal_uploads_no_lockdown(self, tmp_path):
        guard = make_guard(tmp_path)
        for i in range(50):
            assert guard.observe_upload("svc", f"doc{i}.txt",
                                        b"ordinary document text " * 20) is None
        assert not guard.is_locked_down()

    def test_mass_extension_change_triggers_lockdown(self, tmp_path):
        guard = make_guard(tmp_path)
        result = None
        for i in range(100):
            result = guard.observe_overwrite("svc", f"bucket/file{i}.pdf->file{i}.locked")
        assert result == "lockdown"


class TestDualControlClear:
    def test_clear_requires_two_distinct_principals(self, tmp_path):
        guard = make_guard(tmp_path)
        for i in range(100):
            guard.observe_delete("rogue", f"k{i}")
        assert guard.is_locked_down()

        with pytest.raises(PermissionError):
            guard.clear_lockdown("alice", "alice", "self-clear attempt")
        assert guard.is_locked_down()

        assert guard.clear_lockdown("alice", "bob", "incident resolved") is True
        assert not guard.is_locked_down()
        state = json.loads((tmp_path / "lockdown.json").read_text())
        assert state["read_only"] is False
        clearances = (tmp_path / "lockdown_clearances.jsonl").read_text().splitlines()
        assert len(clearances) == 1
        record = json.loads(clearances[0])
        assert record["principals"] == ["alice", "bob"]
        assert any(name == "ransomware_lockdown_cleared" for name, _ in guard.emitted)

    def test_no_new_triggers_while_locked(self, tmp_path):
        guard = make_guard(tmp_path)
        for i in range(100):
            guard.observe_delete("rogue", f"k{i}")
        assert guard.is_locked_down()
        assert guard.observe_delete("rogue", "another") is None  # quiet while locked
