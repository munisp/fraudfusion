"""Tests for drift-triggered retraining (mlops/monitor/drift_trigger.py).

Uses fixture drift-status JSON files (the same shape mlops/monitoring/drift.py
writes via --output) and a fake runner; no real retrain is executed.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TRIGGER_PATH = REPO / "mlops" / "monitor" / "drift_trigger.py"

spec = importlib.util.spec_from_file_location("drift_trigger", TRIGGER_PATH)
drift_trigger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drift_trigger)

HOUR = 3600.0


def write_status(tmp_path: Path, status: str, name: str = "status.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps({
        "status": status,
        "alerts": ([{"feature": "log_amount", "kind": "feature_drift",
                     "psi": 0.4, "ks": 0.2, "status": "alert"}]
                   if status == "alert" else []),
        "features": {"log_amount": {"psi": 0.4 if status == "alert" else 0.01,
                                    "ks": 0.2 if status == "alert" else 0.01,
                                    "status": status}},
    }))
    return p


class FakeRunner:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.calls: list = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)

        class R:
            pass
        r = R()
        r.returncode = self.returncode
        r.stderr = "boom" if self.returncode else ""
        return r


@pytest.fixture()
def paths(tmp_path):
    return {
        "state_file": tmp_path / "state.json",
        "lock_file": tmp_path / "trigger.lock",
        "metric_file": tmp_path / "retrain.prom",
        "retrain_cmd": ["/bin/true"],
    }


def test_single_alert_does_not_trigger(tmp_path, paths):
    status = write_status(tmp_path, "alert")
    runner = FakeRunner()
    d = drift_trigger.check_and_maybe_trigger(
        status, now=1_000_000.0, runner=runner, **paths)
    assert d["action"] == "none"
    assert d["consecutive_alerts"] == 1
    assert runner.calls == []


def test_two_consecutive_alerts_trigger_retrain(tmp_path, paths):
    status = write_status(tmp_path, "alert")
    runner = FakeRunner()
    t0 = 1_000_000.0
    drift_trigger.check_and_maybe_trigger(status, now=t0, runner=runner,
                                          **paths)
    d = drift_trigger.check_and_maybe_trigger(status, now=t0 + HOUR,
                                              runner=runner, **paths)
    assert d["action"] == "retrain"
    assert runner.calls == [paths["retrain_cmd"]]
    # metric textfile emitted
    text = paths["metric_file"].read_text()
    assert "fraudfusion_drift_retrain_total 1" in text
    # state persisted: counter reset, timestamp recorded
    state = json.loads(paths["state_file"].read_text())
    assert state["last_retrain_ts"] == t0 + HOUR
    assert state["consecutive_alerts"] == 0
    assert state["retrain_total"] == 1


def test_cooldown_blocks_immediate_retrigger(tmp_path, paths):
    status = write_status(tmp_path, "alert")
    runner = FakeRunner()
    t0 = 1_000_000.0
    for i in range(2):  # triggers at second alert
        drift_trigger.check_and_maybe_trigger(status, now=t0 + i * HOUR,
                                              runner=runner, **paths)
    assert len(runner.calls) == 1
    # two more alerts within cooldown -> no second retrain
    for i in (2, 3):
        d = drift_trigger.check_and_maybe_trigger(
            status, now=t0 + i * HOUR, runner=runner, **paths)
    assert d["action"] == "none"
    assert "cooldown" in d["reason"]
    assert len(runner.calls) == 1
    # after cooldown (24h) the sustained alert retriggers
    d = drift_trigger.check_and_maybe_trigger(status, now=t0 + 25 * HOUR,
                                              runner=runner, **paths)
    assert d["action"] == "retrain"
    assert len(runner.calls) == 2
    assert "fraudfusion_drift_retrain_total 2" in \
        paths["metric_file"].read_text()


def test_ok_status_resets_consecutive_counter(tmp_path, paths):
    alert = write_status(tmp_path, "alert")
    ok = write_status(tmp_path, "ok", name="ok.json")
    runner = FakeRunner()
    t0 = 1_000_000.0
    drift_trigger.check_and_maybe_trigger(alert, now=t0, runner=runner,
                                          **paths)
    drift_trigger.check_and_maybe_trigger(ok, now=t0 + HOUR, runner=runner,
                                          **paths)
    state = json.loads(paths["state_file"].read_text())
    assert state["consecutive_alerts"] == 0
    # next alert starts the count from 1 again — still no trigger
    d = drift_trigger.check_and_maybe_trigger(alert, now=t0 + 2 * HOUR,
                                              runner=runner, **paths)
    assert d["action"] == "none"
    assert runner.calls == []


def test_lock_file_makes_trigger_idempotent(tmp_path, paths):
    status = write_status(tmp_path, "alert")
    runner = FakeRunner()
    t0 = 1_000_000.0
    drift_trigger.check_and_maybe_trigger(status, now=t0, runner=runner,
                                          **paths)
    paths["lock_file"].write_text("{}")  # simulate a concurrent retrain
    d = drift_trigger.check_and_maybe_trigger(status, now=t0 + HOUR,
                                              runner=runner, **paths)
    assert d["action"] == "none"
    assert "lock" in d["reason"]
    assert runner.calls == []
    assert not paths["metric_file"].exists()  # no metric emitted


def test_failed_retrain_does_not_set_cooldown(tmp_path, paths):
    status = write_status(tmp_path, "alert")
    runner = FakeRunner(returncode=1)
    t0 = 1_000_000.0
    drift_trigger.check_and_maybe_trigger(status, now=t0, runner=runner,
                                          **paths)
    d = drift_trigger.check_and_maybe_trigger(status, now=t0 + HOUR,
                                              runner=runner, **paths)
    assert d["action"] == "retrain_failed"
    state = json.loads(paths["state_file"].read_text())
    assert state["last_retrain_ts"] == 0.0  # cooldown NOT armed on failure
    assert state["retrain_total"] == 0
    assert not paths["metric_file"].exists()
    # a retry on the next alert is allowed (no cooldown was armed)
    d = drift_trigger.check_and_maybe_trigger(status, now=t0 + 2 * HOUR,
                                              runner=runner, **paths)
    assert d["action"] == "retrain_failed"
    assert len(runner.calls) == 2
