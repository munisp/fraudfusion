"""Drift-triggered retraining for fraud_net.

Retraining was previously cron-only (mlops/cron/retrain.sh). This trigger
closes the loop: it reads the latest drift status emitted by the drift
monitor (mlops/monitoring/drift.py --output <status.json>, which reports
PSI/KS per feature plus an overall "status": ok|warn|alert), and when the
status has been "alert" for >= CONSECUTIVE_ALERTS_REQUIRED consecutive
checks it invokes the *same* retrain pipeline as cron
(mlops/cron/retrain.sh) via subprocess.

Safety properties:
- Idempotent: an O_EXCL lock file prevents concurrent retrains; a 24h
  cooldown prevents alert-flapping from retraining in a loop.
- Observable: emits a Prometheus textfile metric
  ``fraudfusion_drift_retrain_total`` (node_exporter textfile collector).
- Never silent: every decision is logged and reflected in the state file.

Usage:
    python mlops/monitor/drift_trigger.py \
        --status-file mlops/data/drift_status.json

Typical cron pairing (after the drift check):
    python mlops/monitoring/drift.py --reference ... --current ... \
        --output mlops/data/drift_status.json
    python mlops/monitor/drift_trigger.py

Env overrides: DRIFT_STATUS_FILE, DRIFT_TRIGGER_STATE_FILE,
DRIFT_TRIGGER_LOCK_FILE, DRIFT_RETRAIN_METRIC_FILE, RETRAIN_CMD,
DRIFT_RETRAIN_COOLDOWN_S, DRIFT_ALERTS_REQUIRED.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [drift-trigger] %(message)s")
logger = logging.getLogger("drift-trigger")

REPO_ROOT = Path(__file__).resolve().parents[2]

CONSECUTIVE_ALERTS_REQUIRED = int(os.getenv("DRIFT_ALERTS_REQUIRED", "2"))
COOLDOWN_S = float(os.getenv("DRIFT_RETRAIN_COOLDOWN_S", str(24 * 3600)))
DEFAULT_STATUS_FILE = os.getenv("DRIFT_STATUS_FILE",
                                str(REPO_ROOT / "mlops" / "data" / "drift_status.json"))
DEFAULT_STATE_FILE = os.getenv(
    "DRIFT_TRIGGER_STATE_FILE",
    str(REPO_ROOT / "mlops" / "monitor" / "drift_trigger_state.json"))
DEFAULT_LOCK_FILE = os.getenv(
    "DRIFT_TRIGGER_LOCK_FILE",
    str(REPO_ROOT / "mlops" / "monitor" / "drift_trigger.lock"))
DEFAULT_METRIC_FILE = os.getenv(
    "DRIFT_RETRAIN_METRIC_FILE",
    str(REPO_ROOT / "mlops" / "monitor" / "drift_retrain.prom"))
DEFAULT_RETRAIN_CMD = os.getenv(
    "RETRAIN_CMD", str(REPO_ROOT / "mlops" / "cron" / "retrain.sh"))


# ---------------------------------------------------------------------------
# State / status IO
# ---------------------------------------------------------------------------
def load_status(status_file: str | Path) -> dict[str, Any]:
    """Load the drift monitor's latest JSON report."""
    return json.loads(Path(status_file).read_text())


def read_state(state_file: str | Path) -> dict[str, Any]:
    path = Path(state_file)
    if not path.exists():
        return {"consecutive_alerts": 0, "last_retrain_ts": 0.0,
                "retrain_total": 0}
    try:
        state = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        logger.warning("state file %s unreadable; resetting", path)
        return {"consecutive_alerts": 0, "last_retrain_ts": 0.0,
                "retrain_total": 0}
    state.setdefault("consecutive_alerts", 0)
    state.setdefault("last_retrain_ts", 0.0)
    state.setdefault("retrain_total", 0)
    return state


def write_state(state_file: str | Path, state: dict[str, Any]) -> None:
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(path)  # atomic rename


def write_metric(metric_file: str | Path, retrain_total: int) -> None:
    """Emit the Prometheus textfile metric (atomic write)."""
    path = Path(metric_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (
        "# HELP fraudfusion_drift_retrain_total Retrains triggered by "
        "sustained drift alerts\n"
        "# TYPE fraudfusion_drift_retrain_total counter\n"
        f"fraudfusion_drift_retrain_total {retrain_total}\n"
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------
class LockFile:
    """Idempotent O_EXCL lock; stale locks older than ``stale_after_s`` are
    reclaimed (a crashed retrain must not wedge the trigger forever)."""

    def __init__(self, path: str | Path, stale_after_s: float = 6 * 3600):
        self.path = Path(path)
        self.stale_after_s = stale_after_s
        self.acquired = False

    def __enter__(self) -> "LockFile":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            age = time.time() - self.path.stat().st_mtime
            if age > self.stale_after_s:
                logger.warning("reclaiming stale lock %s (age %.0fs)",
                               self.path, age)
                self.path.unlink()
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            else:
                raise
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"pid": os.getpid(), "ts": time.time()}))
        self.acquired = True
        return self

    def __exit__(self, *exc) -> None:
        if self.acquired:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self.acquired = False


# ---------------------------------------------------------------------------
# Core decision
# ---------------------------------------------------------------------------
def check_and_maybe_trigger(
    status_file: str | Path,
    state_file: str | Path = DEFAULT_STATE_FILE,
    lock_file: str | Path = DEFAULT_LOCK_FILE,
    metric_file: str | Path = DEFAULT_METRIC_FILE,
    retrain_cmd: str | list[str] = DEFAULT_RETRAIN_CMD,
    cooldown_s: float = COOLDOWN_S,
    alerts_required: int = CONSECUTIVE_ALERTS_REQUIRED,
    now: float | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Evaluate the latest drift status; trigger retrain if sustained alert.

    Returns a decision dict (also persisted into the state file under
    ``last_decision``)."""
    now = time.time() if now is None else now
    status = load_status(status_file)
    drift_status = status.get("status", "unknown")
    state = read_state(state_file)

    if drift_status == "alert":
        state["consecutive_alerts"] += 1
    else:
        if state["consecutive_alerts"]:
            logger.info("drift status %r — resetting consecutive alert "
                        "counter (was %d)", drift_status,
                        state["consecutive_alerts"])
        state["consecutive_alerts"] = 0

    decision: dict[str, Any] = {
        "ts": now, "drift_status": drift_status,
        "consecutive_alerts": state["consecutive_alerts"],
        "action": "none", "reason": "below alert threshold",
    }

    if drift_status == "alert":
        n = state["consecutive_alerts"]
        if n < alerts_required:
            decision["reason"] = (f"alert {n}/{alerts_required} consecutive "
                                  "checks — waiting for confirmation")
            logger.info("drift alert %d/%d consecutive; not retraining yet",
                        n, alerts_required)
        elif now - state["last_retrain_ts"] < cooldown_s:
            decision["reason"] = (
                f"cooldown active: last retrain "
                f"{(now - state['last_retrain_ts']) / 3600:.1f}h ago "
                f"(< {cooldown_s / 3600:.0f}h)")
            logger.info("drift alert sustained but retrain cooldown active")
        else:
            try:
                with LockFile(lock_file):
                    cmd = ([retrain_cmd] if isinstance(retrain_cmd, str)
                           else list(retrain_cmd))
                    logger.warning(
                        "SUSTAINED DRIFT ALERT (%d consecutive checks) — "
                        "triggering retrain pipeline: %s", n, cmd)
                    result = runner(cmd, cwd=str(REPO_ROOT),
                                    capture_output=True, text=True)
                    if getattr(result, "returncode", 1) == 0:
                        state["last_retrain_ts"] = now
                        state["retrain_total"] += 1
                        state["consecutive_alerts"] = 0
                        decision["action"] = "retrain"
                        decision["reason"] = "sustained drift alert"
                        write_metric(metric_file, state["retrain_total"])
                        logger.info("retrain pipeline completed; total "
                                    "drift-triggered retrains=%d",
                                    state["retrain_total"])
                    else:
                        decision["action"] = "retrain_failed"
                        decision["reason"] = (
                            f"retrain exited "
                            f"{getattr(result, 'returncode', '?')}: "
                            f"{str(getattr(result, 'stderr', ''))[-500:]}")
                        logger.error("retrain pipeline FAILED: %s",
                                     decision["reason"])
            except FileExistsError:
                decision["reason"] = "another retrain holds the lock"
                logger.info("retrain already in progress (lock %s)", lock_file)

    state["last_decision"] = decision
    write_state(state_file, state)
    return decision


def main(argv=None) -> dict[str, Any]:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--status-file", default=DEFAULT_STATUS_FILE)
    ap.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    ap.add_argument("--lock-file", default=DEFAULT_LOCK_FILE)
    ap.add_argument("--metric-file", default=DEFAULT_METRIC_FILE)
    ap.add_argument("--retrain-cmd", default=DEFAULT_RETRAIN_CMD)
    args = ap.parse_args(argv)
    decision = check_and_maybe_trigger(
        args.status_file, state_file=args.state_file, lock_file=args.lock_file,
        metric_file=args.metric_file, retrain_cmd=args.retrain_cmd)
    print(json.dumps(decision, indent=2))
    return decision


if __name__ == "__main__":
    sys.exit(0)
