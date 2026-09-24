"""
Ransomware-pattern detector with automatic storage lockdown (lane B3 / P2-1).

Watches storage/audit operation streams for wipe/encryption patterns and, on
trigger, flips storage into read-only lockdown plus emits alerts.

Signals (sliding windows, per principal and global):
  * delete-request rate            (DELETE_RATE_ALERT_PER_MIN / DELETE_RATE_LOCKDOWN_PER_MIN)
  * overwrite rate (PUT on existing key) (OVERWRITE_RATE_LOCKDOWN_PER_MIN)
  * Shannon-entropy spike of uploaded content (ENTROPY_MEAN_THRESHOLD — encrypted
    blobs are near-random, ~8 bits/byte)
  * mass extension change (rename/rewrite with new extension)

Actions on lockdown:
  * set STORAGE_READ_ONLY=true in the shared lockdown state file/env consumed
    by storage_gateway.StorageGateway._assert_writable and the Rust gateway
  * emit Prometheus metrics (storage_lockdown_active gauge, trigger counters)
  * POST a webhook alert (Alertmanager-compatible)
  * emit a CRITICAL AuditEventType.SECURITY_EVENT into the keyed audit chain

Lockdown clear requires dual control (two distinct principals), recorded in a
lockdown_clearances ledger.
"""

import json
import logging
import math
import os
import threading
import time
import urllib.request
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). Encrypted/compressed data ~> 7.5."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


@dataclass
class GuardConfig:
    delete_rate_alert_per_min: int = 20
    delete_rate_lockdown_per_min: int = 100
    overwrite_rate_lockdown_per_min: int = 200
    entropy_mean_threshold: float = 7.5
    entropy_spike_min_uploads: int = 10  # need a burst of high-entropy uploads
    window_seconds: int = 60
    lockdown_state_path: str = ""       # file flipped to {"read_only": true}
    webhook_url: str = ""               # Alertmanager-compatible POST target
    metrics_path: str = ""              # Prometheus textfile collector target

    @classmethod
    def from_env(cls) -> "GuardConfig":
        return cls(
            delete_rate_alert_per_min=int(os.getenv("DELETE_RATE_ALERT_PER_MIN", "20")),
            delete_rate_lockdown_per_min=int(os.getenv("DELETE_RATE_LOCKDOWN_PER_MIN", "100")),
            overwrite_rate_lockdown_per_min=int(os.getenv("OVERWRITE_RATE_LOCKDOWN_PER_MIN", "200")),
            entropy_mean_threshold=float(os.getenv("ENTROPY_MEAN_THRESHOLD", "7.5")),
            window_seconds=int(os.getenv("GUARD_WINDOW_SECONDS", "60")),
            lockdown_state_path=os.getenv(
                "STORAGE_LOCKDOWN_STATE", "/var/lib/fraudfusion/storage/lockdown.json"),
            webhook_url=os.getenv("RANSOMWARE_GUARD_WEBHOOK", ""),
            metrics_path=os.getenv(
                "RANSOMWARE_GUARD_METRICS", "/var/lib/fraudfusion/storage/ransomware_guard.prom"),
        )


@dataclass
class GuardEvent:
    """One observed storage operation."""
    operation: str            # "delete" | "overwrite" | "upload"
    principal: str
    path: str = ""
    content_sample: bytes = b""
    timestamp: float = field(default_factory=time.time)


@dataclass
class LockdownState:
    active: bool = False
    reason: str = ""
    triggered_at: Optional[str] = None
    clearances: List[Dict] = field(default_factory=list)


class RansomwareGuard:
    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        audit_emit: Optional[Callable[[str, dict], None]] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config or GuardConfig.from_env()
        self._clock = clock
        self._lock = threading.Lock()
        self._deletes: Deque[GuardEvent] = deque()
        self._overwrites: Deque[GuardEvent] = deque()
        self._high_entropy_uploads: Deque[GuardEvent] = deque()
        self._extension_changes: Deque[GuardEvent] = deque()
        self.state = LockdownState()
        self._audit_emit = audit_emit or self._default_audit_emit
        self._metrics = {
            "delete_events_total": 0,
            "overwrite_events_total": 0,
            "entropy_spike_uploads_total": 0,
            "alerts_total": 0,
            "lockdowns_total": 0,
        }

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    def observe(self, event: GuardEvent) -> Optional[str]:
        """Feed one storage operation. Returns 'alert' | 'lockdown' | None."""
        with self._lock:
            if self.state.active:
                return None  # already locked down; stay quiet
            self._prune()

            if event.operation == "delete":
                self._deletes.append(event)
                self._metrics["delete_events_total"] += 1
            elif event.operation == "overwrite":
                self._overwrites.append(event)
                self._metrics["overwrite_events_total"] += 1
                if self._extension_changed(event):
                    self._extension_changes.append(event)
            elif event.operation == "upload":
                if event.content_sample and \
                        shannon_entropy(event.content_sample) >= self.config.entropy_mean_threshold:
                    self._high_entropy_uploads.append(event)
                    self._metrics["entropy_spike_uploads_total"] += 1

            signal = self._evaluate()
            if signal == "lockdown":
                self._trigger_lockdown(self._lockdown_reason())
            elif signal == "alert":
                self._emit_alert("ransomware-pattern-alert", self._lockdown_reason(), page=False)
            return signal

    def observe_delete(self, principal: str, path: str = "") -> Optional[str]:
        return self.observe(GuardEvent("delete", principal, path, timestamp=self._clock()))

    def observe_overwrite(self, principal: str, path: str = "") -> Optional[str]:
        return self.observe(GuardEvent("overwrite", principal, path, timestamp=self._clock()))

    def observe_upload(self, principal: str, path: str, content_sample: bytes) -> Optional[str]:
        return self.observe(GuardEvent("upload", principal, path, content_sample,
                                       timestamp=self._clock()))

    @staticmethod
    def _extension_changed(event: GuardEvent) -> bool:
        # path format hint: "old.ext->new.ext" supplied by the storage layer
        return "->" in event.path and \
            event.path.split("->")[0].rsplit(".", 1)[-1] != event.path.split("->")[1].rsplit(".", 1)[-1]

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _prune(self):
        cutoff = self._clock() - self.config.window_seconds
        for dq in (self._deletes, self._overwrites,
                   self._high_entropy_uploads, self._extension_changes):
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()

    def _rates(self) -> Tuple[int, int, int, int]:
        return (len(self._deletes), len(self._overwrites),
                len(self._high_entropy_uploads), len(self._extension_changes))

    def _evaluate(self) -> Optional[str]:
        deletes, overwrites, entropy_hits, ext_changes = self._rates()
        if deletes >= self.config.delete_rate_lockdown_per_min:
            return "lockdown"
        if overwrites >= self.config.overwrite_rate_lockdown_per_min:
            return "lockdown"
        if entropy_hits >= self.config.entropy_spike_min_uploads:
            return "lockdown"
        if ext_changes >= self.config.delete_rate_lockdown_per_min:
            return "lockdown"
        if deletes >= self.config.delete_rate_alert_per_min:
            return "alert"
        return None

    def _lockdown_reason(self) -> str:
        deletes, overwrites, entropy_hits, ext_changes = self._rates()
        parts = []
        if deletes >= self.config.delete_rate_alert_per_min:
            parts.append(f"delete_rate={deletes}/min")
        if overwrites >= self.config.overwrite_rate_lockdown_per_min // 2:
            parts.append(f"overwrite_rate={overwrites}/min")
        if entropy_hits:
            parts.append(f"high_entropy_uploads={entropy_hits}/min")
        if ext_changes:
            parts.append(f"extension_changes={ext_changes}/min")
        return ", ".join(parts) or "anomalous destructive activity"

    # ------------------------------------------------------------------
    # Lockdown
    # ------------------------------------------------------------------

    def _trigger_lockdown(self, reason: str):
        self.state = LockdownState(
            active=True, reason=reason,
            triggered_at=datetime.utcnow().isoformat() + "Z",
        )
        self._metrics["lockdowns_total"] += 1
        self._write_lockdown_file(read_only=True)
        self._emit_alert("ransomware-lockdown", reason, page=True)
        self._audit_emit("ransomware_lockdown", {
            "reason": reason,
            "window_seconds": self.config.window_seconds,
        })
        logger.critical("STORAGE LOCKDOWN ENGAGED: %s", reason)

    def clear_lockdown(self, principal_a: str, principal_b: str, reason: str) -> bool:
        """Dual-control clear: two distinct principals required."""
        if not self.state.active:
            return False
        if not principal_a or not principal_b or principal_a == principal_b:
            raise PermissionError(
                "lockdown clear requires two distinct principals (dual control)"
            )
        clearance = {
            "clearance_id": str(uuid.uuid4()),
            "principals": sorted([principal_a, principal_b]),
            "reason": reason,
            "cleared_at": datetime.utcnow().isoformat() + "Z",
        }
        self.state.clearances.append(clearance)
        self._persist_clearance(clearance)
        self.state.active = False
        self._write_lockdown_file(read_only=False)
        self._audit_emit("ransomware_lockdown_cleared", clearance)
        logger.warning("Storage lockdown cleared by %s + %s", principal_a, principal_b)
        return True

    def is_locked_down(self) -> bool:
        return self.state.active

    # ------------------------------------------------------------------
    # Outputs
    # ------------------------------------------------------------------

    def _write_lockdown_file(self, read_only: bool):
        """Flip the shared lockdown state file consumed by the storage layer.

        STORAGE_READ_ONLY env is the fast path for single-process deployments;
        this JSON file is the cross-process contract (the storage gateway and
        Rust gateway poll it).
        """
        path = Path(self.config.lockdown_state_path)
        if not str(path):
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "read_only": read_only,
                "reason": self.state.reason,
                "updated_at": datetime.utcnow().isoformat() + "Z",
            }
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload))
            os.replace(tmp, path)
        except Exception as e:
            logger.critical("FAILED to write lockdown state file %s: %s", path, e)

    def _persist_clearance(self, clearance: dict):
        path = Path(self.config.lockdown_state_path).with_name("lockdown_clearances.jsonl")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a") as f:
                f.write(json.dumps(clearance) + "\n")
        except Exception as e:
            logger.error("Failed to persist clearance: %s", e)

    def _emit_alert(self, alertname: str, reason: str, page: bool):
        self._metrics["alerts_total"] += 1
        self._write_prometheus_metrics()
        if not self.config.webhook_url:
            logger.warning("alert %s (%s) — no webhook configured", alertname, reason)
            return
        payload = [{
            "labels": {
                "alertname": alertname,
                "severity": "critical" if page else "warning",
                "service": "storage-gateway",
            },
            "annotations": {"summary": reason},
        }]
        try:
            req = urllib.request.Request(
                self.config.webhook_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status >= 400:
                    raise RuntimeError(f"webhook returned {resp.status}")
        except Exception as e:
            logger.critical("ALERT WEBHOOK FAILURE for %s: %s", alertname, e)

    def _write_prometheus_metrics(self):
        path = self.config.metrics_path
        if not path:
            return
        lines = [
            "# HELP storage_lockdown_active Whether storage is in ransomware lockdown",
            "# TYPE storage_lockdown_active gauge",
            f"storage_lockdown_active {1 if self.state.active else 0}",
        ]
        for name, value in self._metrics.items():
            lines.append(f"# TYPE ransomware_guard_{name} counter")
            lines.append(f"ransomware_guard_{name} {value}")
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(path).with_suffix(".tmp")
            tmp.write_text("\n".join(lines) + "\n")
            os.replace(tmp, path)
        except Exception as e:
            logger.error("Failed to write prometheus metrics %s: %s", path, e)

    @staticmethod
    def _default_audit_emit(event_name: str, details: dict):
        try:
            from implementations.security.audit.audit_logger import (
                get_audit_logger, AuditSeverity,
            )
            get_audit_logger().log_security_event(event_name, AuditSeverity.CRITICAL, details)
        except Exception as e:
            logger.critical("guard audit emit failed for %s: %s", event_name, e)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def stats(self) -> Dict:
        deletes, overwrites, entropy_hits, ext_changes = self._rates()
        return {
            "lockdown_active": self.state.active,
            "window_seconds": self.config.window_seconds,
            "delete_rate": deletes,
            "overwrite_rate": overwrites,
            "high_entropy_uploads": entropy_hits,
            "extension_changes": ext_changes,
            **self._metrics,
        }
