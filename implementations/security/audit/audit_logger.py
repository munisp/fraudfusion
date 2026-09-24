"""
Append-Only Audit Logging System

Provides tamper-evident audit logging for:
- All decision events (fraud scores, KYC pass/fail, document verdicts)
- Data access events
- Configuration changes
- User actions
- System events

Features:
- Append-only log files with HMAC-SHA256 keyed cryptographic chaining
  (env ``AUDIT_HMAC_KEY`` or ``AUDIT_HMAC_KEY_URI`` required; fail-closed)
- Cross-segment chain continuity: rotated/day-rolled segments are sealed with a
  signed ``segment_seal`` record and the next segment chains from the previous
  segment root (persisted in ``chain_state.json``) instead of resetting to None
- External anchor hook: every segment seal is shipped to an anchor file
  (``AUDIT_ANCHOR_FILE``) and/or HTTP endpoint (``AUDIT_ANCHOR_ENDPOINT``)
- Log integrity verification (per segment and across the whole chain)
- Structured JSON format
- Retention policy with a regulatory retention floor (never delete regulated
  records younger than ``AUDIT_RETENTION_FLOOR_DAYS``, default 2555 = 7 years)
- Dual-control gated cleanup: ``cleanup_old_logs`` requires a signed,
  single-use approval token plus a sealed+externally-anchored segment
"""

import os
import json
import hmac
import hashlib
import logging
import threading
import gzip
import time
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)

# Event classes whose records are regulated evidence (AML/fraud/KYC) and must
# never be deleted younger than the retention floor (7 years by default).
REGULATED_EVENT_TYPES = frozenset({
    "fraud_detection",
    "kyc_verification",
    "kyb_verification",
    "document_validation",
    "manual_review",
    "override_decision",
    "security_event",
    "data_modification",
})

DEFAULT_RETENTION_FLOOR_DAYS = 2555  # 7 years (AML/BSA record-keeping)


class AuditEventType(Enum):
    FRAUD_DETECTION = "fraud_detection"
    KYC_VERIFICATION = "kyc_verification"
    KYB_VERIFICATION = "kyb_verification"
    DOCUMENT_VALIDATION = "document_validation"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION_CHANGE = "configuration_change"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    API_ACCESS = "api_access"
    PERMISSION_CHANGE = "permission_change"
    MODEL_PREDICTION = "model_prediction"
    MANUAL_REVIEW = "manual_review"
    OVERRIDE_DECISION = "override_decision"
    SYSTEM_EVENT = "system_event"
    SECURITY_EVENT = "security_event"


class AuditSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


def _load_hmac_key(
    hmac_key: Optional[Union[str, bytes]],
    allow_insecure_unkeyed: bool,
) -> Optional[bytes]:
    """Resolve the HMAC key for the audit chain. Fail closed by default.

    Resolution order:
      1. explicit ``hmac_key`` argument (bytes, hex str, or raw str)
      2. ``AUDIT_HMAC_KEY`` environment variable (hex or raw)
      3. ``AUDIT_HMAC_KEY_URI`` environment variable (``file://`` path)

    Raises:
        RuntimeError: if no key is configured and ``allow_insecure_unkeyed``
            is not explicitly True.
    """
    key: Optional[Union[str, bytes]] = hmac_key
    if key is None:
        env_key = os.getenv("AUDIT_HMAC_KEY", "").strip()
        if env_key:
            key = env_key
    if key is None:
        key_uri = os.getenv("AUDIT_HMAC_KEY_URI", "").strip()
        if key_uri:
            if not key_uri.startswith("file://"):
                raise RuntimeError(
                    "AUDIT_HMAC_KEY_URI only supports file:// URIs in this "
                    "runtime; fetch KMS/Vault material out-of-band and expose "
                    "it via a tmpfs file"
                )
            key_path = Path(key_uri[len("file://"):])
            if not key_path.exists():
                raise RuntimeError(f"AUDIT_HMAC_KEY_URI points at missing file: {key_path}")
            key = key_path.read_bytes().strip()

    if key is None:
        if allow_insecure_unkeyed:
            logger.critical(
                "AuditLogger running WITHOUT an HMAC key (allow_insecure_unkeyed=True). "
                "The audit chain is NOT tamper-evident against on-host attackers. "
                "Never use this outside local development/tests."
            )
            return None
        raise RuntimeError(
            "AUDIT_HMAC_KEY (or AUDIT_HMAC_KEY_URI) must be configured; "
            "the audit logger fails closed rather than writing an unkeyed, "
            "forgeable chain"
        )

    if isinstance(key, str):
        try:
            return bytes.fromhex(key)
        except ValueError:
            return key.encode("utf-8")
    return bytes(key)


@dataclass
class AuditEvent:
    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime

    actor_id: Optional[str] = None
    actor_type: Optional[str] = None
    actor_ip: Optional[str] = None

    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    journey_id: Optional[str] = None

    resource_type: Optional[str] = None
    resource_id: Optional[str] = None

    action: str = ""
    outcome: str = ""

    details: Dict[str, Any] = field(default_factory=dict)

    previous_hash: Optional[str] = None
    event_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "event",
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "actor_ip": self.actor_ip,
            "tenant_id": self.tenant_id,
            "request_id": self.request_id,
            "journey_id": self.journey_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        return cls(
            event_id=data["event_id"],
            event_type=AuditEventType(data["event_type"]),
            severity=AuditSeverity(data["severity"]),
            timestamp=datetime.fromisoformat(data["timestamp"].rstrip("Z")),
            actor_id=data.get("actor_id"),
            actor_type=data.get("actor_type"),
            actor_ip=data.get("actor_ip"),
            tenant_id=data.get("tenant_id"),
            request_id=data.get("request_id"),
            journey_id=data.get("journey_id"),
            resource_type=data.get("resource_type"),
            resource_id=data.get("resource_id"),
            action=data.get("action", ""),
            outcome=data.get("outcome", ""),
            details=data.get("details", {}),
            previous_hash=data.get("previous_hash"),
            event_hash=data.get("event_hash")
        )

    def _hash_payload(self) -> str:
        hash_input = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "previous_hash": self.previous_hash
        }
        return json.dumps(hash_input, sort_keys=True, default=str)

    def compute_hash(self, key: Optional[bytes] = None) -> str:
        """Compute the integrity hash of the event.

        With ``key`` present this is HMAC-SHA256 (keyed chain — an attacker
        with write access but without the key cannot recompute the chain after
        rewriting history). With ``key=None`` it falls back to legacy unkeyed
        SHA-256 solely so historical pre-upgrade log files can still be
        verified; new events must always be written keyed.
        """
        payload = self._hash_payload().encode()
        if key is not None:
            return hmac.new(key, payload, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload).hexdigest()


class AuditLogger:
    """
    Append-Only Audit Logger with HMAC-SHA256 Keyed Cryptographic Chaining

    Provides tamper-evident audit logging with:
    - Append-only log files
    - Keyed (HMAC-SHA256) hash chaining — fails closed without AUDIT_HMAC_KEY
    - Log rotation with signed segment seals and cross-segment chain continuity
    - External anchoring of every segment seal (file and/or HTTP endpoint)
    - Integrity verification per segment and across the whole chain
    - Approval-gated, retention-floor-enforced cleanup
    """

    def __init__(
        self,
        log_dir: str = None,
        max_file_size_mb: int = 100,
        retention_days: int = 365,
        compress_after_days: int = 7,
        hmac_key: Optional[Union[str, bytes]] = None,
        allow_insecure_unkeyed: bool = False,
        anchor_file: Optional[str] = None,
        anchor_endpoint: Optional[str] = None,
        retention_floor_days: Optional[int] = None,
    ):
        self.log_dir = Path(
            log_dir
            or os.getenv("AUDIT_LOG_DIR")
            or "/home/ubuntu/FRAUD_FUSION_COMPLETE_UNIFIED/logs/audit"
        )
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.retention_days = retention_days
        self.compress_after_days = compress_after_days
        self.retention_floor_days = (
            retention_floor_days
            if retention_floor_days is not None
            else int(os.getenv("AUDIT_RETENTION_FLOOR_DAYS", str(DEFAULT_RETENTION_FLOOR_DAYS)))
        )

        self._hmac_key = _load_hmac_key(hmac_key, allow_insecure_unkeyed)
        self.anchor_file = Path(anchor_file or os.getenv("AUDIT_ANCHOR_FILE")) if (anchor_file or os.getenv("AUDIT_ANCHOR_FILE")) else None
        self.anchor_endpoint = anchor_endpoint or os.getenv("AUDIT_ANCHOR_ENDPOINT") or None

        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._current_file: Optional[Path] = None
        self._current_file_handle = None
        self._last_hash: Optional[str] = None
        self._segment_event_count = 0
        self._previous_segment_root: Optional[str] = None
        self._used_cleanup_tokens: set = set()

        self._chain_state_file = self.log_dir / "chain_state.json"
        self._restore_chain_state()
        self._initialize_log_file()

    # ------------------------------------------------------------------
    # Chain state persistence (continuity across rotation and restarts)
    # ------------------------------------------------------------------

    def _restore_chain_state(self):
        """Resume the chain head from chain_state.json or the newest log file."""
        if self._chain_state_file.exists():
            try:
                state = json.loads(self._chain_state_file.read_text())
                self._last_hash = state.get("last_hash")
                self._previous_segment_root = state.get("previous_segment_root")
                return
            except Exception as e:
                logger.error(f"Failed to read chain state, falling back to log scan: {e}")

        log_files = sorted(self.log_dir.glob("audit_*.jsonl"))
        if log_files:
            newest = log_files[-1]
            try:
                with open(newest, "r") as f:
                    lines = [l for l in f.read().splitlines() if l.strip()]
                for line in reversed(lines):
                    record = json.loads(line)
                    if record.get("record_type") == "segment_seal":
                        self._last_hash = record.get("segment_root")
                        break
                    if record.get("event_hash"):
                        self._last_hash = record["event_hash"]
                        break
            except Exception as e:
                logger.error(f"Failed to resume chain from {newest}: {e}")

    def _persist_chain_state(self):
        state = {
            "last_hash": self._last_hash,
            "previous_segment_root": self._previous_segment_root,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
        tmp = self._chain_state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        os.replace(tmp, self._chain_state_file)

    # ------------------------------------------------------------------
    # File management / rotation with segment sealing
    # ------------------------------------------------------------------

    def _initialize_log_file(self):
        """Initialize or resume the current log file"""
        today = datetime.utcnow().strftime("%Y%m%d")
        log_file = self.log_dir / f"audit_{today}.jsonl"

        if log_file.exists() and self._last_hash is None:
            with open(log_file, "r") as f:
                lines = [l for l in f.read().splitlines() if l.strip()]
                if lines:
                    last_record = json.loads(lines[-1])
                    self._last_hash = last_record.get("event_hash") or last_record.get("segment_root")

        self._current_file = log_file
        self._current_file_handle = open(log_file, "a")

    def _compute_seal(self, segment_file: str, segment_root: Optional[str],
                      previous_segment_root: Optional[str], event_count: int,
                      sealed_at: str) -> Optional[str]:
        if self._hmac_key is None:
            return None
        payload = json.dumps({
            "segment_file": segment_file,
            "segment_root": segment_root,
            "previous_segment_root": previous_segment_root,
            "event_count": event_count,
            "sealed_at": sealed_at,
        }, sort_keys=True)
        return hmac.new(self._hmac_key, payload.encode(), hashlib.sha256).hexdigest()

    def _seal_current_segment(self):
        """Write a signed segment_seal record as the last line of the current
        segment and ship the seal to the external anchor(s)."""
        if not self._current_file or not self._current_file_handle:
            return
        sealed_at = datetime.utcnow().isoformat() + "Z"
        seal = {
            "record_type": "segment_seal",
            "segment_file": self._current_file.name,
            "segment_root": self._last_hash,
            "previous_segment_root": self._previous_segment_root,
            "event_count": self._segment_event_count,
            "sealed_at": sealed_at,
            "seal": self._compute_seal(
                self._current_file.name, self._last_hash,
                self._previous_segment_root, self._segment_event_count, sealed_at),
        }
        self._current_file_handle.write(json.dumps(seal, default=str) + "\n")
        self._current_file_handle.flush()
        os.fsync(self._current_file_handle.fileno())
        self._anchor_seal(seal)
        self._previous_segment_root = self._last_hash

    def _rotate_if_needed(self):
        """Rotate log file if size limit exceeded or date changed.

        Unlike the legacy implementation the chain is NEVER reset: the old
        segment is sealed, its root becomes the previous_segment_root, and the
        next event's previous_hash continues from the last hash.
        """
        if not self._current_file or not self._current_file.exists():
            self._initialize_log_file()
            return

        today = datetime.utcnow().strftime("%Y%m%d")
        expected_file = self.log_dir / f"audit_{today}.jsonl"

        if self._current_file != expected_file or (
            self._current_file.stat().st_size > self.max_file_size_bytes
        ):
            if self._segment_event_count > 0:
                self._seal_current_segment()
            if self._current_file_handle:
                self._current_file_handle.close()

            if self._current_file == expected_file:
                # size rotation: move sealed segment aside
                timestamp = datetime.utcnow().strftime("%H%M%S")
                rotated_file = self.log_dir / f"audit_{today}_{timestamp}.jsonl"
                self._current_file.rename(rotated_file)

            self._current_file = expected_file
            self._current_file_handle = open(expected_file, "a")
            self._segment_event_count = 0
            self._persist_chain_state()

    # ------------------------------------------------------------------
    # External anchor hook
    # ------------------------------------------------------------------

    def _anchor_seal(self, seal: Dict[str, Any]):
        """Ship a segment seal outside the blast radius.

        Writes to AUDIT_ANCHOR_FILE (append-only JSONL, e.g. on a separate
        mount) and/or POSTs to AUDIT_ANCHOR_ENDPOINT. Anchor failures never
        block logging but are emitted as CRITICAL so alerting picks them up.
        """
        line = json.dumps(seal, default=str)
        if self.anchor_file:
            try:
                self.anchor_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.anchor_file, "a") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                logger.critical(f"AUDIT ANCHOR FAILURE (file {self.anchor_file}): {e}")
        if self.anchor_endpoint:
            try:
                req = urllib.request.Request(
                    self.anchor_endpoint,
                    data=line.encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status >= 400:
                        raise RuntimeError(f"anchor endpoint returned {resp.status}")
            except Exception as e:
                logger.critical(f"AUDIT ANCHOR FAILURE (endpoint {self.anchor_endpoint}): {e}")

    def _is_segment_anchored(self, segment_name: str) -> bool:
        """True if the segment's seal is present in the external anchor file."""
        if not self.anchor_file or not self.anchor_file.exists():
            return False
        try:
            with open(self.anchor_file, "r") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("record_type") == "segment_seal" and \
                            record.get("segment_file") == segment_name:
                        return True
        except Exception as e:
            logger.error(f"Failed to read anchor file {self.anchor_file}: {e}")
        return False

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log(self, event: AuditEvent) -> AuditEvent:
        """
        Log an audit event

        Args:
            event: The audit event to log

        Returns:
            The event with hash computed
        """
        with self._lock:
            self._rotate_if_needed()

            event.previous_hash = self._last_hash
            event.event_hash = event.compute_hash(self._hmac_key)

            log_line = json.dumps(event.to_dict(), default=str) + "\n"
            self._current_file_handle.write(log_line)
            self._current_file_handle.flush()
            os.fsync(self._current_file_handle.fileno())

            self._last_hash = event.event_hash
            self._segment_event_count += 1
            self._persist_chain_state()

            return event

    def log_fraud_detection(
        self,
        fraud_score: float,
        fraud_type: str,
        transaction_id: str,
        decision: str,
        model_name: str = None,
        model_version: str = None,
        **kwargs
    ) -> AuditEvent:
        """Log a fraud detection decision"""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.FRAUD_DETECTION,
            severity=AuditSeverity.CRITICAL if fraud_score > 0.7 else AuditSeverity.INFO,
            timestamp=datetime.utcnow(),
            resource_type="transaction",
            resource_id=transaction_id,
            action="fraud_detection",
            outcome=decision,
            details={
                "fraud_score": fraud_score,
                "fraud_type": fraud_type,
                "model_name": model_name,
                "model_version": model_version,
                **kwargs
            },
            **{k: v for k, v in kwargs.items() if k in ["actor_id", "tenant_id", "request_id", "journey_id"]}
        )
        return self.log(event)

    def log_kyc_verification(
        self,
        verification_type: str,
        subject_id: str,
        status: str,
        verification_result: Dict[str, Any],
        **kwargs
    ) -> AuditEvent:
        """Log a KYC verification decision"""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.KYC_VERIFICATION,
            severity=AuditSeverity.WARNING if status == "failed" else AuditSeverity.INFO,
            timestamp=datetime.utcnow(),
            resource_type="identity",
            resource_id=subject_id,
            action=f"kyc_{verification_type}",
            outcome=status,
            details={
                "verification_type": verification_type,
                "verification_result": verification_result,
                **kwargs
            },
            **{k: v for k, v in kwargs.items() if k in ["actor_id", "tenant_id", "request_id", "journey_id"]}
        )
        return self.log(event)

    def log_document_validation(
        self,
        document_type: str,
        document_id: str,
        status: str,
        validation_result: Dict[str, Any],
        **kwargs
    ) -> AuditEvent:
        """Log a document validation decision"""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.DOCUMENT_VALIDATION,
            severity=AuditSeverity.WARNING if status in ["rejected", "fraudulent"] else AuditSeverity.INFO,
            timestamp=datetime.utcnow(),
            resource_type="document",
            resource_id=document_id,
            action=f"validate_{document_type}",
            outcome=status,
            details={
                "document_type": document_type,
                "validation_result": validation_result,
                **kwargs
            },
            **{k: v for k, v in kwargs.items() if k in ["actor_id", "tenant_id", "request_id", "journey_id"]}
        )
        return self.log(event)

    def log_data_access(
        self,
        resource_type: str,
        resource_id: str,
        access_type: str,
        fields_accessed: List[str] = None,
        **kwargs
    ) -> AuditEvent:
        """Log a data access event"""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditSeverity.INFO,
            timestamp=datetime.utcnow(),
            resource_type=resource_type,
            resource_id=resource_id,
            action=access_type,
            outcome="success",
            details={
                "fields_accessed": fields_accessed or [],
                **kwargs
            },
            **{k: v for k, v in kwargs.items() if k in ["actor_id", "actor_type", "actor_ip", "tenant_id", "request_id"]}
        )
        return self.log(event)

    def log_manual_review(
        self,
        resource_type: str,
        resource_id: str,
        reviewer_id: str,
        decision: str,
        reason: str,
        original_decision: str = None,
        **kwargs
    ) -> AuditEvent:
        """Log a manual review decision"""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.MANUAL_REVIEW,
            severity=AuditSeverity.WARNING,
            timestamp=datetime.utcnow(),
            actor_id=reviewer_id,
            actor_type="reviewer",
            resource_type=resource_type,
            resource_id=resource_id,
            action="manual_review",
            outcome=decision,
            details={
                "reason": reason,
                "original_decision": original_decision,
                **kwargs
            },
            **{k: v for k, v in kwargs.items() if k in ["tenant_id", "request_id", "journey_id"]}
        )
        return self.log(event)

    def log_override_decision(
        self,
        resource_type: str,
        resource_id: str,
        overrider_id: str,
        original_decision: str,
        new_decision: str,
        reason: str,
        **kwargs
    ) -> AuditEvent:
        """Log a decision override"""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.OVERRIDE_DECISION,
            severity=AuditSeverity.CRITICAL,
            timestamp=datetime.utcnow(),
            actor_id=overrider_id,
            actor_type="admin",
            resource_type=resource_type,
            resource_id=resource_id,
            action="override_decision",
            outcome=new_decision,
            details={
                "original_decision": original_decision,
                "reason": reason,
                **kwargs
            },
            **{k: v for k, v in kwargs.items() if k in ["tenant_id", "request_id", "journey_id"]}
        )
        return self.log(event)

    def log_security_event(
        self,
        event_name: str,
        severity: AuditSeverity,
        details: Dict[str, Any],
        **kwargs
    ) -> AuditEvent:
        """Log a security event"""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.SECURITY_EVENT,
            severity=severity,
            timestamp=datetime.utcnow(),
            action=event_name,
            outcome="detected",
            details=details,
            **{k: v for k, v in kwargs.items() if k in ["actor_id", "actor_type", "actor_ip", "tenant_id", "request_id", "resource_type", "resource_id"]}
        )
        return self.log(event)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_integrity(self, log_file: Path = None,
                         key: Optional[bytes] = None,
                         allow_legacy_unkeyed: bool = False,
                         expected_start_hash: Optional[str] = None) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of one audit log segment.

        Args:
            log_file: Specific log file to verify (defaults to current)
            key: HMAC key (defaults to the logger's key)
            allow_legacy_unkeyed: also accept legacy unkeyed SHA-256 hashes
                (for verifying pre-upgrade historical files only)
            expected_start_hash: previous_hash expected on the first event
                (None for the genesis segment; the prior segment root for
                continuation segments — see :meth:`verify_chain`)

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        log_file = Path(log_file) if log_file else self._current_file
        key = key if key is not None else self._hmac_key
        errors = []

        if not log_file or not log_file.exists():
            return True, []

        previous_hash = expected_start_hash
        line_number = 0
        sealed = False

        with open(log_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                line_number += 1
                try:
                    data = json.loads(line)

                    if data.get("record_type") == "segment_seal":
                        sealed = True
                        seal_errors = self._verify_seal_record(data, previous_hash, line_number, key)
                        errors.extend(seal_errors)
                        continue

                    event = AuditEvent.from_dict(data)

                    if event.previous_hash != previous_hash:
                        errors.append(
                            f"Line {line_number}: Chain broken - expected previous_hash "
                            f"{previous_hash}, got {event.previous_hash}"
                        )

                    computed_hash = event.compute_hash(key) if key else None
                    legacy_hash = event.compute_hash(None) if allow_legacy_unkeyed else None
                    if computed_hash is not None and computed_hash != event.event_hash \
                            and event.event_hash != legacy_hash:
                        errors.append(
                            f"Line {line_number}: Hash mismatch - computed {computed_hash}, "
                            f"stored {event.event_hash}"
                        )
                    elif computed_hash is None and event.event_hash != legacy_hash:
                        # No key available and legacy verification not allowed.
                        errors.append(
                            f"Line {line_number}: cannot verify without HMAC key"
                        )

                    previous_hash = event.event_hash

                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_number}: Invalid JSON - {e}")
                except Exception as e:
                    errors.append(f"Line {line_number}: Error - {e}")

        return len(errors) == 0, errors

    def _verify_seal_record(self, seal: Dict[str, Any], last_event_hash: Optional[str],
                            line_number: int, key: Optional[bytes]) -> List[str]:
        errors = []
        if seal.get("segment_root") != last_event_hash:
            errors.append(
                f"Line {line_number}: seal segment_root {seal.get('segment_root')} "
                f"does not match last event hash {last_event_hash}"
            )
        if key is not None:
            expected = self._compute_seal(
                seal.get("segment_file"), seal.get("segment_root"),
                seal.get("previous_segment_root"), seal.get("event_count", 0),
                seal.get("sealed_at", ""))
            if not hmac.compare_digest(expected, seal.get("seal") or ""):
                errors.append(f"Line {line_number}: segment seal signature invalid")
        return errors

    def verify_chain(self, allow_legacy_unkeyed: bool = False) -> Tuple[bool, List[str]]:
        """Verify every segment plus cross-segment continuity via seals.

        For each sealed segment the next segment's first event must chain from
        the sealed segment root. Returns (is_valid, errors).
        """
        errors: List[str] = []
        segments = sorted(
            [p for p in self.log_dir.glob("audit_*.jsonl")],
            key=lambda p: p.name,
        )
        carried_root: Optional[str] = None

        for segment in segments:
            ok, seg_errors = self.verify_integrity(
                segment,
                allow_legacy_unkeyed=allow_legacy_unkeyed,
                expected_start_hash=carried_root,
            )
            errors.extend(f"{segment.name}: {e}" for e in seg_errors)

            _, seg_root, _ = self._segment_bounds(segment)
            if seg_root is not None:
                carried_root = seg_root

        return len(errors) == 0, errors

    def _segment_bounds(self, segment: Path) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Return (first event previous_hash, segment root, seal's previous_segment_root)."""
        first_prev: Optional[str] = None
        last_hash: Optional[str] = None
        seal_prev: Optional[str] = None
        with open(segment, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("record_type") == "segment_seal":
                    seal_prev = record.get("previous_segment_root")
                    last_hash = record.get("segment_root") or last_hash
                    continue
                if first_prev is None:
                    first_prev = record.get("previous_hash")
                if record.get("event_hash"):
                    last_hash = record["event_hash"]
        return first_prev, last_hash, seal_prev

    def query_events(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        event_type: AuditEventType = None,
        actor_id: str = None,
        tenant_id: str = None,
        resource_type: str = None,
        resource_id: str = None,
        limit: int = 1000
    ) -> List[AuditEvent]:
        """Query audit events with filters (segment seals are skipped)."""
        events = []

        log_files = sorted(self.log_dir.glob("audit_*.jsonl"), reverse=True)

        for log_file in log_files:
            if len(events) >= limit:
                break

            with open(log_file, "r") as f:
                for line in f:
                    if len(events) >= limit:
                        break

                    try:
                        data = json.loads(line)
                        if data.get("record_type") == "segment_seal":
                            continue
                        event = AuditEvent.from_dict(data)

                        if start_time and event.timestamp < start_time:
                            continue
                        if end_time and event.timestamp > end_time:
                            continue
                        if event_type and event.event_type != event_type:
                            continue
                        if actor_id and event.actor_id != actor_id:
                            continue
                        if tenant_id and event.tenant_id != tenant_id:
                            continue
                        if resource_type and event.resource_type != resource_type:
                            continue
                        if resource_id and event.resource_id != resource_id:
                            continue

                        events.append(event)

                    except Exception:
                        continue

        return events

    # ------------------------------------------------------------------
    # Cleanup approval tokens (dual control for log destruction)
    # ------------------------------------------------------------------

    def issue_cleanup_token(self, segment_name: str, principal: str,
                            expires_in_seconds: int = 300) -> str:
        """Issue a signed, single-use cleanup approval token for one segment.

        In production this is issued by the second principal of a dual-control
        pair (mirroring the deletion_approvals table flow); the logger only
        verifies the signature, expiry, and single-use property.
        """
        if self._hmac_key is None:
            raise RuntimeError("cleanup tokens require a keyed audit chain")
        token_id = str(uuid.uuid4())
        expiry = int(time.time()) + expires_in_seconds
        payload = f"audit-cleanup|{segment_name}|{principal}|{expiry}|{token_id}"
        signature = hmac.new(self._hmac_key, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}|{signature}"

    def _verify_cleanup_token(self, token: str, segment_name: str) -> Tuple[bool, str]:
        if self._hmac_key is None:
            return False, "cleanup tokens require a keyed audit chain"
        parts = token.split("|")
        if len(parts) != 6 or parts[0] != "audit-cleanup":
            return False, "malformed cleanup token"
        _, token_segment, principal, expiry_text, token_id, signature = parts
        payload = "|".join(parts[:-1])
        expected = hmac.new(self._hmac_key, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False, "cleanup token signature invalid"
        if token_segment != segment_name:
            return False, f"cleanup token is for segment {token_segment}, not {segment_name}"
        if int(expiry_text) < int(time.time()):
            return False, "cleanup token expired"
        if token_id in self._used_cleanup_tokens:
            return False, "cleanup token already used (single-use)"
        return True, principal

    # ------------------------------------------------------------------
    # Compression and retention with regulatory floor + dual control
    # ------------------------------------------------------------------

    def _file_contains_regulated_events(self, log_file: Path) -> bool:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("event_type") in REGULATED_EVENT_TYPES:
                        return True
        except Exception:
            # Fail closed: unreadable files are treated as regulated.
            return True
        return False

    def _segment_is_sealed(self, log_file: Path) -> bool:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    if '"record_type": "segment_seal"' in line or \
                            '"record_type":"segment_seal"' in line:
                        return True
        except Exception:
            return False
        return False

    def compress_old_logs(self):
        """Compress sealed log files older than compress_after_days.

        Only sealed, non-current segments are compressed; the chain head is
        never touched. Compression preserves content byte-for-byte.
        """
        cutoff = datetime.utcnow() - timedelta(days=self.compress_after_days)

        for log_file in self.log_dir.glob("audit_*.jsonl"):
            if log_file == self._current_file:
                continue

            try:
                date_str = log_file.stem.split("_")[1]
                file_date = datetime.strptime(date_str, "%Y%m%d")

                if file_date < cutoff:
                    if not self._segment_is_sealed(log_file):
                        logger.warning(
                            f"Refusing to compress unsealed segment {log_file}; "
                            "seal it via rotation before compression"
                        )
                        continue
                    compressed_file = log_file.with_suffix(".jsonl.gz")

                    with open(log_file, "rb") as f_in:
                        with gzip.open(compressed_file, "wb") as f_out:
                            f_out.writelines(f_in)

                    log_file.unlink()
                    logger.info(f"Compressed {log_file} to {compressed_file}")

            except Exception as e:
                logger.error(f"Failed to compress {log_file}: {e}")

    def cleanup_old_logs(self, approval_tokens: Optional[Dict[str, str]] = None):
        """Delete log files older than the applicable retention period.

        Dual-control gated: each candidate segment requires a valid signed,
        single-use approval token (``approval_tokens[segment_name]``) issued by
        a second principal via :meth:`issue_cleanup_token`.

        Retention floor: segments containing regulated event classes are never
        deleted younger than ``retention_floor_days`` (default 2555 = 7 years),
        regardless of ``retention_days``. Segments must also be sealed and —
        when an anchor file is configured — externally anchored before local
        deletion is permitted.
        """
        approval_tokens = approval_tokens or {}
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        floor_cutoff = datetime.utcnow() - timedelta(days=self.retention_floor_days)

        for log_file in sorted(self.log_dir.glob("audit_*")):
            if log_file.name in ("chain_state.json",):
                continue
            if log_file == self._current_file:
                continue
            try:
                date_str = log_file.stem.split("_")[1]
                file_date = datetime.strptime(date_str, "%Y%m%d")

                if file_date >= cutoff:
                    continue

                # Regulatory retention floor (fail closed on unreadable files)
                if file_date >= floor_cutoff and self._file_contains_regulated_events(log_file):
                    logger.warning(
                        f"Refusing to delete {log_file}: contains regulated events and is "
                        f"younger than the {self.retention_floor_days}-day retention floor"
                    )
                    continue

                # Segment must be sealed before destruction
                if log_file.suffix == ".jsonl" and not self._segment_is_sealed(log_file):
                    logger.warning(f"Refusing to delete unsealed segment {log_file}")
                    continue

                # External anchor must confirm the segment left the blast radius
                if self.anchor_file and not self._is_segment_anchored(log_file.name):
                    logger.warning(
                        f"Refusing to delete {log_file}: no external anchor record found"
                    )
                    continue

                # Dual control: valid single-use signed approval token required
                token = approval_tokens.get(log_file.name)
                if not token:
                    logger.warning(f"Refusing to delete {log_file}: no approval token")
                    continue
                ok, principal_or_reason = self._verify_cleanup_token(token, log_file.name)
                if not ok:
                    logger.warning(f"Refusing to delete {log_file}: {principal_or_reason}")
                    continue

                log_file.unlink()
                token_id = token.split("|")[-2]
                self._used_cleanup_tokens.add(token_id)
                self.log_security_event(
                    "audit_log_destroyed",
                    AuditSeverity.CRITICAL,
                    {
                        "segment_file": log_file.name,
                        "approved_by": principal_or_reason,
                        "retention_floor_days": self.retention_floor_days,
                    },
                )
                logger.info(f"Deleted old audit log: {log_file} (approved by {principal_or_reason})")

            except Exception as e:
                logger.error(f"Failed to delete {log_file}: {e}")

    def close(self):
        """Close the audit logger"""
        if self._current_file_handle:
            self._current_file_handle.close()
            self._current_file_handle = None


_audit_logger_instance: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger instance.

    Fails closed if AUDIT_HMAC_KEY/AUDIT_HMAC_KEY_URI is not configured.
    """
    global _audit_logger_instance

    if _audit_logger_instance is None:
        _audit_logger_instance = AuditLogger()

    return _audit_logger_instance
