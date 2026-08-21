"""
Append-Only Audit Logging System

Provides tamper-evident audit logging for:
- All decision events (fraud scores, KYC pass/fail, document verdicts)
- Data access events
- Configuration changes
- User actions
- System events

Features:
- Append-only log files with cryptographic chaining
- Log integrity verification
- Structured JSON format
- Retention policy support
"""

import os
import json
import hashlib
import logging
import threading
import gzip
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)


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

    def compute_hash(self) -> str:
        """Compute hash of the event for integrity verification"""
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

        hash_string = json.dumps(hash_input, sort_keys=True, default=str)
        return hashlib.sha256(hash_string.encode()).hexdigest()


class AuditLogger:
    """
    Append-Only Audit Logger with Cryptographic Chaining

    Provides tamper-evident audit logging with:
    - Append-only log files
    - Cryptographic hash chaining
    - Log rotation and compression
    - Integrity verification
    """

    def __init__(
        self,
        log_dir: str = None,
        max_file_size_mb: int = 100,
        retention_days: int = 365,
        compress_after_days: int = 7
    ):
        self.log_dir = Path(log_dir or "/home/ubuntu/FRAUD_FUSION_COMPLETE_UNIFIED/logs/audit")
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.retention_days = retention_days
        self.compress_after_days = compress_after_days

        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._current_file: Optional[Path] = None
        self._current_file_handle = None
        self._last_hash: Optional[str] = None

        self._initialize_log_file()

    def _initialize_log_file(self):
        """Initialize or resume the current log file"""
        today = datetime.utcnow().strftime("%Y%m%d")
        log_file = self.log_dir / f"audit_{today}.jsonl"

        if log_file.exists():
            with open(log_file, "r") as f:
                lines = f.readlines()
                if lines:
                    last_event = json.loads(lines[-1])
                    self._last_hash = last_event.get("event_hash")

        self._current_file = log_file
        self._current_file_handle = open(log_file, "a")

    def _rotate_if_needed(self):
        """Rotate log file if size limit exceeded or date changed"""
        if not self._current_file or not self._current_file.exists():
            self._initialize_log_file()
            return

        today = datetime.utcnow().strftime("%Y%m%d")
        expected_file = self.log_dir / f"audit_{today}.jsonl"

        if self._current_file != expected_file:
            if self._current_file_handle:
                self._current_file_handle.close()
            self._current_file = expected_file
            self._current_file_handle = open(expected_file, "a")
            self._last_hash = None
            return

        if self._current_file.stat().st_size > self.max_file_size_bytes:
            if self._current_file_handle:
                self._current_file_handle.close()

            timestamp = datetime.utcnow().strftime("%H%M%S")
            rotated_file = self.log_dir / f"audit_{today}_{timestamp}.jsonl"
            self._current_file.rename(rotated_file)

            self._current_file = self.log_dir / f"audit_{today}.jsonl"
            self._current_file_handle = open(self._current_file, "a")

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
            event.event_hash = event.compute_hash()

            log_line = json.dumps(event.to_dict(), default=str) + "\n"
            self._current_file_handle.write(log_line)
            self._current_file_handle.flush()
            os.fsync(self._current_file_handle.fileno())

            self._last_hash = event.event_hash

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
            **{k: v for k, v in kwargs.items() if k in ["actor_id", "actor_type", "actor_ip", "tenant_id", "request_id"]}
        )
        return self.log(event)

    def verify_integrity(self, log_file: Path = None) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of audit logs

        Args:
            log_file: Specific log file to verify (defaults to current)

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        log_file = log_file or self._current_file
        errors = []

        if not log_file or not log_file.exists():
            return True, []

        previous_hash = None
        line_number = 0

        with open(log_file, "r") as f:
            for line in f:
                line_number += 1
                try:
                    data = json.loads(line)
                    event = AuditEvent.from_dict(data)

                    if event.previous_hash != previous_hash:
                        errors.append(
                            f"Line {line_number}: Chain broken - expected previous_hash "
                            f"{previous_hash}, got {event.previous_hash}"
                        )

                    computed_hash = event.compute_hash()
                    if computed_hash != event.event_hash:
                        errors.append(
                            f"Line {line_number}: Hash mismatch - computed {computed_hash}, "
                            f"stored {event.event_hash}"
                        )

                    previous_hash = event.event_hash

                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_number}: Invalid JSON - {e}")
                except Exception as e:
                    errors.append(f"Line {line_number}: Error - {e}")

        return len(errors) == 0, errors

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
        """
        Query audit events with filters

        Args:
            start_time: Filter events after this time
            end_time: Filter events before this time
            event_type: Filter by event type
            actor_id: Filter by actor
            tenant_id: Filter by tenant
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            limit: Maximum number of events to return

        Returns:
            List of matching audit events
        """
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

    def compress_old_logs(self):
        """Compress log files older than compress_after_days"""
        cutoff = datetime.utcnow() - timedelta(days=self.compress_after_days)

        for log_file in self.log_dir.glob("audit_*.jsonl"):
            if log_file == self._current_file:
                continue

            try:
                date_str = log_file.stem.split("_")[1]
                file_date = datetime.strptime(date_str, "%Y%m%d")

                if file_date < cutoff:
                    compressed_file = log_file.with_suffix(".jsonl.gz")

                    with open(log_file, "rb") as f_in:
                        with gzip.open(compressed_file, "wb") as f_out:
                            f_out.writelines(f_in)

                    log_file.unlink()
                    logger.info(f"Compressed {log_file} to {compressed_file}")

            except Exception as e:
                logger.error(f"Failed to compress {log_file}: {e}")

    def cleanup_old_logs(self):
        """Delete log files older than retention_days"""
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)

        for log_file in self.log_dir.glob("audit_*"):
            try:
                date_str = log_file.stem.split("_")[1]
                file_date = datetime.strptime(date_str, "%Y%m%d")

                if file_date < cutoff:
                    log_file.unlink()
                    logger.info(f"Deleted old audit log: {log_file}")

            except Exception as e:
                logger.error(f"Failed to delete {log_file}: {e}")

    def close(self):
        """Close the audit logger"""
        if self._current_file_handle:
            self._current_file_handle.close()
            self._current_file_handle = None


_audit_logger_instance: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger instance"""
    global _audit_logger_instance

    if _audit_logger_instance is None:
        _audit_logger_instance = AuditLogger()

    return _audit_logger_instance
