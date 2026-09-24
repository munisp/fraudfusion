"""
Storage Gateway - Unified Storage Access Layer
FraudFusion Platform

This module provides a unified gateway for all storage operations,
abstracting the underlying RustFS storage and providing additional
features like virus scanning, content validation, and audit logging.
"""

import os
import hashlib
import logging
import mimetypes
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timedelta
from enum import Enum
import json

from .rustfs_client import RustFSClient, RustFSConfig, UploadResult, ObjectMetadata
from .deletion_approval import (
    DeletionApprovalStore,
    DeleteTokenIssuer,
    DeletionRequest,
    DualControlViolation,
)

logger = logging.getLogger(__name__)

TOMBSTONE_SUFFIX = ".tombstone"
DEFAULT_WORM_RETENTION_DAYS = 2555  # 7 years (AML/BSA)
DEFAULT_TOMBSTONE_RETENTION_DAYS = 90


class WormMode(Enum):
    """WORM / immutability enforcement mode (STORAGE_WORM_MODE)."""
    OFF = "off"                # soft-delete only; hard delete gated by dual control
    GOVERNANCE = "governance"  # retention enforced, overridable via dual control
    COMPLIANCE = "compliance"  # deletes blocked absolutely until retention expires

    @classmethod
    def from_env(cls, default: "WormMode" = None) -> "WormMode":
        raw = os.getenv("STORAGE_WORM_MODE", "").strip().lower()
        if not raw:
            return default or cls.GOVERNANCE
        try:
            return cls(raw)
        except ValueError:
            raise ValueError(
                f"STORAGE_WORM_MODE must be one of compliance|governance|off, got {raw!r}"
            )


class StorageLockdownError(RuntimeError):
    """Raised when storage is in read-only lockdown (ransomware guard)."""


class StorageOperation(Enum):
    """Types of storage operations"""
    UPLOAD = "upload"
    DOWNLOAD = "download"
    DELETE = "delete"
    LIST = "list"
    COPY = "copy"
    PRESIGN = "presign"


class ContentValidationResult(Enum):
    """Content validation results"""
    VALID = "valid"
    INVALID_TYPE = "invalid_type"
    INVALID_SIZE = "invalid_size"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class StoragePolicy:
    """Storage policy configuration"""
    max_file_size: int = 100 * 1024 * 1024  # 100MB default
    allowed_content_types: List[str] = field(default_factory=lambda: [
        "application/pdf",
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "video/mp4",
        "video/webm",
        "application/json",
        "text/plain",
        "text/csv",
    ])
    require_checksum: bool = True
    enable_virus_scan: bool = True
    enable_audit_log: bool = True
    retention_days: Optional[int] = None
    # --- anti-wipe policy -------------------------------------------------
    require_versioning: bool = True  # fail closed if bucket versioning is off
    worm_mode: WormMode = field(default_factory=WormMode.from_env)
    worm_retention_days: int = DEFAULT_WORM_RETENTION_DAYS
    soft_delete_tombstone_retention_days: int = DEFAULT_TOMBSTONE_RETENTION_DAYS
    dual_control_required: bool = True
    require_persistent_audit: bool = True  # fail closed if audit sink unavailable


@dataclass
class AuditLogEntry:
    """Audit log entry for storage operations"""
    timestamp: datetime
    operation: StorageOperation
    bucket: str
    key: str
    user_id: Optional[str]
    ip_address: Optional[str]
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class StorageGateway:
    """
    Unified Storage Gateway for FraudFusion Platform

    Provides a high-level interface for storage operations with:
    - Content validation (type, size)
    - Virus scanning integration
    - Audit logging
    - Policy enforcement
    - Multi-tenant support

    Example:
        gateway = StorageGateway()

        # Upload with validation
        result = gateway.upload_document(
            bucket="documents",
            key="kyc/customer123/passport.pdf",
            file_path="/path/to/passport.pdf",
            user_id="user123",
        )

        # Download with audit
        data = gateway.download_document(
            bucket="documents",
            key="kyc/customer123/passport.pdf",
            user_id="user123",
        )
    """

    def __init__(
        self,
        client: Optional[RustFSClient] = None,
        policy: Optional[StoragePolicy] = None,
        audit_callback: Optional[Callable[[AuditLogEntry], None]] = None,
        approval_store: Optional[DeletionApprovalStore] = None,
        token_issuer: Optional[DeleteTokenIssuer] = None,
        guard: Optional[Any] = None,
        enable_ransomware_guard: Optional[bool] = None,
    ):
        """Initialize storage gateway.

        Ransomware guard wiring (hot path): every mutating operation emits an
        op event to ``services.python.ransomware_guard.RansomwareGuard``
        (in-process direct call). A guard lockdown trip makes
        :meth:`_assert_writable` reject all subsequent writes/deletes.
        Resolution order: explicit ``guard`` argument > disabled via
        ``enable_ransomware_guard=False`` or ``STORAGE_RANSOMWARE_GUARD=false``
        > default guard built from ``GuardConfig.from_env()``.
        """
        self.client = client or RustFSClient()
        self.policy = policy or StoragePolicy()
        self.approval_store = approval_store
        self._token_issuer = token_issuer
        self._audit_log: List[AuditLogEntry] = []  # small in-memory ring for queries
        self._versioning_verified: Dict[str, bool] = {}
        self._guard = self._resolve_guard(guard, enable_ransomware_guard)

        if audit_callback is not None:
            self.audit_callback = audit_callback
        elif self.policy.enable_audit_log:
            # Default: persistent, hash-chained audit ledger (NOT memory-only).
            self.audit_callback = self._build_persistent_audit_sink()
        else:
            self.audit_callback = None

    # ------------------------------------------------------------------
    # Persistent audit sink (P1-3)
    # ------------------------------------------------------------------

    def _build_persistent_audit_sink(self) -> Optional[Callable[[AuditLogEntry], None]]:
        """Wire storage audit events into the tamper-evident AuditLogger.

        Fails closed when ``policy.require_persistent_audit`` is set and no
        keyed audit logger can be constructed (AUDIT_HMAC_KEY missing).
        """
        try:
            from ..security.audit.audit_logger import (
                get_audit_logger, AuditSeverity,
            )
        except Exception as e:
            if self.policy.require_persistent_audit:
                raise RuntimeError(
                    "persistent audit sink unavailable and "
                    "policy.require_persistent_audit is set"
                ) from e
            logger.critical(f"Persistent audit sink unavailable, falling back to memory: {e}")
            return None

        audit_logger = get_audit_logger()  # fails closed without AUDIT_HMAC_KEY

        def sink(entry: AuditLogEntry) -> None:
            severity = AuditSeverity.INFO if entry.success else AuditSeverity.WARNING
            if entry.operation == StorageOperation.DELETE:
                severity = AuditSeverity.CRITICAL
            audit_logger.log_security_event(
                f"storage_{entry.operation.value}",
                severity,
                {
                    "bucket": entry.bucket,
                    "key": entry.key,
                    "success": entry.success,
                    "error_message": entry.error_message,
                    **entry.metadata,
                },
                actor_id=entry.user_id,
                actor_ip=entry.ip_address,
                resource_type="storage_object",
                resource_id=f"{entry.bucket}/{entry.key}",
            )

        # smoke-test the sink once at startup so misconfiguration fails fast
        try:
            sink(AuditLogEntry(
                timestamp=datetime.utcnow(),
                operation=StorageOperation.LIST,
                bucket="__startup__",
                key="audit_sink_check",
                user_id="system",
                ip_address=None,
                success=True,
            ))
        except Exception as e:
            if self.policy.require_persistent_audit:
                raise RuntimeError(f"persistent audit sink failed startup check: {e}") from e
            logger.critical(f"Persistent audit sink failed startup check: {e}")
            return None
        return sink

    # ------------------------------------------------------------------
    # Ransomware guard wiring (hot path)
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_guard(guard: Optional[Any], enabled: Optional[bool]) -> Optional[Any]:
        if guard is not None:
            return guard
        env_off = os.getenv("STORAGE_RANSOMWARE_GUARD", "").strip().lower() in ("0", "false", "no")
        if enabled is False or (enabled is None and env_off):
            return None
        try:
            from services.python.ransomware_guard import RansomwareGuard
        except ImportError:
            # Standalone checkout layout: add the repo root and retry.
            import sys
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            if repo_root not in sys.path:
                sys.path.insert(0, repo_root)
            try:
                from services.python.ransomware_guard import RansomwareGuard
            except ImportError as e:
                logger.critical(
                    "ransomware guard unavailable (%s); storage runs WITHOUT "
                    "behavioral wipe detection — WORM/dual-control barriers remain", e,
                )
                return None
        return RansomwareGuard()  # config from env (GuardConfig.from_env)

    def _observe_upload(self, user_id: Optional[str], bucket: str, key: str,
                        overwrite: bool, content_sample: bytes = b""):
        """Emit a put/upload op event to the ransomware guard (best effort —
        a guard observation failure must not corrupt the storage op, but a
        guard lockdown always blocks the NEXT op via _assert_writable)."""
        guard = self._guard
        if guard is None:
            return
        try:
            path = f"{bucket}/{key}"
            principal = user_id or "system"
            if overwrite:
                guard.observe_overwrite(principal, path)
            else:
                guard.observe_upload(principal, path, content_sample)
        except Exception as e:
            logger.critical("ransomware guard observation failed for %s/%s: %s", bucket, key, e)

    def _observe_delete(self, user_id: Optional[str], bucket: str, key: str):
        guard = self._guard
        if guard is None:
            return
        try:
            guard.observe_delete(user_id or "system", f"{bucket}/{key}")
        except Exception as e:
            logger.critical("ransomware guard observation failed for %s/%s: %s", bucket, key, e)

    def _lockdown_file_active(self) -> bool:
        """Cross-process lockdown contract: the guard flips this JSON file so
        sibling processes (Rust gateway, other Python workers) also lock down.
        Absent file = no lockdown; unreadable/corrupt file = fail closed."""
        path = os.getenv(
            "STORAGE_LOCKDOWN_STATE", "/var/lib/fraudfusion/storage/lockdown.json"
        )
        try:
            with open(path, "r", encoding="utf-8") as f:
                return bool(json.load(f).get("read_only"))
        except FileNotFoundError:
            return False
        except (NotADirectoryError, IsADirectoryError, PermissionError):
            # Path never provisioned in this environment — not a lockdown.
            return False
        except Exception as e:
            logger.critical("lockdown state file %s unreadable (%s); failing closed", path, e)
            return True

    # ------------------------------------------------------------------
    # Lockdown / versioning / tombstones (anti-wipe)
    # ------------------------------------------------------------------

    def _assert_writable(self):
        """Global read-only lockdown switch flipped by ransomware_guard.

        Three lockdown signals, any one blocks writes/deletes:
          1. STORAGE_READ_ONLY env (operator / orchestrator kill switch)
          2. in-process guard lockdown state (direct call wiring)
          3. shared lockdown state file (cross-process guard flip)
        """
        if os.getenv("STORAGE_READ_ONLY", "").strip().lower() in ("1", "true", "yes"):
            raise StorageLockdownError(
                "storage is in READ-ONLY lockdown; writes and deletes are rejected"
            )
        guard = self._guard
        if guard is not None and guard.is_locked_down():
            raise StorageLockdownError(
                f"storage is in READ-ONLY lockdown (ransomware guard: "
                f"{guard.state.reason or 'destructive activity detected'}); "
                "writes and deletes are rejected"
            )
        if self._lockdown_file_active():
            raise StorageLockdownError(
                "storage is in READ-ONLY lockdown (lockdown state file); "
                "writes and deletes are rejected"
            )

    def _ensure_versioned(self, bucket: str):
        """Fail closed if bucket versioning is not enabled (PUT overwrite
        without versioning is a silent destructive mutation)."""
        if not self.policy.require_versioning:
            return
        if self._versioning_verified.get(bucket):
            return
        status = self.client.get_bucket_versioning(bucket)
        if status != "Enabled":
            logger.warning(f"Bucket {bucket} versioning is {status}; enabling")
            self.client.enable_bucket_versioning(bucket)
            status = self.client.get_bucket_versioning(bucket)
        if status != "Enabled":
            raise RuntimeError(
                f"bucket {bucket} does not have versioning Enabled; refusing "
                "to write without overwrite protection (fail closed)"
            )
        self._versioning_verified[bucket] = True

    @staticmethod
    def _tombstone_key(key: str) -> str:
        return f"{key}{TOMBSTONE_SUFFIX}"

    def _is_tombstoned(self, bucket: str, key: str) -> bool:
        return self.client.object_exists(bucket, self._tombstone_key(key))

    def _write_tombstone(
        self,
        bucket: str,
        key: str,
        user_id: Optional[str],
        reason: str,
        approval_id: Optional[str] = None,
    ):
        tombstone_metadata = {
            "deleted_by": user_id or "system",
            "deleted_at": datetime.utcnow().isoformat(),
            "reason": reason,
        }
        if approval_id:
            tombstone_metadata["approval_id"] = approval_id
        self.client.upload_bytes(
            bucket=bucket,
            key=self._tombstone_key(key),
            data=b"",
            content_type="application/x-tombstone",
            metadata=tombstone_metadata,
        )

    def _check_worm_delete_allowed(self, bucket: str, key: str):
        """Enforce WORM retention before any delete.

        COMPLIANCE: hard refusal while the object is within retention.
        GOVERNANCE: retention refusal, overridable only through the approved
        dual-control hard-delete path (which re-checks retention expiry).
        OFF: no retention block.
        """
        if self.policy.worm_mode == WormMode.OFF:
            return
        try:
            meta = self.client.head_object(bucket, key)
        except Exception:
            return  # nothing to delete; let the caller's flow handle 404s
        uploaded_at = None
        raw_ts = (meta.metadata or {}).get("upload_timestamp")
        if raw_ts:
            try:
                uploaded_at = datetime.fromisoformat(raw_ts)
            except ValueError:
                uploaded_at = None
        if uploaded_at is None and meta.last_modified is not None:
            uploaded_at = meta.last_modified
            if hasattr(uploaded_at, "replace"):
                uploaded_at = uploaded_at.replace(tzinfo=None)
        if uploaded_at is None:
            # Unknown age -> fail closed: treat as within retention.
            raise DualControlViolation(
                f"WORM {self.policy.worm_mode.value}: cannot determine age of "
                f"{bucket}/{key}; delete refused (fail closed)"
            )
        retention_until = uploaded_at + timedelta(days=self.policy.worm_retention_days)
        if datetime.utcnow() < retention_until:
            if self.policy.worm_mode == WormMode.COMPLIANCE:
                raise DualControlViolation(
                    f"WORM COMPLIANCE: {bucket}/{key} is locked until "
                    f"{retention_until.isoformat()}Z; deletion is blocked absolutely"
                )
            raise DualControlViolation(
                f"WORM GOVERNANCE: {bucket}/{key} is within retention until "
                f"{retention_until.isoformat()}Z; use soft-delete (tombstone) instead"
            )

    def upload_document(
        self,
        bucket: str,
        key: str,
        file_path: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        skip_validation: bool = False,
    ) -> UploadResult:
        """
        Upload a document with validation and audit logging

        Args:
            bucket: Target bucket
            key: Object key
            file_path: Local file path
            user_id: User performing the operation
            ip_address: Client IP address
            metadata: Custom metadata
            skip_validation: Skip content validation (not recommended)

        Returns:
            UploadResult with upload details

        Raises:
            ValueError: If validation fails
            IOError: If upload fails
        """
        self._assert_writable()
        self._ensure_versioned(bucket)
        if not skip_validation:
            validation_result = self._validate_content(file_path)
            if validation_result != ContentValidationResult.VALID:
                self._log_audit(
                    operation=StorageOperation.UPLOAD,
                    bucket=bucket,
                    key=key,
                    user_id=user_id,
                    ip_address=ip_address,
                    success=False,
                    error_message=f"Validation failed: {validation_result.value}",
                )
                raise ValueError(f"Content validation failed: {validation_result.value}")

        content_type = self._detect_content_type(file_path)

        upload_metadata = {
            "uploaded_by": user_id or "system",
            "upload_timestamp": datetime.utcnow().isoformat(),
            "original_filename": os.path.basename(file_path),
        }
        if metadata:
            upload_metadata.update(metadata)

        overwrite = bool(self._guard) and self.client.object_exists(bucket, key)
        try:
            result = self.client.upload_file(
                bucket=bucket,
                key=key,
                file_path=file_path,
                content_type=content_type,
                metadata=upload_metadata,
            )
            try:
                with open(file_path, "rb") as fh:
                    sample = fh.read(65536)
            except OSError:
                sample = b""
            self._observe_upload(user_id, bucket, key, overwrite, sample)

            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"size": result.size, "etag": result.etag,
                          "version_id": result.version_id},
            )

            return result

        except Exception as e:
            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    def upload_bytes(
        self,
        bucket: str,
        key: str,
        data: bytes,
        content_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> UploadResult:
        """Upload bytes with validation and audit logging"""
        self._assert_writable()
        self._ensure_versioned(bucket)
        if len(data) > self.policy.max_file_size:
            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=f"File size {len(data)} exceeds maximum {self.policy.max_file_size}",
            )
            raise ValueError(f"File size exceeds maximum allowed: {self.policy.max_file_size}")

        if content_type not in self.policy.allowed_content_types:
            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=f"Content type {content_type} not allowed",
            )
            raise ValueError(f"Content type not allowed: {content_type}")

        upload_metadata = {
            "uploaded_by": user_id or "system",
            "upload_timestamp": datetime.utcnow().isoformat(),
        }
        if metadata:
            upload_metadata.update(metadata)

        overwrite = bool(self._guard) and self.client.object_exists(bucket, key)
        try:
            result = self.client.upload_bytes(
                bucket=bucket,
                key=key,
                data=data,
                content_type=content_type,
                metadata=upload_metadata,
            )
            self._observe_upload(user_id, bucket, key, overwrite, data[:65536])

            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"size": result.size, "etag": result.etag,
                          "version_id": result.version_id},
            )

            return result

        except Exception as e:
            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    def download_document(
        self,
        bucket: str,
        key: str,
        file_path: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        """Download a document with audit logging"""
        if self._is_tombstoned(bucket, key):
            self._log_audit(
                operation=StorageOperation.DOWNLOAD,
                bucket=bucket, key=key, user_id=user_id, ip_address=ip_address,
                success=False, error_message="object is tombstoned (soft-deleted)",
            )
            raise FileNotFoundError(f"{bucket}/{key} has been soft-deleted (tombstoned)")
        try:
            result = self.client.download_file(bucket, key, file_path)

            self._log_audit(
                operation=StorageOperation.DOWNLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
            )

            return result

        except Exception as e:
            self._log_audit(
                operation=StorageOperation.DOWNLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    def download_bytes(
        self,
        bucket: str,
        key: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> bytes:
        """Download document as bytes with audit logging"""
        if self._is_tombstoned(bucket, key):
            self._log_audit(
                operation=StorageOperation.DOWNLOAD,
                bucket=bucket, key=key, user_id=user_id, ip_address=ip_address,
                success=False, error_message="object is tombstoned (soft-deleted)",
            )
            raise FileNotFoundError(f"{bucket}/{key} has been soft-deleted (tombstoned)")
        try:
            data = self.client.download_bytes(bucket, key)

            self._log_audit(
                operation=StorageOperation.DOWNLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"size": len(data)},
            )

            return data

        except Exception as e:
            self._log_audit(
                operation=StorageOperation.DOWNLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    def delete_document(
        self,
        bucket: str,
        key: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        reason: str = "user-requested",
    ) -> bool:
        """Soft-delete a document: write a tombstone, keep the object.

        The original object (and all its versions) is retained. In WORM
        compliance/governance mode within retention, even soft-delete markers
        are still allowed (data is preserved), but hard deletion is blocked —
        see :meth:`hard_delete_document`.
        """
        self._assert_writable()
        try:
            if self._is_tombstoned(bucket, key):
                return True  # idempotent: already soft-deleted

            if not self.client.object_exists(bucket, key):
                self._log_audit(
                    operation=StorageOperation.DELETE,
                    bucket=bucket, key=key, user_id=user_id, ip_address=ip_address,
                    success=False, error_message="object not found",
                )
                raise FileNotFoundError(f"{bucket}/{key} does not exist")

            self._write_tombstone(bucket, key, user_id, reason)
            self._observe_delete(user_id, bucket, key)

            self._log_audit(
                operation=StorageOperation.DELETE,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"soft_delete": True, "reason": reason},
            )

            return True

        except Exception as e:
            self._log_audit(
                operation=StorageOperation.DELETE,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    # ------------------------------------------------------------------
    # Dual-control destructive operations (P0-2 / P1-1)
    # ------------------------------------------------------------------

    @property
    def token_issuer(self) -> DeleteTokenIssuer:
        if self._token_issuer is None:
            self._token_issuer = DeleteTokenIssuer()  # fail closed w/o key
        return self._token_issuer

    def request_deletion(
        self,
        bucket: str,
        key: str,
        requester_id: str,
        reason: str,
        version_id: Optional[str] = None,
    ) -> DeletionRequest:
        """Step 1 of dual control: record a deletion request."""
        if not self.policy.dual_control_required:
            raise DualControlViolation("dual control is disabled by policy; refusing request API")
        if self.approval_store is None:
            raise DualControlViolation("no deletion approval store configured")
        return self.approval_store.create_request(bucket, key, requester_id, reason, version_id)

    def approve_deletion(self, approval_id: str, approver_id: str) -> str:
        """Step 2 of dual control: a DIFFERENT principal approves; returns a
        signed, single-use delete token (TTL-bounded)."""
        if self.approval_store is None:
            raise DualControlViolation("no deletion approval store configured")
        approved = self.approval_store.approve(approval_id, approver_id)
        token = self.token_issuer.issue(approved)
        self._log_audit(
            operation=StorageOperation.DELETE,
            bucket=approved.bucket,
            key=approved.key,
            user_id=approver_id,
            ip_address=None,
            success=True,
            metadata={"approval_id": approval_id, "approval_granted": True},
        )
        return token

    def hard_delete_document(
        self,
        bucket: str,
        key: str,
        delete_token: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Physically delete an object — requires a signed delete token backed
        by an approved dual-control request, plus WORM retention expiry.

        Barriers enforced in code (fail closed on every one):
          1. global read-only lockdown
          2. WORM retention (compliance/governance)
          3. signed token valid, unexpired, bound to bucket/key, single-use
          4. underlying approval exists, is approved, requester != approver
          5. tombstone grace window elapsed (for soft-deleted objects)
        """
        self._assert_writable()
        self._check_worm_delete_allowed(bucket, key)

        claims = self.token_issuer.verify(delete_token, bucket, key)

        if self.policy.dual_control_required:
            if self.approval_store is None:
                raise DualControlViolation("no deletion approval store configured")
            approval = self.approval_store.get(claims["approval_id"])
            if approval is None or approval.status != "approved":
                raise DualControlViolation(
                    "hard delete requires an approved deletion request"
                )
            if approval.requester_id == approval.approver_id:
                raise DualControlViolation(
                    "dual control violated: requester and approver must differ"
                )

        # Tombstone grace window: hard delete only after the soft-delete
        # retention window has elapsed (unless the object was never tombstoned
        # and is past WORM retention — checked above).
        if self._is_tombstoned(bucket, key):
            tombstone = self.client.head_object(bucket, self._tombstone_key(key))
            deleted_at_raw = (tombstone.metadata or {}).get("deleted_at")
            if deleted_at_raw:
                deleted_at = datetime.fromisoformat(deleted_at_raw)
                grace_until = deleted_at + timedelta(
                    days=self.policy.soft_delete_tombstone_retention_days
                )
                if datetime.utcnow() < grace_until:
                    raise DualControlViolation(
                        f"tombstone grace window active until {grace_until.isoformat()}Z; "
                        "hard delete not yet eligible"
                    )

        try:
            result = self.client.delete_object(bucket, key, version_id=claims.get("version_id"))
            if self._is_tombstoned(bucket, key):
                self.client.delete_object(bucket, self._tombstone_key(key))
            self._observe_delete(user_id, bucket, key)
            self.token_issuer.consume(claims)
            if self.approval_store is not None and self.policy.dual_control_required:
                self.approval_store.mark_executed(claims["approval_id"])

            self._log_audit(
                operation=StorageOperation.DELETE,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=result,
                metadata={"hard_delete": True, "approval_id": claims["approval_id"]},
            )
            return result
        except Exception as e:
            self._log_audit(
                operation=StorageOperation.DELETE,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    def restore_document(
        self,
        bucket: str,
        key: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Remove a tombstone, restoring read access to a soft-deleted object."""
        self._assert_writable()
        if not self._is_tombstoned(bucket, key):
            return False
        self.client.delete_object(bucket, self._tombstone_key(key))
        self._log_audit(
            operation=StorageOperation.DELETE,
            bucket=bucket,
            key=key,
            user_id=user_id,
            ip_address=ip_address,
            success=True,
            metadata={"tombstone_removed": True, "restored": True},
        )
        return True

    def generate_presigned_url(
        self,
        bucket: str,
        key: str,
        expires_in: int = 3600,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        """Generate a presigned URL with audit logging"""
        try:
            url = self.client.generate_presigned_url(bucket, key, expires_in)

            self._log_audit(
                operation=StorageOperation.PRESIGN,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"expires_in": expires_in},
            )

            return url

        except Exception as e:
            self._log_audit(
                operation=StorageOperation.PRESIGN,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    def list_documents(
        self,
        bucket: str,
        prefix: str = "",
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List documents with audit logging.

        Tombstone markers and tombstoned (soft-deleted) objects are hidden
        from normal listings, mirroring the v_active_* database views.
        """
        try:
            result = self.client.list_objects(bucket, prefix)
            objects = result["objects"]

            def _obj_key(o):
                return o.key if hasattr(o, "key") else o.get("key")

            keys = {_obj_key(o) for o in objects}
            visible = []
            for o in objects:
                o_key = _obj_key(o)
                if o_key.endswith(TOMBSTONE_SUFFIX):
                    continue
                if self._tombstone_key(o_key) in keys:
                    continue
                visible.append(o)

            self._log_audit(
                operation=StorageOperation.LIST,
                bucket=bucket,
                key=prefix,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"count": len(visible)},
            )

            return visible

        except Exception as e:
            self._log_audit(
                operation=StorageOperation.LIST,
                bucket=bucket,
                key=prefix,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                error_message=str(e),
            )
            raise

    def _validate_content(self, file_path: str) -> ContentValidationResult:
        """Validate file content against policy"""
        if not os.path.exists(file_path):
            return ContentValidationResult.UNKNOWN

        file_size = os.path.getsize(file_path)
        if file_size > self.policy.max_file_size:
            return ContentValidationResult.INVALID_SIZE

        content_type = self._detect_content_type(file_path)
        if content_type not in self.policy.allowed_content_types:
            return ContentValidationResult.INVALID_TYPE

        if self.policy.enable_virus_scan:
            if not self._scan_for_viruses(file_path):
                return ContentValidationResult.MALICIOUS

        return ContentValidationResult.VALID

    def _detect_content_type(self, file_path: str) -> str:
        """Detect content type from file"""
        content_type, _ = mimetypes.guess_type(file_path)
        return content_type or "application/octet-stream"

    def _scan_for_viruses(self, file_path: str) -> bool:
        """Scan a file through a configured ClamAV daemon using its INSTREAM protocol.

        The method deliberately fails closed: an absent endpoint, network failure, malformed daemon
        response, or an explicit malware signature all return ``False`` and block the upload.
        """
        host = os.getenv("CLAMAV_HOST", "").strip()
        port_text = os.getenv("CLAMAV_PORT", "3310").strip()
        timeout_text = os.getenv("CLAMAV_TIMEOUT_SECONDS", "10").strip()
        if not host:
            logger.error("CLAMAV_HOST must be configured when virus scanning is enabled")
            return False
        try:
            port = int(port_text)
            timeout = float(timeout_text)
            if not (0 < port <= 65535 and timeout > 0):
                raise ValueError("invalid ClamAV connection settings")
            with socket.create_connection((host, port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                connection.sendall(b"zINSTREAM\\0")
                with open(file_path, "rb") as source:
                    while chunk := source.read(1024 * 1024):
                        connection.sendall(struct.pack("!I", len(chunk)))
                        connection.sendall(chunk)
                connection.sendall(struct.pack("!I", 0))
                response = connection.recv(4096).decode("utf-8", errors="replace").strip()
        except (OSError, ValueError) as error:
            logger.error("ClamAV scan failed closed for %s: %s", file_path, error)
            return False

        if response.endswith("OK"):
            return True
        logger.warning("ClamAV rejected %s: %s", file_path, response)
        return False

    def _log_audit(
        self,
        operation: StorageOperation,
        bucket: str,
        key: str,
        user_id: Optional[str],
        ip_address: Optional[str],
        success: bool,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Log audit entry"""
        if not self.policy.enable_audit_log:
            return

        entry = AuditLogEntry(
            timestamp=datetime.utcnow(),
            operation=operation,
            bucket=bucket,
            key=key,
            user_id=user_id,
            ip_address=ip_address,
            success=success,
            error_message=error_message,
            metadata=metadata or {},
        )

        self._audit_log.append(entry)

        if self.audit_callback:
            try:
                self.audit_callback(entry)
            except Exception as e:
                logger.error(f"Audit callback failed: {e}")

        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"Storage {operation.value}: {bucket}/{key} by {user_id} - {'success' if success else 'failed'}",
        )

    def get_audit_log(
        self,
        bucket: Optional[str] = None,
        user_id: Optional[str] = None,
        operation: Optional[StorageOperation] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[AuditLogEntry]:
        """Query audit log with filters"""
        results = self._audit_log

        if bucket:
            results = [e for e in results if e.bucket == bucket]

        if user_id:
            results = [e for e in results if e.user_id == user_id]

        if operation:
            results = [e for e in results if e.operation == operation]

        if start_time:
            results = [e for e in results if e.timestamp >= start_time]

        if end_time:
            results = [e for e in results if e.timestamp <= end_time]

        return results

    def health_check(self) -> Dict[str, Any]:
        """Check storage gateway health"""
        rustfs_health = self.client.health_check()

        return {
            "gateway": "healthy",
            "storage_backend": rustfs_health,
            "policy": {
                "max_file_size": self.policy.max_file_size,
                "allowed_types": len(self.policy.allowed_content_types),
                "virus_scan_enabled": self.policy.enable_virus_scan,
                "audit_enabled": self.policy.enable_audit_log,
            },
            "audit_log_entries": len(self._audit_log),
        }


class MultiTenantStorageGateway(StorageGateway):
    """
    Multi-tenant storage gateway with tenant isolation

    Provides tenant-specific buckets and access control.
    """

    def __init__(
        self,
        client: Optional[RustFSClient] = None,
        policy: Optional[StoragePolicy] = None,
        bucket_prefix: str = "tenant",
        audit_callback: Optional[Callable[[AuditLogEntry], None]] = None,
        approval_store: Optional[DeletionApprovalStore] = None,
        token_issuer: Optional[DeleteTokenIssuer] = None,
    ):
        """Initialize multi-tenant gateway"""
        super().__init__(client, policy, audit_callback, approval_store, token_issuer)
        self.bucket_prefix = bucket_prefix

    def get_tenant_bucket(self, tenant_id: str) -> str:
        """Get bucket name for tenant"""
        return f"{self.bucket_prefix}-{tenant_id}"

    def ensure_tenant_bucket(self, tenant_id: str) -> str:
        """Ensure tenant bucket exists with anti-wipe protection attached"""
        bucket = self.get_tenant_bucket(tenant_id)
        if not self.client.bucket_exists(bucket):
            self.client.create_bucket(bucket)
            # Attach bucket-level protection policy at creation time
            if self.policy.require_versioning:
                self.client.enable_bucket_versioning(bucket)
            if self.policy.worm_mode != WormMode.OFF:
                try:
                    self.client.put_object_lock_configuration(
                        bucket,
                        mode="COMPLIANCE" if self.policy.worm_mode == WormMode.COMPLIANCE else "GOVERNANCE",
                        retention_days=self.policy.worm_retention_days,
                    )
                except Exception as e:
                    logger.error(f"Failed to set object lock on {bucket}: {e}")
                    if self.policy.worm_mode == WormMode.COMPLIANCE:
                        raise  # fail closed for compliance buckets
        return bucket

    def upload_tenant_document(
        self,
        tenant_id: str,
        key: str,
        file_path: str,
        user_id: Optional[str] = None,
        **kwargs,
    ) -> UploadResult:
        """Upload document to tenant bucket"""
        bucket = self.ensure_tenant_bucket(tenant_id)
        return self.upload_document(bucket, key, file_path, user_id, **kwargs)

    def download_tenant_document(
        self,
        tenant_id: str,
        key: str,
        file_path: str,
        user_id: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Download document from tenant bucket"""
        bucket = self.get_tenant_bucket(tenant_id)
        return self.download_document(bucket, key, file_path, user_id, **kwargs)

    def list_tenant_documents(
        self,
        tenant_id: str,
        prefix: str = "",
        user_id: Optional[str] = None,
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """List documents in tenant bucket"""
        bucket = self.get_tenant_bucket(tenant_id)
        return self.list_documents(bucket, prefix, user_id, **kwargs)


if __name__ == "__main__":
    gateway = StorageGateway()
    health = gateway.health_check()
    print(f"Gateway Health: {json.dumps(health, indent=2)}")
