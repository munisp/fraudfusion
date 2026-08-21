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
from datetime import datetime
from enum import Enum
import json

from .rustfs_client import RustFSClient, RustFSConfig, UploadResult, ObjectMetadata

logger = logging.getLogger(__name__)


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
    ):
        """Initialize storage gateway"""
        self.client = client or RustFSClient()
        self.policy = policy or StoragePolicy()
        self.audit_callback = audit_callback
        self._audit_log: List[AuditLogEntry] = []

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

        try:
            result = self.client.upload_file(
                bucket=bucket,
                key=key,
                file_path=file_path,
                content_type=content_type,
                metadata=upload_metadata,
            )

            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"size": result.size, "etag": result.etag},
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

        try:
            result = self.client.upload_bytes(
                bucket=bucket,
                key=key,
                data=data,
                content_type=content_type,
                metadata=upload_metadata,
            )

            self._log_audit(
                operation=StorageOperation.UPLOAD,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"size": result.size, "etag": result.etag},
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
    ) -> bool:
        """Delete a document with audit logging"""
        try:
            result = self.client.delete_object(bucket, key)

            self._log_audit(
                operation=StorageOperation.DELETE,
                bucket=bucket,
                key=key,
                user_id=user_id,
                ip_address=ip_address,
                success=result,
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
        """List documents with audit logging"""
        try:
            result = self.client.list_objects(bucket, prefix)

            self._log_audit(
                operation=StorageOperation.LIST,
                bucket=bucket,
                key=prefix,
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                metadata={"count": result["key_count"]},
            )

            return result["objects"]

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
    ):
        """Initialize multi-tenant gateway"""
        super().__init__(client, policy)
        self.bucket_prefix = bucket_prefix

    def get_tenant_bucket(self, tenant_id: str) -> str:
        """Get bucket name for tenant"""
        return f"{self.bucket_prefix}-{tenant_id}"

    def ensure_tenant_bucket(self, tenant_id: str) -> str:
        """Ensure tenant bucket exists"""
        bucket = self.get_tenant_bucket(tenant_id)
        if not self.client.bucket_exists(bucket):
            self.client.create_bucket(bucket)
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
