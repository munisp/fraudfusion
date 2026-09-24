"""
RustFS (S3-compatible) storage client for the FraudFusion storage gateway.

Thin wrapper over a boto3 S3 client pointed at a RustFS endpoint. boto3 is
imported lazily so unit tests can substitute a fake client without the AWS
SDK installed. All destructive and control-plane operations are exposed here;
anti-wipe policy (versioning enforcement, tombstones, dual control) lives in
``storage_gateway.py`` / ``deletion_approval.py``.
"""

import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


@dataclass
class RustFSConfig:
    """Connection configuration for the RustFS backend."""
    endpoint_url: str = ""
    access_key: str = ""
    secret_key: str = ""
    region: str = "us-east-1"
    secure: bool = True

    @classmethod
    def from_env(cls) -> "RustFSConfig":
        endpoint = os.getenv("RUSTFS_ENDPOINT") or os.getenv("S3_ENDPOINT") or ""
        if not endpoint:
            raise RuntimeError("RUSTFS_ENDPOINT must be configured")
        allow_insecure = os.getenv("RUSTFS_ALLOW_INSECURE_HTTP", "").lower() == "true"
        if not allow_insecure and not endpoint.startswith("https://"):
            raise RuntimeError(
                "RUSTFS_ENDPOINT must use https:// unless "
                "RUSTFS_ALLOW_INSECURE_HTTP=true is set for local development"
            )
        return cls(
            endpoint_url=endpoint,
            access_key=os.getenv("RUSTFS_ACCESS_KEY") or os.getenv("S3_ACCESS_KEY") or "",
            secret_key=os.getenv("RUSTFS_SECRET_KEY") or os.getenv("S3_SECRET_KEY") or "",
            region=os.getenv("RUSTFS_REGION") or os.getenv("AWS_REGION") or "us-east-1",
            secure=endpoint.startswith("https://"),
        )


@dataclass
class UploadResult:
    """Result of an object upload."""
    bucket: str
    key: str
    etag: str = ""
    size: int = 0
    version_id: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class ObjectMetadata:
    """Object metadata record."""
    key: str
    size: int = 0
    etag: str = ""
    last_modified: Optional[datetime] = None
    content_type: Optional[str] = None
    version_id: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)


class RustFSClient:
    """
    Low-level RustFS/S3 client.

    Parameters
    ----------
    config:
        Connection configuration (defaults to ``RustFSConfig.from_env()``).
    s3_client:
        Optional pre-built boto3 S3 client (used by tests to inject fakes).
    """

    def __init__(self, config: Optional[RustFSConfig] = None, s3_client: Any = None):
        self.config = config or RustFSConfig.from_env()
        self._s3 = s3_client

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @property
    def s3(self):
        if self._s3 is None:
            try:
                import boto3  # lazy import; not required for unit tests
            except ImportError as e:
                raise RuntimeError(
                    "boto3 is required for the RustFS client at runtime "
                    "(pip install boto3)"
                ) from e
            self._s3 = boto3.client(
                "s3",
                endpoint_url=self.config.endpoint_url,
                aws_access_key_id=self.config.access_key,
                aws_secret_access_key=self.config.secret_key,
                region_name=self.config.region,
                use_ssl=self.config.secure,
            )
        return self._s3

    # ------------------------------------------------------------------
    # Health / buckets
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        try:
            self.s3.list_buckets()
            return {"status": "healthy", "endpoint": self.config.endpoint_url}
        except Exception as e:
            return {"status": "unhealthy", "endpoint": self.config.endpoint_url, "error": str(e)}

    def bucket_exists(self, bucket: str) -> bool:
        try:
            self.s3.head_bucket(Bucket=bucket)
            return True
        except Exception:
            return False

    def create_bucket(self, bucket: str) -> bool:
        self.s3.create_bucket(Bucket=bucket)
        return True

    def get_bucket_versioning(self, bucket: str) -> str:
        """Return 'Enabled', 'Suspended', or 'Disabled' (never configured)."""
        resp = self.s3.get_bucket_versioning(Bucket=bucket)
        return resp.get("Status", "Disabled")

    def enable_bucket_versioning(self, bucket: str) -> bool:
        self.s3.put_bucket_versioning(
            Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        return True

    def put_object_lock_configuration(
        self, bucket: str, mode: str = "COMPLIANCE", retention_days: int = 2555
    ) -> bool:
        """Enable a default object-lock retention rule on a bucket.

        COMPLIANCE mode is irreversible by design: locked versions cannot be
        deleted by anyone (including root) until retention expires.
        """
        self.s3.put_object_lock_configuration(
            Bucket=bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {"Mode": mode, "Days": retention_days}
                },
            },
        )
        return True

    # ------------------------------------------------------------------
    # Objects
    # ------------------------------------------------------------------

    def upload_file(
        self,
        bucket: str,
        key: str,
        file_path: str,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> UploadResult:
        extra: Dict[str, Any] = {}
        if content_type:
            extra["ContentType"] = content_type
        if metadata:
            extra["Metadata"] = {k: str(v) for k, v in metadata.items()}
        resp = self.s3.put_object(Bucket=bucket, Key=key, Body=open(file_path, "rb").read(), **extra)
        return UploadResult(
            bucket=bucket,
            key=key,
            etag=resp.get("ETag", "").strip('"'),
            size=os.path.getsize(file_path),
            version_id=resp.get("VersionId"),
            content_type=content_type,
        )

    def upload_bytes(
        self,
        bucket: str,
        key: str,
        data: bytes,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> UploadResult:
        extra: Dict[str, Any] = {}
        if content_type:
            extra["ContentType"] = content_type
        if metadata:
            extra["Metadata"] = {k: str(v) for k, v in metadata.items()}
        resp = self.s3.put_object(Bucket=bucket, Key=key, Body=data, **extra)
        return UploadResult(
            bucket=bucket,
            key=key,
            etag=resp.get("ETag", "").strip('"'),
            size=len(data),
            version_id=resp.get("VersionId"),
            content_type=content_type,
        )

    def download_file(self, bucket: str, key: str, file_path: str) -> str:
        self.s3.download_file(bucket, key, file_path)
        return file_path

    def download_bytes(self, bucket: str, key: str) -> bytes:
        resp = self.s3.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()

    def delete_object(self, bucket: str, key: str, version_id: Optional[str] = None) -> bool:
        """Hard-delete an object (or a specific version). Callers must go
        through the gateway's dual-control path; this method performs no
        policy checks of its own."""
        args: Dict[str, Any] = {"Bucket": bucket, "Key": key}
        if version_id:
            args["VersionId"] = version_id
        self.s3.delete_object(**args)
        return True

    def object_exists(self, bucket: str, key: str) -> bool:
        try:
            self.s3.head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def head_object(self, bucket: str, key: str) -> ObjectMetadata:
        resp = self.s3.head_object(Bucket=bucket, Key=key)
        return ObjectMetadata(
            key=key,
            size=resp.get("ContentLength", 0),
            etag=resp.get("ETag", "").strip('"'),
            last_modified=resp.get("LastModified"),
            content_type=resp.get("ContentType"),
            version_id=resp.get("VersionId"),
            metadata=resp.get("Metadata", {}),
        )

    def list_objects(
        self,
        bucket: str,
        prefix: str = "",
        max_keys: int = 1000,
        continuation_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        args: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": max_keys}
        if continuation_token:
            args["ContinuationToken"] = continuation_token
        resp = self.s3.list_objects_v2(**args)
        objects = [
            ObjectMetadata(
                key=o["Key"],
                size=o.get("Size", 0),
                etag=o.get("ETag", "").strip('"'),
                last_modified=o.get("LastModified"),
            )
            for o in resp.get("Contents", [])
        ]
        return {
            "objects": objects,
            "key_count": resp.get("KeyCount", len(objects)),
            "is_truncated": resp.get("IsTruncated", False),
            "next_continuation_token": resp.get("NextContinuationToken"),
        }

    def generate_presigned_url(self, bucket: str, key: str, expires_in: int = 3600) -> str:
        return self.s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expires_in,
        )
