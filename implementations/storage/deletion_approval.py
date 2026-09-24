"""
Dual-control deletion approvals and signed delete tokens.

Implements the 4-eyes principle for destructive storage operations:

1. A **deletion request** is recorded in an append-only store
   (``deletion_approvals`` JSONL ledger mirroring the database table from
   ``database/20260825_antiwipe_soft_delete.sql``).
2. A **different principal** must approve it (``requester_id != approver_id``
   enforced in code).
3. Approval yields a short-lived **signed delete token**: HMAC-SHA256 over
   ``(bucket, key, version_id, approval_id, expiry, jti)`` keyed by
   ``DELETE_TOKEN_KEY`` / ``DELETE_TOKEN_KEY_URI``. Tokens are single-use
   (jti tracked) and expire (default 300s TTL).

Only a valid token plus an approved request authorizes a hard delete in
``storage_gateway.StorageGateway.hard_delete_document`` and in the Rust
gateway DELETE handler.
"""

import json
import hmac
import hashlib
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Union

logger = logging.getLogger(__name__)

DEFAULT_TOKEN_TTL_SECONDS = 300


class DualControlViolation(PermissionError):
    """Raised when a destructive operation violates dual-control rules."""


@dataclass
class DeletionRequest:
    approval_id: str
    bucket: str
    key: str
    requester_id: str
    reason: str
    version_id: Optional[str] = None
    approver_id: Optional[str] = None
    status: str = "pending"  # pending | approved | rejected | executed
    requested_at: str = ""
    approved_at: Optional[str] = None


class DeletionApprovalStore:
    """Append-only JSONL ledger of deletion requests/approvals.

    The file ledger is the local stand-in for the ``deletion_approvals``
    database table; rows are never mutated in place — status changes are
    appended as new records and the latest record wins.
    """

    def __init__(self, path: Optional[Union[str, Path]] = None):
        self.path = Path(
            path
            or os.getenv("DELETION_APPROVALS_PATH")
            or "/var/lib/fraudfusion/storage/deletion_approvals.jsonl"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _append(self, record: DeletionRequest):
        with self._lock:
            with open(self.path, "a") as f:
                f.write(json.dumps(asdict(record), default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())

    def _load_all(self) -> Dict[str, DeletionRequest]:
        latest: Dict[str, DeletionRequest] = {}
        if not self.path.exists():
            return latest
        with open(self.path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                record = DeletionRequest(**json.loads(line))
                latest[record.approval_id] = record
        return latest

    def create_request(
        self,
        bucket: str,
        key: str,
        requester_id: str,
        reason: str,
        version_id: Optional[str] = None,
    ) -> DeletionRequest:
        if not requester_id:
            raise DualControlViolation("deletion requests require an authenticated requester")
        if not reason or not reason.strip():
            raise DualControlViolation("deletion requests require a reason")
        record = DeletionRequest(
            approval_id=str(uuid.uuid4()),
            bucket=bucket,
            key=key,
            requester_id=requester_id,
            reason=reason.strip(),
            version_id=version_id,
            requested_at=datetime.utcnow().isoformat() + "Z",
        )
        self._append(record)
        return record

    def approve(self, approval_id: str, approver_id: str) -> DeletionRequest:
        latest = self._load_all()
        record = latest.get(approval_id)
        if record is None:
            raise DualControlViolation(f"unknown deletion request {approval_id}")
        if record.status != "pending":
            raise DualControlViolation(f"deletion request {approval_id} is {record.status}")
        if not approver_id or approver_id == record.requester_id:
            # 4-eyes: approver must be a different principal than requester
            raise DualControlViolation(
                "dual control violated: approver must differ from requester"
            )
        approved = DeletionRequest(
            **{**asdict(record),
               "approver_id": approver_id,
               "status": "approved",
               "approved_at": datetime.utcnow().isoformat() + "Z"}
        )
        self._append(approved)
        return approved

    def mark_executed(self, approval_id: str) -> DeletionRequest:
        latest = self._load_all()
        record = latest.get(approval_id)
        if record is None or record.status != "approved":
            raise DualControlViolation(
                f"deletion request {approval_id} is not in an approved state"
            )
        executed = DeletionRequest(**{**asdict(record), "status": "executed"})
        self._append(executed)
        return executed

    def get(self, approval_id: str) -> Optional[DeletionRequest]:
        return self._load_all().get(approval_id)


class DeleteTokenIssuer:
    """Issues and verifies signed, single-use, short-lived delete tokens.

    Token format: ``v1|bucket|key|version_id|approval_id|expiry|jti|hmac_hex``
    """

    VERSION = "v1"

    def __init__(
        self,
        key: Optional[Union[str, bytes]] = None,
        ttl_seconds: Optional[int] = None,
        used_jti_path: Optional[Union[str, Path]] = None,
    ):
        self._key = self._resolve_key(key)
        self.ttl_seconds = ttl_seconds or int(
            os.getenv("DELETE_TOKEN_TTL_SECONDS", str(DEFAULT_TOKEN_TTL_SECONDS))
        )
        if self.ttl_seconds > 900:
            raise ValueError("delete token TTL must not exceed 900 seconds")
        self._used_jti_path = Path(used_jti_path) if used_jti_path else None
        self._used_jtis: set = set()
        self._lock = threading.Lock()

    @staticmethod
    def _resolve_key(key: Optional[Union[str, bytes]]) -> bytes:
        if key is None:
            env_key = os.getenv("DELETE_TOKEN_KEY", "").strip()
            if env_key:
                key = env_key
        if key is None:
            uri = os.getenv("DELETE_TOKEN_KEY_URI", "").strip()
            if uri.startswith("file://"):
                key = Path(uri[len("file://"):]).read_bytes().strip()
        if key is None:
            raise RuntimeError(
                "DELETE_TOKEN_KEY or DELETE_TOKEN_KEY_URI must be configured; "
                "hard deletes fail closed without a token signing key"
            )
        if isinstance(key, str):
            try:
                return bytes.fromhex(key)
            except ValueError:
                return key.encode("utf-8")
        return bytes(key)

    def _sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()

    def issue(self, approval: DeletionRequest) -> str:
        """Issue a signed delete token for an APPROVED deletion request."""
        if approval.status != "approved" or not approval.approver_id:
            raise DualControlViolation(
                "delete tokens can only be issued for approved requests"
            )
        if approval.approver_id == approval.requester_id:
            raise DualControlViolation(
                "dual control violated on the underlying request"
            )
        expiry = int(time.time()) + self.ttl_seconds
        jti = str(uuid.uuid4())
        payload = "|".join([
            self.VERSION,
            approval.bucket,
            approval.key,
            approval.version_id or "",
            approval.approval_id,
            str(expiry),
            jti,
        ])
        return f"{payload}|{self._sign(payload)}"

    def verify(self, token: str, bucket: str, key: str) -> Dict:
        """Verify a delete token for (bucket, key). Returns token claims dict.

        Raises DualControlViolation on any failure (fail closed).
        """
        parts = token.split("|")
        if len(parts) != 8 or parts[0] != self.VERSION:
            raise DualControlViolation("malformed delete token")
        _, t_bucket, t_key, t_version, approval_id, expiry_text, jti, signature = parts
        payload = "|".join(parts[:-1])
        if not hmac.compare_digest(self._sign(payload), signature):
            raise DualControlViolation("delete token signature invalid")
        if t_bucket != bucket or t_key != key:
            raise DualControlViolation(
                f"delete token is bound to {t_bucket}/{t_key}, not {bucket}/{key}"
            )
        if int(expiry_text) < int(time.time()):
            raise DualControlViolation("delete token expired")
        with self._lock:
            if jti in self._used_jtis or self._jti_seen_on_disk(jti):
                raise DualControlViolation("delete token already used (single-use)")
        return {
            "bucket": t_bucket,
            "key": t_key,
            "version_id": t_version or None,
            "approval_id": approval_id,
            "expiry": int(expiry_text),
            "jti": jti,
        }

    def consume(self, claims: Dict) -> None:
        """Mark a verified token's jti as used. Call AFTER the delete succeeds."""
        with self._lock:
            self._used_jtis.add(claims["jti"])
            if self._used_jti_path:
                self._used_jti_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._used_jti_path, "a") as f:
                    f.write(claims["jti"] + "\n")

    def _jti_seen_on_disk(self, jti: str) -> bool:
        if not self._used_jti_path or not self._used_jti_path.exists():
            return False
        with open(self._used_jti_path, "r") as f:
            return jti in {line.strip() for line in f}
