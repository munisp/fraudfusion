"""Tests for anti-wipe protection in the Python storage gateway.

Run: python3 -m pytest implementations/storage/tests/ -q
"""

import os
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from implementations.storage.storage_gateway import (
    StorageGateway,
    StoragePolicy,
    StorageOperation,
    StorageLockdownError,
    WormMode,
    TOMBSTONE_SUFFIX,
)
from implementations.storage.deletion_approval import (
    DeletionApprovalStore,
    DeleteTokenIssuer,
    DualControlViolation,
)
from implementations.storage.rustfs_client import UploadResult, ObjectMetadata


class FakeRustFSClient:
    """In-memory stand-in implementing the RustFSClient surface used by the
    gateway (with simulated bucket versioning)."""

    def __init__(self, versioning_enabled=True):
        self.buckets = {}
        self.versioning = {}
        self.object_lock = {}
        self.versioning_enabled_default = versioning_enabled

    # buckets ------------------------------------------------------------
    def health_check(self):
        return {"status": "healthy"}

    def bucket_exists(self, bucket):
        return bucket in self.buckets

    def create_bucket(self, bucket):
        self.buckets.setdefault(bucket, {})
        return True

    def get_bucket_versioning(self, bucket):
        return self.versioning.get(bucket, "Enabled" if self.versioning_enabled_default else "Disabled")

    def enable_bucket_versioning(self, bucket):
        self.versioning[bucket] = "Enabled"
        return True

    def put_object_lock_configuration(self, bucket, mode="COMPLIANCE", retention_days=2555):
        self.object_lock[bucket] = {"mode": mode, "days": retention_days}
        return True

    # objects ------------------------------------------------------------
    def _put(self, bucket, key, data, content_type, metadata):
        self.buckets.setdefault(bucket, {})[key] = {
            "data": data,
            "metadata": dict(metadata or {}),
            "etag": uuid.uuid4().hex,
            "version_id": uuid.uuid4().hex,
            "last_modified": datetime.utcnow(),
            "content_type": content_type,
        }
        obj = self.buckets[bucket][key]
        return UploadResult(bucket=bucket, key=key, etag=obj["etag"], size=len(data),
                            version_id=obj["version_id"], content_type=content_type)

    def upload_bytes(self, bucket, key, data, content_type=None, metadata=None):
        return self._put(bucket, key, data, content_type, metadata)

    def upload_file(self, bucket, key, file_path, content_type=None, metadata=None):
        with open(file_path, "rb") as f:
            return self._put(bucket, key, f.read(), content_type, metadata)

    def download_bytes(self, bucket, key):
        return self.buckets[bucket][key]["data"]

    def download_file(self, bucket, key, file_path):
        Path(file_path).write_bytes(self.buckets[bucket][key]["data"])
        return file_path

    def delete_object(self, bucket, key, version_id=None):
        self.buckets.get(bucket, {}).pop(key, None)
        return True

    def object_exists(self, bucket, key):
        return key in self.buckets.get(bucket, {})

    def head_object(self, bucket, key):
        obj = self.buckets[bucket][key]
        if key not in self.buckets[bucket]:
            raise KeyError(key)
        return ObjectMetadata(key=key, size=len(obj["data"]), etag=obj["etag"],
                              last_modified=obj["last_modified"],
                              content_type=obj["content_type"],
                              version_id=obj["version_id"], metadata=obj["metadata"])

    def list_objects(self, bucket, prefix="", max_keys=1000, continuation_token=None):
        objs = [ObjectMetadata(key=k, size=len(v["data"]), etag=v["etag"],
                               last_modified=v["last_modified"], content_type=v["content_type"],
                               version_id=v["version_id"], metadata=v["metadata"])
                for k, v in self.buckets.get(bucket, {}).items() if k.startswith(prefix)]
        return {"objects": objs, "key_count": len(objs), "is_truncated": False,
                "next_continuation_token": None}

    def generate_presigned_url(self, bucket, key, expires_in=3600):
        return f"https://fake.local/{bucket}/{key}?expires={expires_in}"


@pytest.fixture
def captured_audit():
    entries = []

    class Cap:
        def __call__(self, entry):
            entries.append(entry)

    Cap.entries = entries
    return Cap()


@pytest.fixture
def gateway(tmp_path, captured_audit):
    policy = StoragePolicy(
        worm_mode=WormMode.OFF,
        enable_virus_scan=False,
        soft_delete_tombstone_retention_days=90,
    )
    gw = StorageGateway(
        client=FakeRustFSClient(),
        policy=policy,
        audit_callback=captured_audit,
        approval_store=DeletionApprovalStore(tmp_path / "approvals.jsonl"),
        token_issuer=DeleteTokenIssuer(key=b"delete-token-test-key",
                                       used_jti_path=tmp_path / "jtis.txt"),
    )
    return gw


def upload(gw, bucket="evidence", key="kyc/doc1.pdf", data=b"pdf-bytes"):
    return gw.upload_bytes(bucket, key, data, "application/pdf", user_id="u1")


class TestVersioning:
    def test_put_creates_version(self, gateway):
        result = upload(gateway)
        assert result.version_id
        # audit trail records the version id
        uploads = [e for e in captured_audit_entries(gateway) if e.operation == StorageOperation.UPLOAD]
        assert uploads and uploads[-1].metadata.get("version_id") == result.version_id

    def test_versioning_fail_closed(self, tmp_path, captured_audit):
        client = FakeRustFSClient(versioning_enabled=False)

        def refuse(bucket):
            raise RuntimeError("backend rejected versioning")

        client.enable_bucket_versioning = refuse
        gw = StorageGateway(client=client,
                            policy=StoragePolicy(worm_mode=WormMode.OFF, enable_virus_scan=False),
                            audit_callback=captured_audit)
        with pytest.raises(RuntimeError, match="versioning"):
            gw.upload_bytes("evidence", "a.txt", b"x", "text/plain")


def captured_audit_entries(gw):
    return gw.audit_callback.entries


class TestSoftDelete:
    def test_delete_creates_tombstone_and_retains_object(self, gateway):
        upload(gateway)
        assert gateway.delete_document("evidence", "kyc/doc1.pdf", user_id="u1") is True
        assert gateway.client.object_exists("evidence", "kyc/doc1.pdf"), "original must be retained"
        assert gateway.client.object_exists("evidence", "kyc/doc1.pdf" + TOMBSTONE_SUFFIX)

    def test_tombstoned_reads_fail(self, gateway):
        upload(gateway)
        gateway.delete_document("evidence", "kyc/doc1.pdf", user_id="u1")
        with pytest.raises(FileNotFoundError):
            gateway.download_bytes("evidence", "kyc/doc1.pdf", user_id="u1")

    def test_tombstoned_hidden_from_listing(self, gateway):
        upload(gateway)
        upload(gateway, key="kyc/doc2.pdf")
        gateway.delete_document("evidence", "kyc/doc1.pdf", user_id="u1")
        keys = [o.key for o in gateway.list_documents("evidence", user_id="u1")]
        assert "kyc/doc2.pdf" in keys
        assert "kyc/doc1.pdf" not in keys
        assert not any(k.endswith(TOMBSTONE_SUFFIX) for k in keys)

    def test_restore_removes_tombstone(self, gateway):
        upload(gateway)
        gateway.delete_document("evidence", "kyc/doc1.pdf", user_id="u1")
        assert gateway.restore_document("evidence", "kyc/doc1.pdf", user_id="admin") is True
        assert gateway.download_bytes("evidence", "kyc/doc1.pdf") == b"pdf-bytes"

    def test_delete_nonexistent_raises(self, gateway):
        with pytest.raises(FileNotFoundError):
            gateway.delete_document("evidence", "nope", user_id="u1")


class TestDualControlHardDelete:
    def test_same_principal_approval_rejected(self, gateway):
        req = gateway.request_deletion("evidence", "kyc/doc1.pdf", "alice", "cleanup")
        with pytest.raises(DualControlViolation, match="differ"):
            gateway.approve_deletion(req.approval_id, "alice")

    def test_full_flow_and_single_use_token(self, gateway):
        upload(gateway)
        req = gateway.request_deletion("evidence", "kyc/doc1.pdf", "alice", "retention passed")
        token = gateway.approve_deletion(req.approval_id, "bob")

        # token is bound: wrong key rejected
        with pytest.raises(DualControlViolation, match="bound"):
            gateway.hard_delete_document("evidence", "other-key", token)

        # grace window: object not tombstoned here, worm off -> allowed
        assert gateway.hard_delete_document("evidence", "kyc/doc1.pdf", token, user_id="bob")
        assert not gateway.client.object_exists("evidence", "kyc/doc1.pdf")

        # token replay rejected (single-use jti)
        upload(gateway)
        with pytest.raises(DualControlViolation, match="single-use"):
            gateway.hard_delete_document("evidence", "kyc/doc1.pdf", token)

    def test_tombstone_grace_window(self, gateway):
        upload(gateway)
        gateway.delete_document("evidence", "kyc/doc1.pdf", user_id="u1")
        req = gateway.request_deletion("evidence", "kyc/doc1.pdf", "alice", "purge")
        token = gateway.approve_deletion(req.approval_id, "bob")
        with pytest.raises(DualControlViolation, match="grace window"):
            gateway.hard_delete_document("evidence", "kyc/doc1.pdf", token)

    def test_grace_window_elapsed_allows_delete(self, gateway, tmp_path):
        gateway.policy.soft_delete_tombstone_retention_days = 0
        upload(gateway)
        gateway.delete_document("evidence", "kyc/doc1.pdf", user_id="u1")
        req = gateway.request_deletion("evidence", "kyc/doc1.pdf", "alice", "purge")
        token = gateway.approve_deletion(req.approval_id, "bob")
        assert gateway.hard_delete_document("evidence", "kyc/doc1.pdf", token)
        assert not gateway.client.object_exists("evidence", "kyc/doc1.pdf")
        assert not gateway.client.object_exists("evidence", "kyc/doc1.pdf" + TOMBSTONE_SUFFIX)


class TestWormModes:
    def _worm_gateway(self, tmp_path, captured_audit, mode):
        policy = StoragePolicy(worm_mode=mode, enable_virus_scan=False,
                               worm_retention_days=2555)
        return StorageGateway(
            client=FakeRustFSClient(),
            policy=policy,
            audit_callback=captured_audit,
            approval_store=DeletionApprovalStore(tmp_path / f"approvals-{mode.value}.jsonl"),
            token_issuer=DeleteTokenIssuer(key=b"delete-token-test-key"),
        )

    def test_compliance_blocks_delete_until_retention(self, tmp_path, captured_audit):
        gw = self._worm_gateway(tmp_path, captured_audit, WormMode.COMPLIANCE)
        upload(gw)
        req = gw.request_deletion("evidence", "kyc/doc1.pdf", "alice", "x")
        token = gw.approve_deletion(req.approval_id, "bob")
        with pytest.raises(DualControlViolation, match="COMPLIANCE"):
            gw.hard_delete_document("evidence", "kyc/doc1.pdf", token)

    def test_governance_blocks_hard_delete_within_retention(self, tmp_path, captured_audit):
        gw = self._worm_gateway(tmp_path, captured_audit, WormMode.GOVERNANCE)
        upload(gw)
        req = gw.request_deletion("evidence", "kyc/doc1.pdf", "alice", "x")
        token = gw.approve_deletion(req.approval_id, "bob")
        with pytest.raises(DualControlViolation, match="GOVERNANCE"):
            gw.hard_delete_document("evidence", "kyc/doc1.pdf", token)
        # soft delete is still permitted (data retained)
        assert gw.delete_document("evidence", "kyc/doc1.pdf", user_id="alice")

    def test_retention_expired_allows_hard_delete(self, tmp_path, captured_audit):
        gw = self._worm_gateway(tmp_path, captured_audit, WormMode.COMPLIANCE)
        upload(gw)
        # age the object beyond retention
        obj = gw.client.buckets["evidence"]["kyc/doc1.pdf"]
        obj["metadata"]["upload_timestamp"] = (
            datetime.utcnow() - timedelta(days=3000)).isoformat()
        obj["last_modified"] = datetime.utcnow() - timedelta(days=3000)
        req = gw.request_deletion("evidence", "kyc/doc1.pdf", "alice", "expired")
        token = gw.approve_deletion(req.approval_id, "bob")
        assert gw.hard_delete_document("evidence", "kyc/doc1.pdf", token)


class TestLockdown:
    def test_read_only_lockdown_blocks_writes_and_deletes(self, gateway, monkeypatch):
        monkeypatch.setenv("STORAGE_READ_ONLY", "true")
        with pytest.raises(StorageLockdownError):
            gateway.upload_bytes("evidence", "x.pdf", b"x", "application/pdf")
        with pytest.raises(StorageLockdownError):
            gateway.delete_document("evidence", "kyc/doc1.pdf", user_id="u1")
        # reads still work
        monkeypatch.delenv("STORAGE_READ_ONLY")
        upload(gateway)
        monkeypatch.setenv("STORAGE_READ_ONLY", "true")
        assert gateway.download_bytes("evidence", "kyc/doc1.pdf") == b"pdf-bytes"


class TestPersistentAudit:
    def test_default_sink_writes_hash_chained_ledger(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDIT_HMAC_KEY", "0123456789abcdef" * 4)
        from implementations.security.audit import audit_logger as al
        al._audit_logger_instance = None  # reset singleton for the test
        monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path / "audit"))

        gw = StorageGateway(
            client=FakeRustFSClient(),
            policy=StoragePolicy(worm_mode=WormMode.OFF, enable_virus_scan=False),
        )
        upload(gw)
        gw.delete_document("evidence", "kyc/doc1.pdf", user_id="u1")

        logger = al.get_audit_logger()
        ok, errors = logger.verify_integrity()
        assert ok, errors
        events = logger.query_events(resource_type="storage_object")
        actions = [e.action for e in events]
        assert "storage_upload" in actions
        assert "storage_delete" in actions
        delete_events = [e for e in events if e.action == "storage_delete"]
        assert all(e.severity.value == "critical" for e in delete_events)
        logger.close()
        al._audit_logger_instance = None

    def test_fail_closed_without_audit_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
        monkeypatch.delenv("AUDIT_HMAC_KEY_URI", raising=False)
        from implementations.security.audit import audit_logger as al
        al._audit_logger_instance = None
        with pytest.raises(RuntimeError):
            StorageGateway(
                client=FakeRustFSClient(),
                policy=StoragePolicy(worm_mode=WormMode.OFF, enable_virus_scan=False),
            )
        al._audit_logger_instance = None


class TestMultiTenantProtection:
    def test_new_tenant_bucket_gets_versioning_and_lock(self, tmp_path, captured_audit):
        from implementations.storage.storage_gateway import MultiTenantStorageGateway
        client = FakeRustFSClient(versioning_enabled=False)
        policy = StoragePolicy(worm_mode=WormMode.COMPLIANCE, enable_virus_scan=False)
        gw = MultiTenantStorageGateway(client=client, policy=policy,
                                       audit_callback=captured_audit)
        bucket = gw.ensure_tenant_bucket("t-123")
        assert client.versioning[bucket] == "Enabled"
        assert client.object_lock[bucket]["mode"] == "COMPLIANCE"
