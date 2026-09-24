"""Integration tests: storage gateway <-> ransomware_guard hot-path wiring.

Proves that op events emitted by StorageGateway (put/delete/bytes) trip the
RansomwareGuard detector and that a guard lockdown makes the gateway reject
subsequent writes/deletes (in-process state AND the shared lockdown file).

Run: python3 -m pytest implementations/storage/tests/test_ransomware_integration.py -q
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from implementations.storage.storage_gateway import (
    StorageGateway,
    StorageLockdownError,
    StoragePolicy,
    WormMode,
)
from implementations.storage.deletion_approval import (
    DeletionApprovalStore,
    DeleteTokenIssuer,
)
from services.python.ransomware_guard import GuardConfig, RansomwareGuard
from test_antiwipe import FakeRustFSClient, captured_audit  # noqa: F401  (fixture reuse)


def make_guard(tmp_path, **overrides):
    cfg = GuardConfig(
        lockdown_state_path=str(tmp_path / "lockdown.json"),
        metrics_path=str(tmp_path / "guard.prom"),
        webhook_url="",
        delete_rate_alert_per_min=overrides.pop("delete_rate_alert_per_min", 2),
        delete_rate_lockdown_per_min=overrides.pop("delete_rate_lockdown_per_min", 3),
        overwrite_rate_lockdown_per_min=overrides.pop("overwrite_rate_lockdown_per_min", 3),
        entropy_spike_min_uploads=overrides.pop("entropy_spike_min_uploads", 3),
        **overrides,
    )
    emitted = []
    return RansomwareGuard(config=cfg, audit_emit=lambda n, d: emitted.append((n, d))), emitted


def make_gateway(tmp_path, captured_audit, guard):
    return StorageGateway(
        client=FakeRustFSClient(),
        policy=StoragePolicy(worm_mode=WormMode.OFF, enable_virus_scan=False),
        audit_callback=captured_audit,
        approval_store=DeletionApprovalStore(tmp_path / "approvals.jsonl"),
        token_issuer=DeleteTokenIssuer(key=b"delete-token-test-key",
                                       used_jti_path=tmp_path / "jtis.txt"),
        guard=guard,
    )


def upload(gw, key, data=b"pdf-bytes"):
    return gw.upload_bytes("evidence", key, data, "application/pdf", user_id="u1")


class TestDeleteBurstLockdown:
    def test_delete_burst_trips_guard_and_blocks_subsequent_writes(self, tmp_path, captured_audit):
        guard, emitted = make_guard(tmp_path)
        gw = make_gateway(tmp_path, captured_audit, guard)

        for i in range(3):
            upload(gw, f"kyc/doc{i}.pdf")
        # Simulated wipe: rapid delete burst hits the lockdown threshold (3/min).
        gw.delete_document("evidence", "kyc/doc0.pdf", user_id="attacker")
        assert not guard.is_locked_down()
        gw.delete_document("evidence", "kyc/doc1.pdf", user_id="attacker")
        signal = guard.observe_delete("attacker", "evidence/kyc/aux.pdf")
        assert signal == "lockdown" or guard.is_locked_down()

        # The gateway now rejects all subsequent writes AND deletes.
        with pytest.raises(StorageLockdownError):
            upload(gw, "kyc/doc3.pdf")
        with pytest.raises(StorageLockdownError):
            gw.delete_document("evidence", "kyc/doc2.pdf", user_id="attacker")

        # Reads still work (lockdown is read-only, not read-blocking).
        assert gw.download_bytes("evidence", "kyc/doc2.pdf", user_id="u1") == b"pdf-bytes"

        # Lockdown was recorded: audit emit + lockdown state file + metrics.
        assert any(name == "ransomware_lockdown" for name, _ in emitted)
        import json
        state = json.loads((tmp_path / "lockdown.json").read_text())
        assert state["read_only"] is True
        assert "storage_lockdown_active 1" in (tmp_path / "guard.prom").read_text()

    def test_gateway_delete_burst_alone_trips_lockdown(self, tmp_path, captured_audit):
        """All lockdown-relevant events come from gateway ops only (no direct
        guard pokes): 3 gateway deletes => lockdown => 4th write rejected."""
        guard, _ = make_guard(tmp_path)
        gw = make_gateway(tmp_path, captured_audit, guard)
        for i in range(4):
            upload(gw, f"kyc/doc{i}.pdf")
        for i in range(3):
            gw.delete_document("evidence", f"kyc/doc{i}.pdf", user_id="attacker")
        assert guard.is_locked_down()
        with pytest.raises(StorageLockdownError):
            gw.delete_document("evidence", "kyc/doc3.pdf", user_id="attacker")
        with pytest.raises(StorageLockdownError):
            upload(gw, "kyc/new.pdf")


class TestCrossProcessLockdownFile:
    def test_lockdown_file_blocks_gateway_without_inprocess_guard(
        self, tmp_path, captured_audit, monkeypatch
    ):
        guard, _ = make_guard(tmp_path)
        monkeypatch.setenv("STORAGE_LOCKDOWN_STATE", str(tmp_path / "lockdown.json"))
        gw1 = make_gateway(tmp_path, captured_audit, guard)
        for i in range(3):
            upload(gw1, f"kyc/doc{i}.pdf")
            gw1.delete_document("evidence", f"kyc/doc{i}.pdf", user_id="attacker")
        assert guard.is_locked_down()

        # A sibling process: separate gateway, no shared guard object.
        gw2 = StorageGateway(
            client=FakeRustFSClient(),
            policy=StoragePolicy(worm_mode=WormMode.OFF, enable_virus_scan=False),
            audit_callback=captured_audit,
            enable_ransomware_guard=False,
        )
        with pytest.raises(StorageLockdownError):
            gw2.upload_bytes("evidence", "x.pdf", b"x", "application/pdf", user_id="u2")


class TestDualControlClear:
    def test_clear_requires_two_principals_and_restores_writes(self, tmp_path, captured_audit):
        guard, _ = make_guard(tmp_path)
        gw = make_gateway(tmp_path, captured_audit, guard)
        for i in range(3):
            upload(gw, f"kyc/doc{i}.pdf")
            gw.delete_document("evidence", f"kyc/doc{i}.pdf", user_id="attacker")
        assert guard.is_locked_down()

        with pytest.raises(PermissionError):
            guard.clear_lockdown("admin", "admin", "same principal")
        with pytest.raises(StorageLockdownError):
            upload(gw, "kyc/new.pdf")

        assert guard.clear_lockdown("admin-a", "admin-b", "verified false positive")
        upload(gw, "kyc/new.pdf")  # writes accepted again
        assert gw.download_bytes("evidence", "kyc/new.pdf") == b"pdf-bytes"


class TestOtherSignals:
    def test_overwrite_burst_trips_lockdown(self, tmp_path, captured_audit):
        guard, _ = make_guard(tmp_path)
        gw = make_gateway(tmp_path, captured_audit, guard)
        for i in range(4):
            # 1 initial upload + 3 overwrites (PUT on an existing key)
            upload(gw, "kyc/doc.pdf", data=f"v{i}".encode())
        assert guard.is_locked_down()
        with pytest.raises(StorageLockdownError):
            upload(gw, "kyc/other.pdf")

    def test_high_entropy_upload_burst_trips_lockdown(self, tmp_path, captured_audit):
        guard, _ = make_guard(tmp_path)
        gw = make_gateway(tmp_path, captured_audit, guard)
        for i in range(3):
            upload(gw, f"kyc/blob{i}.bin", data=os.urandom(4096))  # ~8 bits/byte
        assert guard.is_locked_down()


class TestGuardToggle:
    def test_guard_can_be_disabled_explicitly(self, tmp_path, captured_audit):
        gw = StorageGateway(
            client=FakeRustFSClient(),
            policy=StoragePolicy(worm_mode=WormMode.OFF, enable_virus_scan=False),
            audit_callback=captured_audit,
            enable_ransomware_guard=False,
        )
        assert gw._guard is None
        for i in range(5):
            upload(gw, f"kyc/doc{i}.pdf")
            gw.delete_document("evidence", f"kyc/doc{i}.pdf", user_id="u1")
        upload(gw, "kyc/still-writable.pdf")

    def test_default_guard_builds_from_env(self, tmp_path, captured_audit, monkeypatch):
        monkeypatch.setenv("STORAGE_LOCKDOWN_STATE", str(tmp_path / "lockdown.json"))
        monkeypatch.setenv("RANSOMWARE_GUARD_METRICS", str(tmp_path / "guard.prom"))
        monkeypatch.setenv("DELETE_RATE_LOCKDOWN_PER_MIN", "3")
        gw = StorageGateway(
            client=FakeRustFSClient(),
            policy=StoragePolicy(worm_mode=WormMode.OFF, enable_virus_scan=False),
            audit_callback=captured_audit,
        )
        assert gw._guard is not None
        for i in range(3):
            upload(gw, f"kyc/doc{i}.pdf")
            gw.delete_document("evidence", f"kyc/doc{i}.pdf", user_id="attacker")
        with pytest.raises(StorageLockdownError):
            upload(gw, "kyc/blocked.pdf")
