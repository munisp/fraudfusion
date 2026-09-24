"""Tests for the HMAC-keyed, cross-segment chained audit logger.

Run: python3 -m pytest implementations/security/audit/tests/ -q
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from implementations.security.audit.audit_logger import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    DEFAULT_RETENTION_FLOOR_DAYS,
)

TEST_KEY = b"test-hmac-key-0123456789abcdef"


def make_logger(tmp_path, **kwargs) -> AuditLogger:
    kwargs.setdefault("hmac_key", TEST_KEY)
    return AuditLogger(log_dir=str(tmp_path / "audit"), **kwargs)


def make_event(action="test_action", event_type=AuditEventType.SYSTEM_EVENT) -> AuditEvent:
    return AuditEvent(
        event_id=f"evt-{time.time_ns()}",
        event_type=event_type,
        severity=AuditSeverity.INFO,
        timestamp=datetime.utcnow(),
        action=action,
        outcome="success",
    )


class TestFailClosedKey:
    def test_missing_key_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
        monkeypatch.delenv("AUDIT_HMAC_KEY_URI", raising=False)
        with pytest.raises(RuntimeError, match="AUDIT_HMAC_KEY"):
            AuditLogger(log_dir=str(tmp_path / "audit"))

    def test_env_key_accepted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDIT_HMAC_KEY", TEST_KEY.hex())
        logger = AuditLogger(log_dir=str(tmp_path / "audit"))
        logger.log(make_event())
        ok, errors = logger.verify_integrity()
        assert ok, errors
        logger.close()

    def test_unkeyed_requires_explicit_opt_out(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
        monkeypatch.delenv("AUDIT_HMAC_KEY_URI", raising=False)
        logger = AuditLogger(log_dir=str(tmp_path / "audit"), allow_insecure_unkeyed=True)
        logger.log(make_event())
        ok, _ = logger.verify_integrity(allow_legacy_unkeyed=True)
        assert ok
        logger.close()


class TestKeyedChain:
    def test_events_chain_and_verify(self, tmp_path):
        logger = make_logger(tmp_path)
        logger.log(make_event("a"))
        logger.log(make_event("b"))
        logger.log(make_event("c"))
        ok, errors = logger.verify_integrity()
        assert ok, errors
        logger.close()

    def test_rewrite_tail_attack_detected(self, tmp_path):
        """Attacker rewrites a historical event and recomputes the UNKEYED
        sha256 chain — must still fail because the chain is HMAC-keyed."""
        logger = make_logger(tmp_path)
        logger.log(make_event("transfer_100"))
        logger.log(make_event("transfer_200"))
        logger.close()

        log_file = next(Path(tmp_path / "audit").glob("audit_*.jsonl"))
        lines = log_file.read_text().splitlines()
        first = json.loads(lines[0])
        # attacker tampers: change the outcome and try to repair the chain
        # with plain SHA-256 (no key)
        first["outcome"] = "laundered"
        tampered = AuditEvent.from_dict(first)
        tampered.event_hash = tampered.compute_hash(None)  # unkeyed recompute
        lines[0] = json.dumps(tampered.to_dict())
        # fix the next link to point at the forged hash
        second = json.loads(lines[1])
        second["previous_hash"] = tampered.event_hash
        lines[1] = json.dumps(second)
        log_file.write_text("\n".join(lines) + "\n")

        logger2 = make_logger(tmp_path)
        ok, errors = logger2.verify_integrity()
        assert not ok
        assert any("Hash mismatch" in e for e in errors)
        logger2.close()

    def test_wrong_key_detected(self, tmp_path):
        logger = make_logger(tmp_path)
        logger.log(make_event())
        logger.close()
        other = make_logger(tmp_path, hmac_key=b"a-different-key-entirely")
        ok, errors = other.verify_integrity()
        assert not ok
        other.close()


class TestCrossSegmentContinuity:
    def _force_day_rotation(self, logger: AuditLogger):
        """Simulate a day change by pointing the logger at yesterday's file."""
        yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y%m%d")
        old = logger._current_file
        renamed = old.with_name(f"audit_{yesterday}.jsonl")
        logger._current_file_handle.close()
        os.replace(old, renamed)
        logger._current_file = renamed
        logger._current_file_handle = open(renamed, "a")
        return renamed

    def test_rotation_seals_and_continues_chain(self, tmp_path):
        logger = make_logger(tmp_path)
        logger.log(make_event("before-rotation"))
        old_segment = self._force_day_rotation(logger)
        logger.log(make_event("after-rotation"))  # triggers seal + new segment
        logger.close()

        # old segment has a signed seal as its last line
        old_lines = old_segment.read_text().splitlines()
        seal = json.loads(old_lines[-1])
        assert seal["record_type"] == "segment_seal"
        assert seal["segment_root"]
        assert seal["seal"]

        # new segment's first event chains from the old segment root, not None
        new_segment = logger.log_dir / f"audit_{datetime.utcnow().strftime('%Y%m%d')}.jsonl"
        first = json.loads(new_segment.read_text().splitlines()[0])
        assert first["previous_hash"] == seal["segment_root"]

        ok, errors = logger.verify_chain()
        assert ok, errors

    def test_chain_state_survives_restart(self, tmp_path):
        logger = make_logger(tmp_path)
        logger.log(make_event("persistent"))
        head = logger._last_hash
        logger.close()

        logger2 = make_logger(tmp_path)
        assert logger2._last_hash == head
        evt = logger2.log(make_event("after-restart"))
        assert evt.previous_hash == head
        ok, errors = logger2.verify_integrity()
        assert ok, errors
        logger2.close()

    def test_seal_signature_verified(self, tmp_path):
        logger = make_logger(tmp_path)
        logger.log(make_event("x"))
        old_segment = self._force_day_rotation(logger)
        logger.log(make_event("y"))
        logger.close()

        # corrupt the seal
        lines = old_segment.read_text().splitlines()
        seal = json.loads(lines[-1])
        seal["event_count"] = 999
        lines[-1] = json.dumps(seal)
        old_segment.write_text("\n".join(lines) + "\n")

        logger2 = make_logger(tmp_path)
        ok, errors = logger2.verify_integrity(old_segment)
        assert not ok
        assert any("seal" in e.lower() for e in errors)
        logger2.close()


class TestExternalAnchor:
    def test_seal_anchored_to_file(self, tmp_path):
        anchor = tmp_path / "anchor" / "anchors.jsonl"
        logger = make_logger(tmp_path, anchor_file=str(anchor))
        logger.log(make_event("anchored"))
        yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y%m%d")
        old = logger._current_file
        renamed = old.with_name(f"audit_{yesterday}.jsonl")
        logger._current_file_handle.close()
        os.replace(old, renamed)
        logger._current_file = renamed
        logger._current_file_handle = open(renamed, "a")
        logger.log(make_event("next-day"))
        logger.close()

        anchor_lines = [json.loads(l) for l in anchor.read_text().splitlines()]
        assert any(
            r.get("record_type") == "segment_seal" and r.get("segment_file") == renamed.name
            for r in anchor_lines
        )
        assert logger._is_segment_anchored(renamed.name)


class TestGatedCleanup:
    def _old_segment(self, logger, tmp_path, age_days, regulated=True):
        date = (datetime.utcnow() - timedelta(days=age_days)).strftime("%Y%m%d")
        seg = logger.log_dir / f"audit_{date}.jsonl"
        evt_type = AuditEventType.FRAUD_DETECTION if regulated else AuditEventType.USER_LOGIN
        event = make_event("old", evt_type)
        event.previous_hash = None
        event.event_hash = event.compute_hash(TEST_KEY)
        seal = {
            "record_type": "segment_seal",
            "segment_file": seg.name,
            "segment_root": event.event_hash,
            "previous_segment_root": None,
            "event_count": 1,
            "sealed_at": datetime.utcnow().isoformat() + "Z",
        }
        seal["seal"] = logger._compute_seal(
            seg.name, event.event_hash, None, 1, seal["sealed_at"])
        seg.write_text(json.dumps(event.to_dict()) + "\n" + json.dumps(seal) + "\n")
        return seg

    def test_no_token_no_delete(self, tmp_path):
        logger = make_logger(tmp_path, retention_days=30)
        seg = self._old_segment(logger, tmp_path, age_days=DEFAULT_RETENTION_FLOOR_DAYS + 10)
        logger.cleanup_old_logs()
        assert seg.exists()
        logger.close()

    def test_retention_floor_protects_regulated(self, tmp_path):
        logger = make_logger(tmp_path, retention_days=30)
        seg = self._old_segment(logger, tmp_path, age_days=400, regulated=True)
        token = logger.issue_cleanup_token(seg.name, "approver-2")
        logger.cleanup_old_logs(approval_tokens={seg.name: token})
        assert seg.exists(), "regulated segment younger than 7y floor must survive"
        logger.close()

    def test_unsealed_segment_refused(self, tmp_path):
        logger = make_logger(tmp_path, retention_days=30)
        date = (datetime.utcnow() - timedelta(days=DEFAULT_RETENTION_FLOOR_DAYS + 10)).strftime("%Y%m%d")
        seg = logger.log_dir / f"audit_{date}.jsonl"
        seg.write_text(json.dumps(make_event("x").to_dict()) + "\n")
        token = logger.issue_cleanup_token(seg.name, "approver-2")
        logger.cleanup_old_logs(approval_tokens={seg.name: token})
        assert seg.exists()
        logger.close()

    def test_anchor_required_when_configured(self, tmp_path):
        anchor = tmp_path / "anchor.jsonl"
        logger = make_logger(tmp_path, retention_days=30, anchor_file=str(anchor))
        seg = self._old_segment(logger, tmp_path, age_days=DEFAULT_RETENTION_FLOOR_DAYS + 10)
        token = logger.issue_cleanup_token(seg.name, "approver-2")
        logger.cleanup_old_logs(approval_tokens={seg.name: token})
        assert seg.exists(), "must not delete before external anchor confirms export"

        # now anchor the segment externally and retry with a fresh token
        with open(anchor, "a") as f:
            f.write(json.dumps({"record_type": "segment_seal", "segment_file": seg.name}) + "\n")
        token2 = logger.issue_cleanup_token(seg.name, "approver-2")
        logger.cleanup_old_logs(approval_tokens={seg.name: token2})
        assert not seg.exists()
        logger.close()

    def test_token_single_use_and_segment_bound(self, tmp_path):
        logger = make_logger(tmp_path, retention_days=30)
        seg = self._old_segment(logger, tmp_path, age_days=DEFAULT_RETENTION_FLOOR_DAYS + 10)
        token = logger.issue_cleanup_token(seg.name, "approver-2")

        ok, _ = logger._verify_cleanup_token(token, "audit_19990101.jsonl")
        assert not ok, "token must be bound to its segment"

        logger._used_cleanup_tokens.add(token.split("|")[-2])
        ok, reason = logger._verify_cleanup_token(token, seg.name)
        assert not ok and "single-use" in reason
        logger.close()

    def test_expired_token_rejected(self, tmp_path):
        logger = make_logger(tmp_path)
        token = logger.issue_cleanup_token("audit_20000101.jsonl", "approver-2",
                                           expires_in_seconds=-1)
        ok, reason = logger._verify_cleanup_token(token, "audit_20000101.jsonl")
        assert not ok and "expired" in reason
        logger.close()
