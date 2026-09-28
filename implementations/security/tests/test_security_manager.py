"""Regression tests for security_manager audit remediations.

- JWT secret: env-loaded, fail-closed boot, rotation window via
  JWT_SECRET_PREVIOUS.
- Role matrix pinned: ANALYST must NOT hold TRAIN_MODELS.
- Rate limiter: memory + Redis backends (Redis via a fake client), fail-closed
  on Redis errors, honest health reporting.
- Login-failure clearing is a soft-clear tombstone (UPDATE ... cleared_at),
  never DELETE FROM.

Run: python3 -m pytest tests/ -q   (from implementations/security)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import security_manager as sm  # noqa: E402


# ---------------------------------------------------------------------------
# JWT secret handling
# ---------------------------------------------------------------------------

class TestJwtSecret:
    def test_config_reads_secret_from_env(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "test-secret-key-0123456789abcdef")
        config = sm.SecurityConfig()
        assert config.jwt_secret == "test-secret-key-0123456789abcdef"

    def test_boot_fails_closed_without_secret(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("JWT_SECRET_PREVIOUS", raising=False)
        monkeypatch.setenv("DATABASE_URL", "postgres://x")
        config = sm.SecurityConfig()
        with pytest.raises(ValueError, match="JWT_SECRET"):
            sm.SecurityManager(config)

    def test_no_random_default_secret(self, monkeypatch):
        """Two configs must not silently mint distinct per-process secrets."""
        monkeypatch.delenv("JWT_SECRET", raising=False)
        a = sm.SecurityConfig()
        b = sm.SecurityConfig()
        assert a.jwt_secret == "" and b.jwt_secret == ""
        assert a.jwt_secret == b.jwt_secret  # never a random token_urlsafe

    def test_rotation_window_accepts_previous_secret(self):
        config = sm.SecurityConfig(jwt_secret="new-secret", jwt_previous_secret="old-secret")
        mgr = sm.JWTManager(config)
        old = sm.JWTManager(sm.SecurityConfig(jwt_secret="old-secret"))
        token = old.create_token("user-1", sm.Role.VIEWER)
        payload = mgr.verify_token(token)
        assert payload is not None and payload["user_id"] == "user-1"

    def test_unknown_secret_rejected(self):
        mgr = sm.JWTManager(sm.SecurityConfig(jwt_secret="right"))
        foreign = sm.JWTManager(sm.SecurityConfig(jwt_secret="wrong"))
        token = foreign.create_token("user-1", sm.Role.VIEWER)
        assert mgr.verify_token(token) is None


# ---------------------------------------------------------------------------
# Role -> permission matrix regression
# ---------------------------------------------------------------------------

class TestRoleMatrix:
    EXPECTED = {
        sm.Role.ADMIN: {sm.Permission.ADMIN_ALL},
        sm.Role.ANALYST: {
            sm.Permission.READ_TRANSACTIONS,
            sm.Permission.WRITE_TRANSACTIONS,
            sm.Permission.READ_MODELS,
            sm.Permission.READ_AUDIT,
        },
        sm.Role.VIEWER: {sm.Permission.READ_TRANSACTIONS, sm.Permission.READ_MODELS},
        sm.Role.API_USER: {sm.Permission.READ_TRANSACTIONS, sm.Permission.READ_MODELS},
    }

    def test_matrix_matches_exactly(self):
        authz = sm.AuthorizationManager()
        assert set(authz.role_permissions) == set(self.EXPECTED)
        for role, perms in self.EXPECTED.items():
            assert set(authz.role_permissions[role]) == perms, role

    def test_analyst_cannot_train_models(self):
        """Audit caveat: ANALYST previously held TRAIN_MODELS."""
        authz = sm.AuthorizationManager()
        assert sm.Permission.TRAIN_MODELS not in authz.role_permissions[sm.Role.ANALYST]
        assert authz.has_permission(sm.Role.ANALYST, sm.Permission.TRAIN_MODELS) is False

    def test_only_admin_deploys_and_trains(self):
        authz = sm.AuthorizationManager()
        for role in (sm.Role.ANALYST, sm.Role.VIEWER, sm.Role.API_USER):
            assert authz.has_permission(role, sm.Permission.TRAIN_MODELS) is False
            assert authz.has_permission(role, sm.Permission.DEPLOY_MODELS) is False
        assert authz.has_permission(sm.Role.ADMIN, sm.Permission.TRAIN_MODELS) is True


# ---------------------------------------------------------------------------
# Rate limiter backends
# ---------------------------------------------------------------------------

class _FakePipeline:
    def __init__(self, store):
        self.store = store
        self.ops = []

    def zremrangebyscore(self, key, lo, hi):
        self.ops.append(("zrem", key, lo, hi))
        return self

    def zcard(self, key):
        self.ops.append(("zcard", key))
        return self

    def zadd(self, key, mapping):
        self.ops.append(("zadd", key, mapping))
        return self

    def expire(self, key, ttl):
        self.ops.append(("expire", key, ttl))
        return self

    def execute(self):
        import time

        now_ms = int(time.time() * 1000)
        out = []
        for op in self.ops:
            if op[0] == "zrem":
                _, key, lo, hi = op
                self.store[key] = {m: s for m, s in self.store.get(key, {}).items() if not (lo <= s <= hi)}
                out.append(0)
            elif op[0] == "zcard":
                out.append(len(self.store.get(op[1], {})))
            elif op[0] == "zadd":
                self.store.setdefault(op[1], {}).update(op[2])
                out.append(1)
            else:
                out.append(True)
        return out


class _FakeRedis:
    def __init__(self, fail=False):
        self.store = {}
        self.fail = fail

    def pipeline(self, transaction=True):
        if self.fail:
            raise ConnectionError("redis down")
        return _FakePipeline(self.store)


class TestRateLimiter:
    def _config(self, limit=3):
        return sm.SecurityConfig(jwt_secret="s", rate_limit_requests=limit,
                                 rate_limit_window_seconds=60)

    def test_memory_backend_allows_then_denies(self):
        limiter = sm.RateLimiter(self._config())
        assert limiter.backend == "memory"
        assert [limiter.is_allowed("u") for _ in range(3)] == [True, True, True]
        assert limiter.is_allowed("u") is False

    def test_redis_backend_sliding_window(self):
        limiter = sm.RateLimiter(self._config(), redis_client=_FakeRedis())
        assert limiter.backend == "redis"
        assert [limiter.is_allowed("u") for _ in range(3)] == [True, True, True]
        assert limiter.is_allowed("u") is False
        # separate identifier has its own window
        assert limiter.is_allowed("other") is True

    def test_redis_error_fails_closed(self):
        limiter = sm.RateLimiter(self._config(), redis_client=_FakeRedis(fail=True))
        assert limiter.is_allowed("u") is False

    def test_health_reports_backend_loudly(self):
        memory = sm.RateLimiter(sm.SecurityConfig(jwt_secret="s", redis_url=None))
        assert memory.health()["backend"] == "memory"
        assert memory.health()["degraded"] is False
        redis_backed = sm.RateLimiter(self._config(), redis_client=_FakeRedis())
        assert redis_backed.health()["backend"] == "redis"


# ---------------------------------------------------------------------------
# Audit logger persistence + ring
# ---------------------------------------------------------------------------

class TestAuditLogger:
    def test_persist_called_and_ring_kept(self):
        written = []
        logger = sm.AuditLogger(persist=written.append, ring_capacity=5)
        for i in range(7):
            logger.log_event("evt", "user", {"i": i})
        assert len(written) == 7           # every event persisted
        assert len(logger.audit_log) == 5  # ring is bounded
        assert logger.get_events()[0]["details"]["i"] == 2  # oldest dropped

    def test_persist_failure_is_loud_but_nonfatal(self, caplog):
        def boom(event):
            raise RuntimeError("db down")

        logger = sm.AuditLogger(persist=boom)
        import logging

        with caplog.at_level(logging.ERROR):
            logger.log_event("evt", "user", {})
        assert any("AUDIT PERSISTENCE FAILED" in r.message for r in caplog.records)
        assert len(logger.audit_log) == 1


# ---------------------------------------------------------------------------
# Login-failure soft clear (tombstone, anti-wipe)
# ---------------------------------------------------------------------------

class _FakeCursor:
    def __init__(self, parent):
        self.parent = parent

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.parent.queries.append((sql, params))


class _FakeConn:
    def __init__(self, parent):
        self.parent = parent

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self, **kwargs):
        return _FakeCursor(self.parent)

    def commit(self):
        pass

    def rollback(self):
        pass


class _FakeManager:
    """Captures the SQL SecurityManager would run, without a database."""

    def __init__(self):
        self.queries = []

    def _connection(self):
        return _FakeConn(self)


class TestSoftClear:
    def _mgr(self):
        fake = _FakeManager()
        mgr = sm.SecurityManager.__new__(sm.SecurityManager)
        mgr.config = sm.SecurityConfig(jwt_secret="s")
        mgr._connection = fake._connection
        mgr._fake = fake
        return mgr

    def test_clear_uses_tombstone_not_delete(self):
        mgr = self._mgr()
        mgr._clear_failed_logins("alice")
        sql, params = mgr._fake.queries[0]
        assert "DELETE FROM" not in sql.upper()
        assert "UPDATE security_login_failures" in sql
        assert "cleared_at" in sql and "cleared_by" in sql
        assert params == ("alice", "alice")

    def test_lockout_counts_only_uncleared_rows(self):
        mgr = self._mgr()
        try:
            mgr._is_account_locked("alice")
        except Exception:
            pass  # fake cursor cannot fetchone; we only care about the SQL
        sql, _ = mgr._fake.queries[0]
        assert "cleared_at IS NULL" in sql
