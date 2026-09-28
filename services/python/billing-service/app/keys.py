"""API key lifecycle primitives: generation, hashing, authentication
dependency, per-key sliding-window rate limiting, and buffered usage
recording.

Key format: ``ffk_live_<32 hex chars>`` (16 random bytes). Only the SHA-256
hash and a non-secret prefix (``ffk_live_<first 8 of random part>``) are
stored; the plaintext is returned to the caller exactly once at
issue/rotation time.

Rate limiting is a per-key sliding window over 60 seconds. Redis is used
when REDIS_URL is set (and the redis package is importable); otherwise an
in-process backend is used and /health reports ``rate_limit_backend:
memory`` loudly so operators know limits are per-replica.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from app.db import Database, get_db

log = logging.getLogger("billing.keys")

KEY_ENV = os.getenv("BILLING_KEY_ENV", "live")
KEY_PREFIX = f"ffk_{KEY_ENV}_"


def generate_key() -> tuple[str, str, str]:
    """Return (plaintext, key_prefix, sha256_hex). Plaintext is shown once."""
    random_part = secrets.token_hex(16)  # 32 hex chars
    plaintext = f"{KEY_PREFIX}{random_part}"
    prefix = f"{KEY_PREFIX}{random_part[:8]}"
    return plaintext, prefix, hash_key(plaintext)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    """Per-key sliding-window limiter (window = 60s, limit = rate_limit_rpm)."""

    WINDOW_SECONDS = 60.0

    def __init__(self) -> None:
        self._redis = None
        redis_url = os.getenv("REDIS_URL", "").strip()
        if redis_url:
            try:
                import redis  # type: ignore

                self._redis = redis.Redis.from_url(redis_url, socket_timeout=2.0)
                self._redis.ping()
                log.info("rate limiter backend: redis (%s)", redis_url)
            except Exception as exc:  # noqa: BLE001 - fall back, loudly
                log.warning(
                    "REDIS_URL set but Redis unusable (%s); falling back to "
                    "in-process rate limiting (per-replica only)", exc,
                )
                self._redis = None
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    @property
    def backend(self) -> str:
        return "redis" if self._redis is not None else "memory"

    def allow(self, key_id: str, limit_rpm: int) -> bool:
        now = time.monotonic()
        if self._redis is not None:
            try:
                return self._allow_redis(key_id, limit_rpm)
            except Exception as exc:  # noqa: BLE001 - degrade to memory
                log.warning("redis rate-limit check failed (%s); using memory", exc)
        with self._lock:
            hits = self._hits[key_id]
            cutoff = now - self.WINDOW_SECONDS
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= limit_rpm:
                return False
            hits.append(now)
            return True

    def _allow_redis(self, key_id: str, limit_rpm: int) -> bool:
        now = time.time()
        member = f"{now}:{uuid.uuid4().hex}"
        bucket = f"billing:rl:{key_id}"
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(bucket, 0, now - self.WINDOW_SECONDS)
        pipe.zadd(bucket, {member: now})
        pipe.zcard(bucket)
        pipe.expire(bucket, int(self.WINDOW_SECONDS) + 1)
        _rem, _add, count, _exp = pipe.execute()
        if count > limit_rpm:
            # Over the limit: remove the entry we just added so rejected
            # requests do not count against the caller.
            self._redis.zrem(bucket, member)
            return False
        return True

    def reset_for_tests(self) -> None:
        with self._lock:
            self._hits.clear()


# ---------------------------------------------------------------------------
# Buffered usage recording
# ---------------------------------------------------------------------------

class UsageBuffer:
    """Buffers usage events from the data plane and flushes them to the DB
    asynchronously (size threshold or periodic timer). Idempotency of the
    underlying insert is enforced by the (tenant_id, idempotency_key) unique
    index, so a flush retried after a crash cannot double-count."""

    def __init__(self, db: Database, flush_threshold: int | None = None):
        self._db = db
        self._threshold = flush_threshold or int(os.getenv("BILLING_USAGE_FLUSH_THRESHOLD", "100"))
        self._buf: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._buf)

    def record(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._buf.append(event)
            should_flush = len(self._buf) >= self._threshold
        if should_flush:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            batch, self._buf = self._buf, []
        for event in batch:
            inserted = self._db.insert_idempotent(
                "INSERT INTO usage_events "
                "(id, tenant_id, api_key_id, service, operation, units, amount_kobo, idempotency_key, occurred_at) "
                "VALUES (:id, :tenant_id, :api_key_id, :service, :operation, :units, :amount_kobo, :idem, :occurred_at)",
                event,
            )
            if inserted:
                # Same upsert works on Postgres and SQLite: unqualified
                # `units` on the RHS refers to the existing row's value.
                self._db.execute(
                    "INSERT INTO usage_rollups (tenant_id, period, operation, units, updated_at) "
                    "VALUES (:tenant_id, :period, :operation, :units, :now) "
                    "ON CONFLICT (tenant_id, period, operation) DO UPDATE SET "
                    "units = units + :units, updated_at = :now",
                    {
                        "tenant_id": event["tenant_id"],
                        "period": event["occurred_at"][:7],
                        "operation": event["operation"],
                        "units": event["units"],
                        "now": utcnow(),
                    },
                )


# ---------------------------------------------------------------------------
# Data-plane dependency
# ---------------------------------------------------------------------------

def get_limiter(request: Request) -> SlidingWindowRateLimiter:
    return request.app.state.rate_limiter


def get_usage_buffer(request: Request) -> UsageBuffer:
    return request.app.state.usage_buffer


def _parse_scopes(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(s) for s in raw]
    try:
        return [str(s) for s in json.loads(raw or "[]")]
    except (TypeError, ValueError):
        return []


def require_api_key(
    operation: str,
    x_api_key: str = Header(default=""),
    db: Database = Depends(get_db),
    limiter: SlidingWindowRateLimiter = Depends(get_limiter),
    buffer: UsageBuffer = Depends(get_usage_buffer),
) -> dict[str, Any]:
    """Authenticate a metered data-plane call.

    Fail-closed: missing/invalid/expired key -> 401; revoked/suspended key
    -> 403; key missing the required scope -> 403; over rate limit -> 429.
    On success the usage event is recorded via the async buffer.
    """
    if not x_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing API key")
    row = db.query_one("SELECT * FROM api_keys WHERE key_hash = :h", {"h": hash_key(x_api_key)})
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
    if row["status"] == "revoked":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API key revoked")
    if row["status"] == "suspended":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API key suspended (billing)")
    expires_at = row.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= exp:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key expired")
        except ValueError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key expiry unreadable")
    if operation not in _parse_scopes(row.get("scopes")):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"API key lacks required scope '{operation}'",
        )
    if not limiter.allow(row["id"], int(row["rate_limit_rpm"])):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded")

    now = utcnow()
    db.execute("UPDATE api_keys SET last_used_at = :now, updated_at = :now WHERE id = :id",
               {"now": now, "id": row["id"]})
    buffer.record({
        "id": str(uuid.uuid4()),
        "tenant_id": row["tenant_id"],
        "api_key_id": row["id"],
        "service": "billing-gateway",
        "operation": operation,
        "units": 1,
        "amount_kobo": 0,  # rated at invoice time against the plan
        "idem": f"key:{row['id']}:{now}",
        "occurred_at": now,
    })
    row["scopes"] = _parse_scopes(row.get("scopes"))
    return row
