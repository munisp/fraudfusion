"""Sandbox auth + rate limiting.

The sandbox accepts ANY ``X-API-Key`` with the ``ffk_test_`` prefix (prefix
check only — no key store, no introspection). ``ffk_live_*`` keys are
rejected with an explicit error so developers can never confuse environments;
a missing or malformed key is a 401.

Rate limiting: in-memory sliding window, 60 requests/minute per API key.
Single-process, per-instance — documented as a sandbox limitation.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import HTTPException, Request

TEST_KEY_PREFIX = "ffk_test_"
LIVE_KEY_PREFIX = "ffk_live_"

RATE_LIMIT_RPM = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0


class SlidingWindowRateLimiter:
    """In-memory sliding-window limiter keyed by API key."""

    def __init__(self, max_requests: int = RATE_LIMIT_RPM,
                 window_seconds: float = RATE_LIMIT_WINDOW_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> tuple[bool, float]:
        """Record one hit for ``key``. Returns (allowed, retry_after_seconds)."""
        now = now if now is not None else time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            cutoff = now - self.window_seconds
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.max_requests:
                retry_after = max(0.0, hits[0] + self.window_seconds - now)
                return False, retry_after
            hits.append(now)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def require_sandbox_key(request: Request) -> str:
    """FastAPI dependency: validate X-API-Key and enforce the rate limit.

    Returns the (sandbox-only, test-class) API key on success."""
    key = request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(
            status_code=401,
            detail="missing X-API-Key header — the sandbox accepts any key "
                   "with the ffk_test_ prefix (e.g. ffk_test_dev)")
    if key.startswith(LIVE_KEY_PREFIX):
        raise HTTPException(
            status_code=403,
            detail="live API keys (ffk_live_*) cannot be used in the sandbox — "
                   "this environment performs NO real verification. Use any "
                   "ffk_test_* key here, and keep live keys for the production "
                   "data plane only")
    if not key.startswith(TEST_KEY_PREFIX) or len(key) <= len(TEST_KEY_PREFIX):
        raise HTTPException(
            status_code=401,
            detail=f"invalid sandbox API key — expected an {TEST_KEY_PREFIX}* "
                   "test key (prefix check only; any value after the prefix "
                   "is accepted)")

    limiter: SlidingWindowRateLimiter = request.app.state.rate_limiter
    allowed, retry_after = limiter.check(key)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"sandbox rate limit exceeded "
                   f"({limiter.max_requests} requests/minute per key)",
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))})
    return key
