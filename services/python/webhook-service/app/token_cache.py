"""Bounded TTL cache for Keycloak token introspection (fail-closed).

Every control-plane request introspects its bearer token against Keycloak.
That is correct but expensive: p99 latency and IdP load scale with request
rate. This module caches introspection outcomes keyed by the token's
SHA-256 (the token itself is never stored):

  * active claims     -> cached for AUTH_CACHE_TTL_SECONDS (default 45s)
  * inactive claims   -> negative-cached for 5s (freshly activated tokens
                         recover quickly)
  * transport errors  -> NEVER cached; every retry hits the IdP, so a
                         recovered Keycloak is picked up immediately and a
                         flaky network cannot pin a 503 onto a healthy token

Fail-closed is preserved: a cache miss or expiry always performs a real
introspection, and the cache never fabricates claims. Correctness never
depends on the cache (bounded, evicting).

Set AUTH_CACHE_TTL_SECONDS=0 to disable caching entirely.

This file is intentionally duplicated across the Python services (the
platform's services are standalone deployables with no shared package);
keep the copies byte-identical.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Any, Callable, Optional

TTL_SECONDS = float(os.getenv("AUTH_CACHE_TTL_SECONDS", "45"))
NEG_TTL_SECONDS = 5.0
MAX_ENTRIES = 10_000


class TokenCache:
    """Thread-safe bounded TTL cache: token-hash -> (expires_at, claims)."""

    def __init__(self, ttl: float = TTL_SECONDS, neg_ttl: float = NEG_TTL_SECONDS,
                 max_entries: int = MAX_ENTRIES) -> None:
        self.ttl = ttl
        self.neg_ttl = neg_ttl
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[float, dict[str, Any]]] = {}

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def get(self, token: str) -> Optional[dict[str, Any]]:
        if self.ttl <= 0:
            return None
        with self._lock:
            entry = self._entries.get(self._key(token))
            if entry and entry[0] > time.monotonic():
                return entry[1]
            if entry:
                del self._entries[self._key(token)]
        return None

    def put(self, token: str, claims: dict[str, Any]) -> None:
        if self.ttl <= 0:
            return
        ttl = self.ttl if claims.get("active") is True else self.neg_ttl
        with self._lock:
            if len(self._entries) >= self.max_entries:
                now = time.monotonic()
                for key in [k for k, v in self._entries.items() if v[0] <= now]:
                    del self._entries[key]
                if len(self._entries) >= self.max_entries:
                    return  # bound holds even under churn; skip caching
            self._entries[self._key(token)] = (time.monotonic() + ttl, claims)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# Process-wide default instance; services may construct their own.
DEFAULT_CACHE = TokenCache()


def cached_introspect(token: str, fetch: Callable[[str], dict[str, Any]],
                      cache: TokenCache = DEFAULT_CACHE) -> dict[str, Any]:
    """Return introspection claims for ``token``, consulting the cache first.

    ``fetch`` performs the real introspection and RAISES on any error —
    exceptions propagate and are never cached. Concurrent duplicate fetches
    for the same cold token are accepted (the IdP sees at most a burst of
    duplicates per TTL window per token; correctness is unaffected).
    """
    cached = cache.get(token)
    if cached is not None:
        return cached
    claims = fetch(token)
    cache.put(token, claims)
    return claims


def reset_token_cache() -> None:
    """Test hook: drop every cached entry."""
    DEFAULT_CACHE.clear()
