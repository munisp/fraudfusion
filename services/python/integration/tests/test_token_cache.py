"""Contract + parity tests for integration/token_cache.py.

The token cache is deliberately duplicated into each service's app/
package (standalone deployables, no shared package). These tests pin the
contract AND the byte-identity of every copy — a fix must land everywhere
or nowhere.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import token_cache
from token_cache import TokenCache, cached_introspect

REPO = Path(__file__).resolve().parents[4]
COPIES = [
    "services/python/billing-service/app/token_cache.py",
    "services/python/kyc-api/app/token_cache.py",
    "services/python/intel-service/app/token_cache.py",
    "services/python/onboarding-service/app/token_cache.py",
    "services/python/webhook-service/app/token_cache.py",
]


class TestCopyParity:
    @pytest.mark.parametrize("copy_path", COPIES)
    def test_copy_is_byte_identical_to_canonical(self, copy_path):
        canonical = (REPO / "services/python/integration/token_cache.py").read_bytes()
        replica = (REPO / copy_path).read_bytes()
        assert replica == canonical, (
            f"{copy_path} diverged from the canonical integration/token_cache.py"
        )


class TestContract:
    def test_active_claims_cached_per_token_hash(self):
        cache = TokenCache(ttl=45.0)
        calls = []
        fetch = lambda t: calls.append(t) or {"active": True, "sub": "u"}
        assert cached_introspect("a", fetch, cache) == cached_introspect("a", fetch, cache)
        assert calls == ["a"]

    def test_inactive_negative_ttl_is_short(self):
        cache = TokenCache(ttl=45.0, neg_ttl=0.05)
        calls = []
        fetch = lambda t: calls.append(t) or {"active": False}
        cached_introspect("x", fetch, cache)
        cached_introspect("x", fetch, cache)
        assert len(calls) == 1
        time.sleep(0.06)
        cached_introspect("x", fetch, cache)
        assert len(calls) == 2

    def test_errors_never_cached(self):
        cache = TokenCache(ttl=45.0)
        calls = []

        def fetch(t):
            calls.append(t)
            raise RuntimeError("idp down")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                cached_introspect("e", fetch, cache)
        assert len(calls) == 2

    def test_disabled_at_zero_ttl(self):
        cache = TokenCache(ttl=0.0)
        calls = []
        fetch = lambda t: calls.append(t) or {"active": True}
        cached_introspect("a", fetch, cache)
        cached_introspect("a", fetch, cache)
        assert len(calls) == 2

    def test_raw_token_never_stored(self):
        cache = TokenCache(ttl=45.0)
        cached_introspect("secret-token", lambda t: {"active": True}, cache)
        assert all("secret-token" not in k for k in cache._entries)

    def test_default_instance_resets_cleanly(self):
        cached_introspect("z", lambda t: {"active": True})
        token_cache.reset_token_cache()
        assert token_cache.DEFAULT_CACHE._entries == {}
