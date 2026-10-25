"""Token introspection cache contract (app/token_cache.py).

Covers: active-claim caching, negative caching of inactive tokens,
never-cache-errors, the disable switch, boundedness, and hash-only keying.
"""

from __future__ import annotations

import time

import pytest

from app.token_cache import TokenCache, cached_introspect


@pytest.fixture(autouse=True)
def _fresh():
    yield


def test_active_claims_cached_per_token_hash():
    cache = TokenCache(ttl=45.0)
    calls = []

    def fetch(token):
        calls.append(token)
        return {"active": True, "sub": "user-1"}

    first = cached_introspect("tok-a", fetch, cache)
    second = cached_introspect("tok-a", fetch, cache)
    assert first == second == {"active": True, "sub": "user-1"}
    assert calls == ["tok-a"]  # one real introspection for two requests


def test_distinct_tokens_do_not_share_entries():
    cache = TokenCache(ttl=45.0)
    calls = []

    def fetch(token):
        calls.append(token)
        return {"active": True, "sub": token}

    cached_introspect("tok-a", fetch, cache)
    cached_introspect("tok-b", fetch, cache)
    assert calls == ["tok-a", "tok-b"]


def test_inactive_uses_short_negative_ttl(monkeypatch):
    cache = TokenCache(ttl=45.0, neg_ttl=0.05)
    calls = []

    def fetch(token):
        calls.append(token)
        return {"active": False}

    cached_introspect("tok-x", fetch, cache)
    cached_introspect("tok-x", fetch, cache)
    assert len(calls) == 1  # negatively cached
    time.sleep(0.06)
    cached_introspect("tok-x", fetch, cache)
    assert len(calls) == 2  # recovered quickly after negative TTL


def test_errors_are_never_cached():
    cache = TokenCache(ttl=45.0)
    calls = []

    def fetch(token):
        calls.append(token)
        raise RuntimeError("idp unreachable")

    with pytest.raises(RuntimeError):
        cached_introspect("tok-err", fetch, cache)
    with pytest.raises(RuntimeError):
        cached_introspect("tok-err", fetch, cache)
    assert len(calls) == 2  # every retry hit the IdP


def test_disabled_when_ttl_zero():
    cache = TokenCache(ttl=0.0)
    calls = []

    def fetch(token):
        calls.append(token)
        return {"active": True}

    cached_introspect("tok-a", fetch, cache)
    cached_introspect("tok-a", fetch, cache)
    assert len(calls) == 2


def test_bound_is_enforced_under_churn():
    cache = TokenCache(ttl=45.0, max_entries=8)
    for i in range(100):
        cached_introspect(f"tok-{i}", lambda t: {"active": True, "sub": t}, cache)
    assert len(cache._entries) <= 8


def test_raw_token_never_stored():
    cache = TokenCache(ttl=45.0)
    cached_introspect("tok-plaintext-secret", lambda t: {"active": True}, cache)
    assert all("tok-plaintext-secret" not in key for key in cache._entries)

