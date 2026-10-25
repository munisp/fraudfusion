"""Tests for the account-takeover detector (was: zero coverage).

Strategy: a fake asyncpg pool over in-memory tables routed by SQL shape,
and Keycloak introspection served through httpx.MockTransport. The ONNX
artifact is pointed at a nonexistent path BEFORE import so scoring runs in
deterministic rule-fallback mode; one test re-enables the real artifact to
prove the hybrid path loads and scores.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ["ATO_MODEL_PATH"] = "/nonexistent/model.onnx"  # before import: rule fallback
for var, value in {
    "DATABASE_URL": "postgresql://fake",
    "KEYCLOAK_URL": "https://keycloak.test",
    "KEYCLOAK_REALM": "fraudfusion",
    "KEYCLOAK_CLIENT_ID": "ato",
    "KEYCLOAK_CLIENT_SECRET": "secret",
    "KEYCLOAK_REQUIRED_ROLES": "fraud_analyst,service",
}.items():
    os.environ.setdefault(var, value)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import main as ato  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fake asyncpg pool over in-memory tables
# ---------------------------------------------------------------------------

class FakeConnection:
    def __init__(self, state):
        self.state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def transaction(self):
        return self  # async CM no-op

    def _logins(self, tenant, user):
        return [r for r in self.state["login_patterns"]
                if r["tenant_id"] == tenant and r["user_id"] == user]

    async def fetchrow(self, sql, *args):
        s = " ".join(sql.split())
        if "COUNT(*) AS recent_logins" in s and "distinct_locations" in s:
            tenant, user, device, location = args
            rows = self._logins(tenant, user)
            return {
                "recent_logins": len(rows),
                "distinct_ips": len({r["ip_address"] for r in rows}),
                "distinct_locations": len({r["location"] for r in rows}),
                "known_device": any(r["device_id"] == device for r in rows),
                "known_location": any(r["location"] == location for r in rows),
            }
        if "COUNT(*) AS recent_logins" in s:
            tenant, user, device, location = args
            rows = self._logins(tenant, user)
            return {
                "recent_logins": len(rows),
                "distinct_ips": len({r["ip_address"] for r in rows}),
                "known_device": any(r["device_id"] == device for r in rows),
                "known_location": any(r["location"] == location for r in rows),
            }
        if "SELECT ip_address, device_id, location FROM login_patterns" in s:
            rows = self._logins(args[0], args[1])
            return max(rows, key=lambda r: r["created_at"]) if rows else None
        if "SELECT location, created_at FROM login_patterns" in s:
            rows = self._logins(args[0], args[1])
            return max(rows, key=lambda r: r["created_at"]) if rows else None
        if "FROM device_fingerprints" in s:
            tenant, user, device = args
            rows = [r for r in self.state["device_fingerprints"]
                    if r["tenant_id"] == tenant and r["user_id"] == user
                    and r["device_id"] == device]
            return max(rows, key=lambda r: r["created_at"]) if rows else None
        if "FROM credential_stuffing_attempts" in s:
            tenant, ip = args
            rows = [r for r in self.state["credential_stuffing_attempts"]
                    if r["tenant_id"] == tenant and r["ip_address"] == ip]
            return {
                "failed_attempts": sum(r["failed_attempts"] for r in rows),
                "targeted_users": len({r["username"] for r in rows}),
            }
        raise AssertionError(f"unrouted fetchrow SQL: {s[:120]}")

    async def execute(self, sql, *args):
        s = " ".join(sql.split())
        if "INSERT INTO login_patterns" in s:
            tenant, user, ip, device, location, ua, created = args
            self.state["login_patterns"].append({
                "tenant_id": tenant, "user_id": user, "ip_address": ip,
                "device_id": device, "location": location, "user_agent": ua,
                "created_at": created,
            })
        elif "INSERT INTO device_fingerprints" in s:
            tenant, user, device, fp = args
            self.state["device_fingerprints"].append({
                "tenant_id": tenant, "user_id": user, "device_id": device,
                "fingerprint": fp, "is_trusted": False, "created_at": NOW,
            })
        elif "UPDATE device_fingerprints SET is_trusted=TRUE" in s:
            tenant, user, device = args
            for r in self.state["device_fingerprints"]:
                if (r["tenant_id"], r["user_id"], r["device_id"]) == (tenant, user, device):
                    r["is_trusted"] = True
        elif "INSERT INTO credential_stuffing_attempts" in s:
            tenant, username, ip, failed = args
            self.state["credential_stuffing_attempts"].append({
                "tenant_id": tenant, "username": username, "ip_address": ip,
                "failed_attempts": failed, "created_at": NOW,
            })
        elif "INSERT INTO ato_events" in s:
            tenant, user, etype, score, indicators = args
            self.state["ato_events"].append({
                "tenant_id": tenant, "user_id": user, "event_type": etype,
                "risk_score": score, "indicators": indicators, "created_at": NOW,
            })
        elif "INSERT INTO ato_alerts" in s:
            tenant, user, atype, level = args
            self.state["ato_alerts"].append({
                "id": len(self.state["ato_alerts"]) + 1, "tenant_id": tenant,
                "user_id": user, "alert_type": atype, "risk_level": level,
                "created_at": NOW,
            })
        else:
            raise AssertionError(f"unrouted execute SQL: {s[:120]}")

    async def fetch(self, sql, *args):
        s = " ".join(sql.split())
        if "FROM ato_alerts" in s:
            tenant, limit = args
            rows = [r for r in self.state["ato_alerts"] if r["tenant_id"] == tenant]
            return sorted(rows, key=lambda r: r["created_at"], reverse=True)[:limit]
        raise AssertionError(f"unrouted fetch SQL: {s[:120]}")


class FakePool:
    def __init__(self, healthy=True):
        self.state = {k: [] for k in ("login_patterns", "device_fingerprints",
                                      "credential_stuffing_attempts",
                                      "ato_events", "ato_alerts")}
        self.healthy = healthy

    def acquire(self):
        return FakeConnection(self.state)

    async def fetchval(self, sql):
        if not self.healthy:
            raise asyncpg.PostgresError("boom")
        return 1

    async def fetch(self, sql, *args):
        return await FakeConnection(self.state).fetch(sql, *args)

    async def close(self):
        pass


# ---------------------------------------------------------------------------
# Auth stubbing via Keycloak MockTransport
# ---------------------------------------------------------------------------

TOKENS = {
    "good-service": {"active": True, "sub": "svc-ato", "roles": ["service"]},
    "good-tenant": {"active": True, "sub": "analyst-1", "roles": ["fraud_analyst"],
                    "tenant_id": "tenant-1"},
    "no-roles": {"active": True, "sub": "user-x", "roles": []},
    "inactive": {"active": False},
}


def _keycloak_client():
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        token = next((kv.split("=", 1)[1] for kv in body.split("&")
                      if kv.startswith("token=")), "")
        claims = TOKENS.get(token)
        if claims is None:
            return httpx.Response(200, json={"active": False})
        return httpx.Response(200, json=claims)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


@pytest.fixture()
def client(monkeypatch):
    ato._token_cache.clear()
    ato._token_inflight.clear()
    pool = FakePool()

    async def fake_create_pool(**kwargs):
        return pool

    monkeypatch.setattr(ato.asyncpg, "create_pool", fake_create_pool)
    with TestClient(ato.app) as tc:
        tc.app.state.http_client = _keycloak_client()
        tc.app.state.pool = pool
        yield tc, pool


def auth(token="good-service"):
    return {"Authorization": f"Bearer {token}"}


def login_event(tenant="tenant-1", user="u-1", device="dev-a", ip="1.1.1.1",
                location="lagos", ts=NOW):
    return {"tenant_id": tenant, "user_id": user, "ip_address": ip,
            "device_id": device, "location": location,
            "timestamp": ts.isoformat(), "user_agent": "test-agent"}


# ---------------------------------------------------------------------------
# Authentication & tenant binding
# ---------------------------------------------------------------------------

class TestAuth:
    def test_missing_bearer_is_401(self, client):
        tc, _ = client
        assert tc.post("/analyze-login", json=login_event()).status_code == 401

    def test_unknown_token_is_401(self, client):
        tc, _ = client
        assert tc.post("/analyze-login", json=login_event(),
                       headers=auth("forged")).status_code == 401

    def test_active_token_without_roles_is_403(self, client):
        tc, _ = client
        assert tc.post("/analyze-login", json=login_event(),
                       headers=auth("no-roles")).status_code == 403

    def test_tenant_token_cannot_touch_other_tenant(self, client):
        tc, _ = client
        resp = tc.post("/analyze-login", json=login_event(tenant="tenant-2"),
                       headers=auth("good-tenant"))
        assert resp.status_code == 403

    def test_tenant_token_reads_own_alerts_only(self, client):
        tc, pool = client
        pool.state["ato_alerts"].append({
            "id": 1, "tenant_id": "tenant-2", "user_id": "u-9",
            "alert_type": "account_takeover", "risk_level": "high",
            "created_at": NOW})
        assert tc.get("/ato-alerts", params={"tenant_id": "tenant-2"},
                      headers=auth("good-tenant")).status_code == 403
        ok = tc.get("/ato-alerts", params={"tenant_id": "tenant-1"},
                    headers=auth("good-tenant"))
        assert ok.status_code == 200 and ok.json()["count"] == 0

    def test_service_account_without_tenant_claim_is_allowed(self, client):
        tc, _ = client
        resp = tc.post("/analyze-login", json=login_event(tenant="tenant-9"),
                       headers=auth("good-service"))
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Detection endpoints (rule-fallback mode)
# ---------------------------------------------------------------------------

class TestAnalyzeLogin:
    def test_known_device_and_location_scores_low(self, client):
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "lagos", "user_agent": "x",
            "created_at": NOW - timedelta(days=1)})
        out = tc.post("/analyze-login", json=login_event(), headers=auth()).json()
        assert out["risk_score"] == 0 and out["is_suspicious"] is False
        assert "score_mode:rule_fallback" in out["indicators"]

    def test_new_device_location_and_ip_rotation_is_suspicious(self, client):
        tc, pool = client
        for i in range(3):
            pool.state["login_patterns"].append({
                "tenant_id": "tenant-1", "user_id": "u-1",
                "ip_address": f"2.2.2.{i}", "device_id": f"old-{i}",
                "location": "abuja", "user_agent": "x",
                "created_at": NOW - timedelta(hours=i + 1)})
        out = tc.post("/analyze-login", json=login_event(), headers=auth()).json()
        # unrecognized_device 25 + unrecognized_location 20 + ip_rotation 20
        assert out["risk_score"] == 65 and out["is_suspicious"] is True
        assert set(out["indicators"]) >= {"unrecognized_device",
                                          "unrecognized_location", "ip_rotation"}


class TestDetectTakeover:
    def test_full_novel_context_triggers_alert(self, client):
        tc, pool = client
        for i in range(3):
            pool.state["login_patterns"].append({
                "tenant_id": "tenant-1", "user_id": "u-1",
                "ip_address": f"3.3.3.{i}", "device_id": f"old-{i}",
                "location": "abuja", "user_agent": "x",
                "created_at": NOW - timedelta(days=i + 1)})
        out = tc.post("/detect-takeover", json=login_event(), headers=auth()).json()
        # new_device 30 + new_location 25 + multiple_recent_ips 20 = 75
        assert out["risk_score"] == 75 and out["takeover_detected"] is True
        assert out["risk_level"] == "critical"
        alerts = [a for a in pool.state["ato_alerts"]
                  if a["alert_type"] == "account_takeover"]
        assert len(alerts) == 1 and alerts[0]["tenant_id"] == "tenant-1"

    def test_known_context_no_alert(self, client):
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "lagos", "user_agent": "x",
            "created_at": NOW - timedelta(days=1)})
        out = tc.post("/detect-takeover", json=login_event(), headers=auth()).json()
        assert out["risk_score"] == 0 and out["takeover_detected"] is False
        assert pool.state["ato_alerts"] == []
        # Event still recorded in the audit trail
        assert pool.state["ato_events"][0]["event_type"] == "takeover_detection"


class TestVerifyDevice:
    def test_new_device_registered_untrusted_then_promoted_on_reverify(self, client):
        tc, pool = client
        body = {"tenant_id": "tenant-1", "user_id": "u-1", "device_id": "dev-a",
                "device_fingerprint": "fp-abcdef123456"}
        first = tc.post("/verify-device", json=body, headers=auth()).json()
        assert first["device_verified"] is False and first["is_trusted"] is False
        second = tc.post("/verify-device", json=body, headers=auth()).json()
        assert second["device_verified"] is True and second["is_trusted"] is True
        assert any(e["event_type"] == "device_trusted"
                   for e in pool.state["ato_events"])

    def test_changed_fingerprint_is_not_verified(self, client):
        tc, _ = client
        body = {"tenant_id": "tenant-1", "user_id": "u-1", "device_id": "dev-a",
                "device_fingerprint": "fp-abcdef123456"}
        tc.post("/verify-device", json=body, headers=auth())
        out = tc.post("/verify-device",
                      json={**body, "device_fingerprint": "fp-DIFFERENT999"},
                      headers=auth()).json()
        assert out["device_verified"] is False and out["is_trusted"] is False


class TestCredentialStuffing:
    def test_small_volume_no_detection(self, client):
        tc, _ = client
        out = tc.post("/detect-credential-stuffing",
                      json={"tenant_id": "tenant-1", "username": "u-1",
                            "ip_address": "9.9.9.9", "failed_attempts": 3},
                      headers=auth()).json()
        assert out["stuffing_detected"] is False and out["risk_score"] == 15

    def test_distributed_burst_detected_and_alerted(self, client):
        tc, pool = client
        for i in range(4):
            out = tc.post("/detect-credential-stuffing",
                          json={"tenant_id": "tenant-1", "username": f"user-{i}",
                                "ip_address": "9.9.9.9", "failed_attempts": 4},
                          headers=auth()).json()
        # total 16 attempts * 5 + (4 users - 1) * 10 = 110 -> capped 100
        assert out["risk_score"] == 100 and out["stuffing_detected"] is True
        assert "multiple_accounts_targeted" in out["indicators"]
        assert any(a["alert_type"] == "credential_stuffing"
                   for a in pool.state["ato_alerts"])


class TestSessionHijacking:
    def test_full_context_change_detected(self, client):
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "lagos", "user_agent": "x",
            "created_at": NOW - timedelta(hours=2)})
        out = tc.post("/detect-session-hijacking",
                      json=login_event(device="dev-b", ip="5.5.5.5",
                                       location="london"),
                      headers=auth()).json()
        assert out["risk_score"] == 80 and out["hijacking_detected"] is True
        assert set(out["indicators"]) == {"device_changed", "ip_changed",
                                          "location_changed"}

    def test_first_seen_session_scores_zero(self, client):
        tc, _ = client
        out = tc.post("/detect-session-hijacking", json=login_event(),
                      headers=auth()).json()
        assert out["risk_score"] == 0 and out["hijacking_detected"] is False


class TestImpossibleTravel:
    def test_lagos_to_london_in_one_hour_is_impossible(self, client):
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "lagos", "user_agent": "x",
            "created_at": NOW - timedelta(hours=1)})
        out = tc.post("/check-impossible-travel",
                      json=login_event(location="london"), headers=auth()).json()
        assert out["impossible_travel"] is True and out["risk_score"] == 70
        assert out["distance_km"] > 4000

    def test_lagos_to_abuja_in_three_hours_is_plausible(self, client):
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "lagos", "user_agent": "x",
            "created_at": NOW - timedelta(hours=3)})
        out = tc.post("/check-impossible-travel",
                      json=login_event(location="abuja"), headers=auth()).json()
        assert out["impossible_travel"] is False and out["risk_score"] == 0

    def test_naive_timestamp_is_coerced_not_500(self, client):
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "lagos", "user_agent": "x",
            "created_at": NOW - timedelta(hours=1)})
        naive = login_event(location="london")
        naive["timestamp"] = "2026-10-25T12:00:00"  # no offset
        resp = tc.post("/check-impossible-travel", json=naive, headers=auth())
        assert resp.status_code == 200
        assert resp.json()["impossible_travel"] is True


class TestHealth:
    def test_health_reports_rule_fallback_mode(self, client):
        tc, _ = client
        out = tc.get("/health").json()
        assert out["status"] == "healthy"
        assert out["scoring_mode"] == "rule_fallback"

    def test_db_outage_is_503(self, client):
        tc, pool = client
        pool.healthy = False
        assert tc.get("/health").status_code == 503


class TestOnnxScorer:
    def test_missing_artifact_is_honest_fallback(self):
        scorer = ato.OnnxScorer()
        assert scorer.mode == "rule_fallback"
        assert scorer.predict_proba({"hour": 3}) is None

    def test_real_artifact_loads_hybrid(self, monkeypatch):
        artifact = (Path(ato.__file__).resolve().parents[3]
                    / "ml" / "artifacts" / "fraud_net" / "v1")
        if not (artifact / "model.onnx").exists():
            pytest.skip("fraud_net artifact not present")
        pytest.importorskip("onnxruntime")
        monkeypatch.setattr(ato, "MODEL_PATH", artifact / "model.onnx")
        monkeypatch.setattr(ato, "ARTIFACT_DIR", artifact)
        scorer = ato.OnnxScorer()
        assert scorer.mode == "hybrid"
        proba = scorer.predict_proba({f: 0.0 for f in ato.NUMERIC_FEATURES})
        assert proba is not None and 0.0 <= proba <= 1.0

    def test_blend_score_paths(self):
        assert ato.blend_score(None, 50) == (50, "rule_fallback")
        score, mode = ato.blend_score(1.0, 0)
        assert mode == "hybrid" and score == round(ato.MODEL_BLEND_WEIGHT * 100)


class TestGeoHonesty:
    def test_unknown_city_is_flagged_not_silently_zero(self, client):
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "lagos", "user_agent": "x",
            "created_at": NOW - timedelta(hours=1)})
        out = tc.post("/check-impossible-travel",
                      json=login_event(location="ouagadougou"),
                      headers=auth()).json()
        assert out["impossible_travel"] is False
        assert "location_unresolved" in out["indicators"]

    def test_regional_cities_now_resolved(self, client):
        # kano -> maiduguri (~500km) in 20 minutes: impossible with the
        # expanded Nigerian table (both were unknown before R4).
        tc, pool = client
        pool.state["login_patterns"].append({
            "tenant_id": "tenant-1", "user_id": "u-1", "ip_address": "1.1.1.1",
            "device_id": "dev-a", "location": "kano", "user_agent": "x",
            "created_at": NOW - timedelta(minutes=20)})
        out = tc.post("/check-impossible-travel",
                      json=login_event(location="maiduguri"),
                      headers=auth()).json()
        assert out["impossible_travel"] is True

    def test_city_distance_unknown_returns_none(self):
        assert ato.city_distance_km("lagos", "atlantis") is None
        assert ato.city_distance_km("Kano", "LAGOS") > 800  # case-insensitive
