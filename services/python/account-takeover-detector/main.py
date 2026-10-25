from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncpg
import httpx
import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger(SERVICE_NAME := "account-takeover-detector")

# Hybrid scoring: ONNX model blended with rules. Rules remain as the
# (loudly logged) fallback when the artifact is missing.
ARTIFACT_DIR = Path(os.getenv(
    "ATO_ARTIFACT_DIR",
    str(Path(__file__).resolve().parents[3] / "ml" / "artifacts" / "fraud_net" / "v1"),
))
MODEL_PATH = Path(os.getenv("ATO_MODEL_PATH", "")) if os.getenv("ATO_MODEL_PATH") else next(
    (p for p in (ARTIFACT_DIR / "fraud_net.onnx", ARTIFACT_DIR / "model.onnx") if p.exists()),
    ARTIFACT_DIR / "model.onnx",
)
MODEL_BLEND_WEIGHT = float(os.getenv("ATO_MODEL_BLEND_WEIGHT", "0.6"))  # 0=rules only, 1=model only

# ml lane fraud_net contract (mirrors ml/data/synthetic_nigeria.py).
NUMERIC_FEATURES = [
    "log_amount", "hour", "dow", "is_month_end", "is_market_day",
    "amount_vs_sender_avg", "sender_txns_24h", "sender_unique_receivers_72h",
    "receiver_fanin_72h", "mins_since_last_txn", "device_emulator",
    "sim_swap_7d", "new_device", "cross_state", "cross_bank", "is_night",
]
CATEGORICAL_FEATURES = ["channel", "sender_bank", "receiver_bank", "sender_state", "device_os"]


class OnnxScorer:
    """Lazy-loading fraud_net ONNX scorer (x_num/x_cat contract). Never raises;
    falls back to rules when the artifact is missing or unloadable."""

    def __init__(self) -> None:
        self.session = None
        self.input_names: list[str] = []
        self.vocab: dict[str, dict[str, int]] = {}
        self.scaler_mean = None
        self.scaler_std = None
        self.mode = "rule_fallback"
        if not MODEL_PATH.exists():
            logger.warning(
                "ATO MODEL ARTIFACT MISSING at %s — using RULE-BASED FALLBACK scoring (heuristic, NOT ML). "
                "Train/export via ml/train to enable the ONNX model.", MODEL_PATH,
            )
            return
        try:
            import json as _json

            import onnxruntime as ort

            vocab_path = ARTIFACT_DIR / "vocab.json"
            if vocab_path.exists():
                self.vocab = _json.loads(vocab_path.read_text())
            prep_path = ARTIFACT_DIR / "preprocess.npz"
            if prep_path.exists():
                prep = np.load(prep_path)
                self.scaler_mean, self.scaler_std = prep["scaler_mean"], prep["scaler_std"]
            self.session = ort.InferenceSession(str(MODEL_PATH), providers=["CPUExecutionProvider"])
            self.input_names = [i.name for i in self.session.get_inputs()]
            self.mode = "hybrid"
            logger.info("Loaded ONNX model %s (inputs=%s)", MODEL_PATH, self.input_names)
        except Exception as exc:  # noqa: BLE001
            self.session = None
            logger.warning("ATO MODEL FAILED TO LOAD (%s) — using RULE-BASED FALLBACK scoring.", exc)

    def predict_proba(self, features: dict[str, float]) -> float | None:
        """Model probability in [0,1], or None when the model is unavailable."""
        if self.session is None:
            return None
        if "x_num" in self.input_names:
            x_num = np.array([[float(features.get(f, 0.0)) for f in NUMERIC_FEATURES]], dtype=np.float32)
            if self.scaler_mean is not None and self.scaler_std is not None:
                x_num = ((x_num - self.scaler_mean) / self.scaler_std).astype(np.float32)
            inputs: dict[str, np.ndarray] = {"x_num": x_num}
            if "x_cat" in self.input_names:
                # All-categorical-unknown -> OOV index 0 (sorted order matches the ml lane).
                inputs["x_cat"] = np.zeros((1, len(CATEGORICAL_FEATURES)), dtype=np.int64)
        else:
            meta = self.session.get_inputs()[0]
            dim = meta.shape[1] if len(meta.shape) >= 2 and isinstance(meta.shape[1], int) and meta.shape[1] > 0 else len(NUMERIC_FEATURES)
            vec = np.zeros(dim, dtype=np.float32)
            for i, name in enumerate(NUMERIC_FEATURES[:dim]):
                vec[i] = float(features.get(name, 0.0))
            inputs = {meta.name: vec.reshape(1, -1)}
        raw = float(np.asarray(self.session.run(None, inputs)[0]).reshape(-1)[0])
        if raw < 0.0 or raw > 1.0:
            raw = 1.0 / (1.0 + math.exp(-raw))
        return raw


def blend_score(model_proba: float | None, rule_score: int) -> tuple[int, str]:
    """Blend model probability with the rule score (both normalized to 0..100)."""
    if model_proba is None:
        return rule_score, "rule_fallback"
    blended = MODEL_BLEND_WEIGHT * (model_proba * 100.0) + (1 - MODEL_BLEND_WEIGHT) * rule_score
    return min(int(round(blended)), 100), "hybrid"


def login_features(event: LoginEvent, history: Any, hour_window_logins: int | None = None) -> dict[str, float]:
    """Map login context onto the fraud_net numeric feature contract."""
    logins = int(hour_window_logins if hour_window_logins is not None else history["recent_logins"])
    return {
        "log_amount": 0.0,
        "hour": float(event.timestamp.hour),
        "dow": float(event.timestamp.weekday()),
        "is_night": 1.0 if event.timestamp.hour < 6 else 0.0,
        "sender_txns_24h": float(logins),
        "sender_unique_receivers_72h": float(history["distinct_ips"] or 0),
        "new_device": 0.0 if bool(history["known_device"]) else 1.0,
        "cross_state": 0.0 if bool(history["known_location"]) else 1.0,
    }


def get_scorer(request: Request) -> OnnxScorer:
    scorer = getattr(request.app.state, "scorer", None)
    if scorer is None:
        scorer = request.app.state.scorer = OnnxScorer()
    return scorer


class LoginEvent(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=255)
    user_id: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=255)
    location: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    user_agent: str | None = Field(default=None, max_length=2048)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _require_tz(cls, v):
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return v


class DeviceVerificationRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=255)
    user_id: str = Field(min_length=1, max_length=255)
    device_id: str = Field(min_length=1, max_length=255)
    device_fingerprint: str = Field(min_length=8, max_length=4096)


class CredentialStuffingRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=64)
    failed_attempts: int = Field(ge=0, le=10000)


class AuthenticatedSubject(BaseModel):
    subject: str
    roles: set[str]
    tenant_id: str | None = None  # token claim; service accounts carry none

    def require_tenant(self, tenant_id: str) -> None:
        """Tenant binding: when the token carries a tenant claim it MUST
        match the requested tenant. Tokens without a tenant claim are
        platform service accounts and are allowed (role-gated above)."""
        if self.tenant_id and self.tenant_id != tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="token is not authorized for this tenant")


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_url = required_env("DATABASE_URL")
    app.state.pool = await asyncpg.create_pool(
        dsn=database_url,
        min_size=int(os.getenv("DB_MIN_CONNECTIONS", "2")),
        max_size=int(os.getenv("DB_MAX_CONNECTIONS", "20")),
        command_timeout=10,
    )
    app.state.http_client = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    # Load the ONNX artifact at startup so the first request does not pay
    # model-load latency.
    app.state.scorer = OnnxScorer()
    yield
    await app.state.http_client.aclose()
    await app.state.pool.close()


app = FastAPI(title="Account Takeover Detector", version="2.0.0", lifespan=lifespan)


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured")
    return value


def required_roles() -> set[str]:
    values = {value.strip() for value in required_env("KEYCLOAK_REQUIRED_ROLES").split(",") if value.strip()}
    if not values:
        raise RuntimeError("KEYCLOAK_REQUIRED_ROLES must contain at least one role")
    return values



# --- Introspection result cache (P3): token-hash TTL cache + singleflight ---
_TOKEN_CACHE_TTL = float(os.getenv("AUTH_CACHE_TTL_SECONDS", "45"))
_TOKEN_NEG_TTL = 5.0
_TOKEN_CACHE_MAX = 10000
_token_cache: dict[str, tuple[float, Any, Any]] = {}  # hash -> (expires_at, claims, exc)
_token_inflight: dict[str, asyncio.Future] = {}
_token_cache_lock = asyncio.Lock()


def _store_token_cache(key: str, entry: tuple[float, Any, Any]) -> None:
    if len(_token_cache) >= _TOKEN_CACHE_MAX:
        now = time.monotonic()
        for k in [k for k, v in _token_cache.items() if v[0] <= now]:
            del _token_cache[k]
        if len(_token_cache) >= _TOKEN_CACHE_MAX:
            return  # correctness never depends on the cache
    _token_cache[key] = entry


async def _introspect_cached(client: httpx.AsyncClient, endpoint: str, token: str, data: dict[str, str]) -> dict[str, Any]:
    """Introspect via a bounded TTL cache keyed by token SHA-256 with
    singleflight dedup; only a cold cache hits Keycloak."""
    key = hashlib.sha256(token.encode()).hexdigest()
    async with _token_cache_lock:
        entry = _token_cache.get(key)
        if entry and entry[0] > time.monotonic():
            _, claims, exc = entry
            if exc is not None:
                raise exc
            return claims
        fut = _token_inflight.get(key)
        leader = fut is None
        if leader:
            fut = asyncio.get_running_loop().create_future()
            _token_inflight[key] = fut
    if not leader:
        claims, exc = await fut
        if exc is not None:
            raise exc
        return claims
    try:
        response = await client.post(endpoint, data=data)
        response.raise_for_status()
        claims: dict[str, Any] = response.json()
        # Active results get the full TTL; inactive/error results get the
        # short negative TTL so newly-activated tokens recover quickly.
        ttl = _TOKEN_CACHE_TTL if claims.get("active") is True else _TOKEN_NEG_TTL
        _store_token_cache(key, (time.monotonic() + ttl, claims, None))
        fut.set_result((claims, None))
        return claims
    except (httpx.HTTPError, ValueError) as exc:
        _store_token_cache(key, (time.monotonic() + _TOKEN_NEG_TTL, None, exc))
        fut.set_result((None, exc))
        raise
    finally:
        async with _token_cache_lock:
            _token_inflight.pop(key, None)

async def authenticate(request: Request, authorization: str = Header(default="")) -> AuthenticatedSubject:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required")

    keycloak_url = required_env("KEYCLOAK_URL").rstrip("/")
    if not keycloak_url.startswith("https://") and os.getenv(
            "KEYCLOAK_INSECURE_HTTP", "").lower() != "true":
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Keycloak must use HTTPS (KEYCLOAK_INSECURE_HTTP=true for local dev only)")
    endpoint = f"{keycloak_url}/realms/{required_env('KEYCLOAK_REALM')}/protocol/openid-connect/token/introspect"
    try:
        claims = await _introspect_cached(
            request.app.state.http_client,
            endpoint,
            token,
            data={
                "token": token,
                "client_id": required_env("KEYCLOAK_CLIENT_ID"),
                "client_secret": required_env("KEYCLOAK_CLIENT_SECRET"),
            },
        )
    except (httpx.HTTPError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token validation unavailable") from error

    if claims.get("active") is not True or not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="inactive token")
    roles = set(claims.get("roles") or [])
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        roles.update(realm_access.get("roles") or [])
    if not roles.intersection(required_roles()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
    tenant_id = claims.get("tenant_id") or claims.get("tenant") or None
    if tenant_id is not None and not isinstance(tenant_id, str):
        tenant_id = str(tenant_id)
    return AuthenticatedSubject(subject=claims["sub"], roles=roles, tenant_id=tenant_id or None)


@app.get("/health")
async def health_check(request: Request):
    try:
        await request.app.state.pool.fetchval("SELECT 1")
    except Exception:  # noqa: BLE001 - any DB failure is honestly "unavailable"
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="database unavailable")
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "scoring_mode": get_scorer(request).mode,
        "model_path": str(MODEL_PATH),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/detect-takeover")
async def detect_takeover(event: LoginEvent, request: Request, subject: AuthenticatedSubject = Depends(authenticate)):
    subject.require_tenant(event.tenant_id)
    async with request.app.state.pool.acquire() as connection:
        async with connection.transaction():
            history = await connection.fetchrow(
                """
                SELECT COUNT(*) AS recent_logins,
                       COUNT(DISTINCT ip_address) AS distinct_ips,
                       COUNT(DISTINCT location) AS distinct_locations,
                       BOOL_OR(device_id = $3) AS known_device,
                       BOOL_OR(location = $4) AS known_location
                FROM login_patterns
                WHERE tenant_id = $1 AND user_id = $2 AND created_at >= NOW() - INTERVAL '30 days'
                """,
                event.tenant_id, event.user_id, event.device_id, event.location,
            )
            await connection.execute(
                """
                INSERT INTO login_patterns (tenant_id, user_id, ip_address, device_id, location, user_agent, created_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                """,
                event.tenant_id, event.user_id, event.ip_address, event.device_id, event.location, event.user_agent, event.timestamp,
            )
            rule_score, indicators = takeover_score(history, event)
            model_proba = await asyncio.to_thread(get_scorer(request).predict_proba, login_features(event, history))
            risk_score, score_mode = blend_score(model_proba, rule_score)
            if score_mode == "rule_fallback":
                logger.warning("takeover_detection served by RULE FALLBACK for user=%s", event.user_id)
            indicators.append(f"score_mode:{score_mode}")
            await record_event(connection, event.tenant_id, event.user_id, "takeover_detection", risk_score, indicators)
            if risk_score >= 60:
                await create_alert(connection, event.tenant_id, event.user_id, "account_takeover", risk_level(risk_score))

    return response(event.user_id, risk_score, indicators, "takeover_detected", risk_score >= 60)


@app.post("/analyze-login")
async def analyze_login(event: LoginEvent, request: Request, subject: AuthenticatedSubject = Depends(authenticate)):
    subject.require_tenant(event.tenant_id)
    async with request.app.state.pool.acquire() as connection:
        history = await connection.fetchrow(
            """
            SELECT COUNT(*) AS recent_logins, COUNT(DISTINCT ip_address) AS distinct_ips,
                   BOOL_OR(device_id = $3) AS known_device, BOOL_OR(location = $4) AS known_location
            FROM login_patterns
            WHERE tenant_id=$1 AND user_id=$2 AND created_at >= NOW() - INTERVAL '24 hours'
            """,
            event.tenant_id, event.user_id, event.device_id, event.location,
        )
        await connection.execute(
            "INSERT INTO login_patterns (tenant_id,user_id,ip_address,device_id,location,user_agent,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            event.tenant_id, event.user_id, event.ip_address, event.device_id, event.location, event.user_agent, event.timestamp,
        )
        rule_score, indicators = login_score(history, event)
        model_proba = await asyncio.to_thread(get_scorer(request).predict_proba, login_features(event, history))
        risk_score, score_mode = blend_score(model_proba, rule_score)
        if score_mode == "rule_fallback":
            logger.warning("login_analysis served by RULE FALLBACK for user=%s", event.user_id)
        indicators.append(f"score_mode:{score_mode}")
        await record_event(connection, event.tenant_id, event.user_id, "login_analysis", risk_score, indicators)
    return response(event.user_id, risk_score, indicators, "is_suspicious", risk_score >= 40)


@app.post("/verify-device")
async def verify_device(payload: DeviceVerificationRequest, request: Request, subject: AuthenticatedSubject = Depends(authenticate)):
    subject.require_tenant(payload.tenant_id)
    async with request.app.state.pool.acquire() as connection:
        existing = await connection.fetchrow(
            "SELECT fingerprint, is_trusted FROM device_fingerprints WHERE tenant_id=$1 AND user_id=$2 AND device_id=$3 ORDER BY created_at DESC LIMIT 1",
            payload.tenant_id, payload.user_id, payload.device_id,
        )
        fingerprint_match = bool(existing and existing["fingerprint"] == payload.device_fingerprint)
        trusted = fingerprint_match and bool(existing["is_trusted"])
        if existing is None:
            await connection.execute(
                "INSERT INTO device_fingerprints (tenant_id,user_id,device_id,fingerprint,is_trusted,created_at) VALUES ($1,$2,$3,$4,FALSE,NOW())",
                payload.tenant_id, payload.user_id, payload.device_id, payload.device_fingerprint,
            )
        elif fingerprint_match and not existing["is_trusted"]:
            # Successful re-verification of a known fingerprint proves continuity of
            # possession: promote the device to trusted (previously is_trusted could
            # never become TRUE, leaving every device permanently untrusted).
            await connection.execute(
                "UPDATE device_fingerprints SET is_trusted=TRUE WHERE tenant_id=$1 AND user_id=$2 AND device_id=$3",
                payload.tenant_id, payload.user_id, payload.device_id,
            )
            trusted = True
            await record_event(connection, payload.tenant_id, payload.user_id, "device_trusted", 0, ["device_promoted_to_trusted"])
        await record_event(connection, payload.tenant_id, payload.user_id, "device_verification", 0 if trusted else 30, ["trusted_device" if trusted else "unrecognized_device"])
    return {"user_id": payload.user_id, "device_verified": fingerprint_match, "is_trusted": trusted, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/detect-credential-stuffing")
async def detect_credential_stuffing(payload: CredentialStuffingRequest, request: Request, subject: AuthenticatedSubject = Depends(authenticate)):
    subject.require_tenant(payload.tenant_id)
    async with request.app.state.pool.acquire() as connection:
        async with connection.transaction():
            await connection.execute(
                "INSERT INTO credential_stuffing_attempts (tenant_id,username,ip_address,failed_attempts,created_at) VALUES ($1,$2,$3,$4,NOW())",
                payload.tenant_id, payload.username, payload.ip_address, payload.failed_attempts,
            )
            aggregate = await connection.fetchrow(
                "SELECT COALESCE(SUM(failed_attempts),0) AS failed_attempts, COUNT(DISTINCT username) AS targeted_users FROM credential_stuffing_attempts WHERE tenant_id=$1 AND ip_address=$2 AND created_at >= NOW() - INTERVAL '1 hour'",
                payload.tenant_id, payload.ip_address,
            )
            total_attempts = int(aggregate["failed_attempts"])
            targeted_users = int(aggregate["targeted_users"])
            score = min(100, total_attempts * 5 + max(0, targeted_users - 1) * 10)
            indicators = ["repeated_failed_attempts"] if total_attempts >= 5 else []
            if targeted_users >= 3:
                indicators.append("multiple_accounts_targeted")
            await record_event(connection, payload.tenant_id, payload.username, "credential_stuffing", score, indicators)
            if score >= 60:
                await create_alert(connection, payload.tenant_id, payload.username, "credential_stuffing", risk_level(score))
    return {"username": payload.username, "stuffing_detected": score >= 60, "risk_score": score, "failed_attempts_last_hour": total_attempts, "targeted_users_last_hour": targeted_users, "indicators": indicators, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/detect-session-hijacking")
async def detect_session_hijacking(event: LoginEvent, request: Request, subject: AuthenticatedSubject = Depends(authenticate)):
    subject.require_tenant(event.tenant_id)
    async with request.app.state.pool.acquire() as connection:
        previous = await connection.fetchrow(
            "SELECT ip_address, device_id, location FROM login_patterns WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 1",
            event.tenant_id, event.user_id,
        )
        indicators: list[str] = []
        score = 0
        if previous:
            if previous["device_id"] != event.device_id:
                score += 35
                indicators.append("device_changed")
            if previous["ip_address"] != event.ip_address:
                score += 20
                indicators.append("ip_changed")
            if previous["location"] != event.location:
                score += 25
                indicators.append("location_changed")
        await connection.execute(
            "INSERT INTO login_patterns (tenant_id,user_id,ip_address,device_id,location,user_agent,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            event.tenant_id, event.user_id, event.ip_address, event.device_id, event.location, event.user_agent, event.timestamp,
        )
        await record_event(connection, event.tenant_id, event.user_id, "session_hijacking", score, indicators)
        if score >= 60:
            await create_alert(connection, event.tenant_id, event.user_id, "session_hijacking", risk_level(score))
    return response(event.user_id, score, indicators, "hijacking_detected", score >= 60)


@app.post("/check-impossible-travel")
async def check_impossible_travel(event: LoginEvent, request: Request, subject: AuthenticatedSubject = Depends(authenticate)):
    subject.require_tenant(event.tenant_id)
    async with request.app.state.pool.acquire() as connection:
        previous = await connection.fetchrow(
            "SELECT location, created_at FROM login_patterns WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 1",
            event.tenant_id, event.user_id,
        )
        distance_km, time_diff_hours = 0.0, 0.0
        impossible = False
        indicators: list[str] = []
        if previous:
            dist = city_distance_km(previous["location"], event.location)
            if dist is None:
                # Honest gap: an unknown city must never look like zero travel.
                indicators.append("location_unresolved")
            else:
                distance_km = dist
                time_diff_hours = max((event.timestamp - previous["created_at"]).total_seconds() / 3600, 0.001)
                impossible = distance_km > 0 and distance_km / time_diff_hours > 900
                if impossible:
                    indicators.append("impossible_travel_velocity")
        score = 70 if impossible else 0
        await connection.execute(
            "INSERT INTO login_patterns (tenant_id,user_id,ip_address,device_id,location,user_agent,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            event.tenant_id, event.user_id, event.ip_address, event.device_id, event.location, event.user_agent, event.timestamp,
        )
        await record_event(connection, event.tenant_id, event.user_id, "impossible_travel", score, indicators)
        if impossible:
            await create_alert(connection, event.tenant_id, event.user_id, "impossible_travel", risk_level(score))
    return {"user_id": event.user_id, "impossible_travel": impossible, "distance_km": round(distance_km, 2), "time_diff_hours": round(time_diff_hours, 3), "risk_score": score, "indicators": indicators, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/ato-alerts")
async def get_ato_alerts(request: Request, tenant_id: str, limit: int = 50, subject: AuthenticatedSubject = Depends(authenticate)):
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_id is required")
    subject.require_tenant(tenant_id)
    limit = min(max(limit, 1), 200)
    rows = await request.app.state.pool.fetch(
        "SELECT id,user_id,alert_type,risk_level,created_at FROM ato_alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2",
        tenant_id, limit,
    )
    alerts = [{"alert_id": row["id"], "user_id": row["user_id"], "alert_type": row["alert_type"], "risk_level": row["risk_level"], "timestamp": row["created_at"].isoformat()} for row in rows]
    return {"alerts": alerts, "count": len(alerts)}


async def record_event(connection: asyncpg.Connection, tenant_id: str, user_id: str, event_type: str, risk_score: int, indicators: list[str]) -> None:
    await connection.execute(
        "INSERT INTO ato_events (tenant_id,user_id,event_type,risk_score,indicators,created_at) VALUES ($1,$2,$3,$4,$5,NOW())",
        tenant_id, user_id, event_type, risk_score, indicators,
    )


async def create_alert(connection: asyncpg.Connection, tenant_id: str, user_id: str, alert_type: str, level: str) -> None:
    await connection.execute(
        "INSERT INTO ato_alerts (tenant_id,user_id,alert_type,risk_level,created_at) VALUES ($1,$2,$3,$4,NOW())",
        tenant_id, user_id, alert_type, level,
    )


def takeover_score(history: asyncpg.Record, event: LoginEvent) -> tuple[int, list[str]]:
    score, indicators = 0, []
    if not bool(history["known_device"]):
        score += 30
        indicators.append("new_device")
    if not bool(history["known_location"]):
        score += 25
        indicators.append("new_location")
    if int(history["distinct_ips"]) >= 3:
        score += 20
        indicators.append("multiple_recent_ips")
    if int(history["recent_logins"]) >= 20:
        score += 20
        indicators.append("high_login_velocity")
    return min(score, 100), indicators


def login_score(history: asyncpg.Record, event: LoginEvent) -> tuple[int, list[str]]:
    score, indicators = 0, []
    if not bool(history["known_device"]):
        score += 25
        indicators.append("unrecognized_device")
    if not bool(history["known_location"]):
        score += 20
        indicators.append("unrecognized_location")
    if int(history["distinct_ips"]) >= 3:
        score += 20
        indicators.append("ip_rotation")
    return min(score, 100), indicators


def response(user_id: str, score: int, indicators: list[str], boolean_field: str, value: bool) -> dict[str, Any]:
    return {"user_id": user_id, boolean_field: value, "risk_score": score, "risk_level": risk_level(score), "indicators": indicators, "timestamp": datetime.now(timezone.utc).isoformat()}


def risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def city_distance_km(origin: str, destination: str) -> float | None:
    """Great-circle distance in km, or None when either city is unknown —
    callers MUST surface that honestly (a silent 0.0 reads as 'no travel')."""
    coordinates = {
        # Nigerian state capitals and major cities
        "abuja": (9.0765, 7.3986), "lagos": (6.5244, 3.3792),
        "kano": (12.0022, 8.5920), "ibadan": (7.3775, 3.9470),
        "port harcourt": (4.8156, 7.0498), "benin city": (6.3350, 5.6037),
        "kaduna": (10.5105, 7.4165), "jos": (9.8965, 8.8583),
        "ilorin": (8.4966, 4.5426), "enugu": (6.4403, 7.4942),
        "aba": (5.1166, 7.3667), "onitsha": (6.1667, 6.7833),
        "warri": (5.5167, 5.7500), "owerri": (5.4833, 7.0333),
        "calabar": (4.9517, 8.3220), "uyo": (5.0333, 7.9167),
        "akure": (7.2571, 5.2058), "osogbo": (7.7667, 4.5667),
        "abeokuta": (7.1475, 3.3619), "maiduguri": (11.8311, 13.1510),
        "zaria": (11.0855, 7.7199), "sokoto": (13.0059, 5.2476),
        "katsina": (12.9908, 7.6018), "bauchi": (10.3158, 9.8442),
        "gombe": (10.2897, 11.1673), "yola": (9.2000, 12.4833),
        "makurdi": (7.7322, 8.5391), "minna": (9.6136, 6.5569),
        "lafia": (8.4833, 8.5167), "asaba": (6.1833, 6.7333),
        "awka": (6.2167, 7.0833), "lokoja": (7.8023, 6.7333),
        "dutse": (11.7594, 9.3392), "damaturu": (11.7469, 11.9609),
        "birnin kebbi": (12.4539, 4.1975), "jalingo": (8.8833, 11.3667),
        "yenegoa": (4.9267, 6.2676), "ado ekiti": (7.6167, 5.2167),
        "ogbomosho": (8.1333, 4.2667), "nsukka": (6.8567, 7.3958),
        # Regional and global hubs
        "accra": (5.6037, -0.1870), "abidjan": (5.3600, -4.0083),
        "dakar": (14.7167, -17.4677), "nairobi": (-1.2921, 36.8219),
        "johannesburg": (-26.2041, 28.0473), "cairo": (30.0444, 31.2357),
        "london": (51.5072, -0.1276), "paris": (48.8566, 2.3522),
        "frankfurt": (50.1109, 8.6821), "amsterdam": (52.3676, 4.9041),
        "madrid": (40.4168, -3.7038), "rome": (41.9028, 12.4964),
        "istanbul": (41.0082, 28.9784), "dubai": (25.2048, 55.2708),
        "doha": (25.2854, 51.5310), "riyadh": (24.7136, 46.6753),
        "mumbai": (19.0760, 72.8777), "delhi": (28.7041, 77.1025),
        "singapore": (1.3521, 103.8198), "hong kong": (22.3193, 114.1694),
        "tokyo": (35.6762, 139.6503), "beijing": (39.9042, 116.4074),
        "shanghai": (31.2304, 121.4737), "sydney": (-33.8688, 151.2093),
        "new york": (40.7128, -74.0060), "los angeles": (34.0522, -118.2437),
        "chicago": (41.8781, -87.6298), "houston": (29.7604, -95.3698),
        "atlanta": (33.7490, -84.3880), "miami": (25.7617, -80.1918),
        "toronto": (43.6532, -79.3832), "sao paulo": (-23.5505, -46.6333),
    }
    source = coordinates.get(origin.strip().lower())
    target = coordinates.get(destination.strip().lower())
    if not source or not target:
        return None
    lat1, lon1, lat2, lon2 = map(math.radians, (*source, *target))
    haversine = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(haversine))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8092")))
