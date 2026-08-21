from __future__ import annotations

import math
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import asyncpg
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

SERVICE_NAME = "account-takeover-detector"


class LoginEvent(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=255)
    user_id: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=255)
    location: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    user_agent: str | None = Field(default=None, max_length=2048)


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


async def authenticate(request: Request, authorization: str = Header(default="")) -> AuthenticatedSubject:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required")

    keycloak_url = required_env("KEYCLOAK_URL").rstrip("/")
    if not keycloak_url.startswith("https://"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Keycloak must use HTTPS")
    endpoint = f"{keycloak_url}/realms/{required_env('KEYCLOAK_REALM')}/protocol/openid-connect/token/introspect"
    try:
        response = await request.app.state.http_client.post(
            endpoint,
            data={
                "token": token,
                "client_id": required_env("KEYCLOAK_CLIENT_ID"),
                "client_secret": required_env("KEYCLOAK_CLIENT_SECRET"),
            },
        )
        response.raise_for_status()
        claims: dict[str, Any] = response.json()
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
    return AuthenticatedSubject(subject=claims["sub"], roles=roles)


@app.get("/health")
async def health_check(request: Request):
    try:
        await request.app.state.pool.fetchval("SELECT 1")
    except asyncpg.PostgresError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="database unavailable")
    return {"status": "healthy", "service": SERVICE_NAME, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/detect-takeover")
async def detect_takeover(event: LoginEvent, request: Request, _: AuthenticatedSubject = Depends(authenticate)):
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
            risk_score, indicators = takeover_score(history, event)
            await record_event(connection, event.tenant_id, event.user_id, "takeover_detection", risk_score, indicators)
            if risk_score >= 60:
                await create_alert(connection, event.tenant_id, event.user_id, "account_takeover", risk_level(risk_score))

    return response(event.user_id, risk_score, indicators, "takeover_detected", risk_score >= 60)


@app.post("/analyze-login")
async def analyze_login(event: LoginEvent, request: Request, _: AuthenticatedSubject = Depends(authenticate)):
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
        risk_score, indicators = login_score(history, event)
        await record_event(connection, event.tenant_id, event.user_id, "login_analysis", risk_score, indicators)
    return response(event.user_id, risk_score, indicators, "is_suspicious", risk_score >= 40)


@app.post("/verify-device")
async def verify_device(payload: DeviceVerificationRequest, request: Request, _: AuthenticatedSubject = Depends(authenticate)):
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
        await record_event(connection, payload.tenant_id, payload.user_id, "device_verification", 0 if trusted else 30, ["trusted_device" if trusted else "unrecognized_device"])
    return {"user_id": payload.user_id, "device_verified": fingerprint_match, "is_trusted": trusted, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/detect-credential-stuffing")
async def detect_credential_stuffing(payload: CredentialStuffingRequest, request: Request, _: AuthenticatedSubject = Depends(authenticate)):
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
async def detect_session_hijacking(event: LoginEvent, request: Request, _: AuthenticatedSubject = Depends(authenticate)):
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
async def check_impossible_travel(event: LoginEvent, request: Request, _: AuthenticatedSubject = Depends(authenticate)):
    async with request.app.state.pool.acquire() as connection:
        previous = await connection.fetchrow(
            "SELECT location, created_at FROM login_patterns WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 1",
            event.tenant_id, event.user_id,
        )
        distance_km, time_diff_hours = 0.0, 0.0
        impossible = False
        indicators: list[str] = []
        if previous:
            distance_km = city_distance_km(previous["location"], event.location)
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
async def get_ato_alerts(request: Request, tenant_id: str, limit: int = 50, _: AuthenticatedSubject = Depends(authenticate)):
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_id is required")
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


def city_distance_km(origin: str, destination: str) -> float:
    coordinates = {
        "lagos": (6.5244, 3.3792), "abuja": (9.0765, 7.3986), "port harcourt": (4.8156, 7.0498),
        "london": (51.5072, -0.1276), "new york": (40.7128, -74.0060), "dubai": (25.2048, 55.2708),
    }
    source = coordinates.get(origin.strip().lower())
    target = coordinates.get(destination.strip().lower())
    if not source or not target:
        return 0.0
    lat1, lon1, lat2, lon2 = map(math.radians, (*source, *target))
    haversine = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(haversine))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8092")))
