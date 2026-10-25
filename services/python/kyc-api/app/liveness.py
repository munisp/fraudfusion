"""Challenge-response liveness endpoints (Round 10, Lane L).

POST /api/v1/biometric/liveness/challenge issues a STATELESS HMAC-signed
challenge (random phase sequence, 120s TTL) — no table required.
POST /api/v1/biometric/liveness/verify-frames verifies the signature and
expiry, runs the local frame-sequence engine
(services/python/doc-verification/liveness.py), persists a HASH-ONLY audit
row in document_verifications, and emits kyc.verification.completed.

PAD-readiness, not certification: the engine maps signals onto the ISO/IEC
30107-3 attack-instrument taxonomy, but an accredited lab assessment is a
separate procurement step. Inconclusive verdicts route to manual review —
liveness is never fabricated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from app import docverification
from app.api_keys import principal_tenant, require_scope
from app.auth import Principal
from app.db import Database, get_db

logger = logging.getLogger(__name__)

CHALLENGE_TTL_SECONDS = int(os.getenv("LIVENESS_CHALLENGE_TTL_SECONDS", "120"))
MAX_FRAMES = int(os.getenv("LIVENESS_MAX_FRAMES", "12"))
MAX_FRAME_BYTES = 2 * 1024 * 1024  # 2MB per frame

# Directional phases ("left"/"right") defeat generic wiggle replays: the
# subject must pan in the freshly challenged direction, verified by phase
# correlation in the engine.
_PHASE_POOL = ("still", "move", "left", "right")


def _secret() -> bytes:
    raw = os.getenv("LIVENESS_CHALLENGE_SECRET", "").strip()
    if not raw:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "liveness challenges not configured (LIVENESS_CHALLENGE_SECRET)",
        )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest().encode("utf-8")


def _sign(challenge_id: str, phases: list[str], expires_at: int) -> str:
    msg = f"{challenge_id}|{','.join(phases)}|{expires_at}".encode("utf-8")
    return hmac.new(_secret(), msg, hashlib.sha256).hexdigest()


def create_liveness_router() -> APIRouter:
    router = APIRouter()

    @router.post("/api/v1/biometric/liveness/challenge")
    async def issue_challenge(
        principal: Principal = Depends(require_scope("kyc_verify")),
        db: Database = Depends(get_db),
    ) -> dict:
        """Issue a signed challenge: a random still/move/left/right phase
        sequence the client must capture against within the TTL.

        The challenge id is recorded so verify-frames can enforce
        SINGLE-USE consumption — a captured (id, signature) pair cannot be
        replayed for a second verification inside the TTL."""
        phases = [secrets.choice(_PHASE_POOL) for _ in range(3)]
        challenge_id = uuid.uuid4().hex
        expires_at = int(time.time()) + CHALLENGE_TTL_SECONDS
        try:
            db.execute(
                "INSERT INTO liveness_challenges (challenge_id, actor_sub,"
                " phases, expires_at, consumed_at)"
                " VALUES (:cid, :actor, :phases, :exp, NULL)",
                {"cid": challenge_id,
                 "actor": getattr(principal, "sub", ""),
                 "phases": ",".join(phases), "exp": expires_at},
            )
        except Exception as exc:
            # Replay protection is security-critical: fail closed.
            logger.error("liveness challenge persistence failed: %s", exc)
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "liveness challenge store unavailable")
        return {
            "challenge_id": challenge_id,
            "phases": phases,
            "expires_at": expires_at,
            "ttl_seconds": CHALLENGE_TTL_SECONDS,
            "signature": _sign(challenge_id, phases, expires_at),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @router.post("/api/v1/biometric/liveness/verify-frames")
    async def verify_frames(
        challenge_id: str = Form(...),
        phases: str = Form(...),          # comma-joined, as issued
        expires_at: int = Form(...),
        signature: str = Form(...),
        frames: list[UploadFile] = File(...),
        principal: Principal = Depends(require_scope("kyc_verify")),
        db: Database = Depends(get_db),
    ) -> dict:
        phase_list = [p.strip() for p in phases.split(",") if p.strip()]
        expected = _sign(challenge_id, phase_list, int(expires_at))
        if not hmac.compare_digest(expected, signature):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "challenge signature invalid")
        if int(time.time()) > int(expires_at):
            raise HTTPException(status.HTTP_410_GONE, "challenge expired")
        if len(frames) > MAX_FRAMES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                f"at most {MAX_FRAMES} frames")
        payload = []
        for f in frames:
            data = await f.read()
            if len(data) > MAX_FRAME_BYTES:
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    "frame exceeds 2MB limit")
            payload.append(data)

        # Single-use: atomically consume the challenge only AFTER the
        # request validated (a malformed upload must not burn it). The
        # UPDATE lands only when the id exists and is unconsumed; rowcount
        # 0 means unknown or already spent -> 409 replay/unknown.
        try:
            consumed = db.execute(
                "UPDATE liveness_challenges SET consumed_at = :now"
                " WHERE challenge_id = :cid AND consumed_at IS NULL",
                {"now": datetime.now(timezone.utc).isoformat(),
                 "cid": challenge_id},
            )
        except Exception as exc:
            logger.error("liveness challenge consumption failed: %s", exc)
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "liveness challenge store unavailable")
        if not consumed:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "challenge unknown or already consumed — request a fresh one")

        verification_id = uuid.uuid4().hex
        if not docverification.DOCVERIFICATION_AVAILABLE:
            return {
                "verification_id": verification_id,
                "performed": False,
                "verdict": "unavailable",
                "reason": docverification.DOCVERIFICATION_UNAVAILABLE_REASON,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        result = docverification.liveness.analyze_frame_sequence(
            payload, challenge_phases=phase_list)

        # Optional VLM deepfake advisory on the middle frame — never blocks,
        # never auto-passes; "high" synthetic likelihood forces review.
        advisory = docverification.vlm_deepfake_advisory(
            payload[len(payload) // 2])
        if advisory and advisory.get("status") == "ok":
            result.setdefault("signals", []).append({
                "signal": "vlm_deepfake_advisory", "status": "ran",
                "synthetic_likelihood": advisory["synthetic_likelihood"],
                "findings": advisory["findings"],
                "model": advisory.get("model")})
            if (advisory["synthetic_likelihood"] == "high"
                    and result["verdict"] == "live"):
                result["verdict"] = "inconclusive"
                result.setdefault("reasons", []).append(
                    "VLM advisory: high synthetic likelihood — routed to "
                    "manual review")
        elif advisory:
            result.setdefault("signals", []).append({
                "signal": "vlm_deepfake_advisory", "status": "unavailable",
                "reason": advisory.get("reason", "advisory unavailable")})

        # Hash-only audit: frame hashes + verdict, never the frames.
        try:
            db.execute(
                "INSERT INTO document_verifications (id, actor_sub,"
                " document_type, detected_format, sha256, size_bytes, status,"
                " quality, provenance_json, reasons_json, created_at)"
                " VALUES (:id, :actor, :dt, :fmt, :sha, :sz, :st, :q, :prov,"
                " :reasons, :now)",
                {
                    "id": verification_id,
                    "actor": getattr(principal, "sub", ""),
                    "dt": "liveness_frames",
                    "fmt": "frame_sequence",
                    "sha": hashlib.sha256(b"".join(payload)).hexdigest(),
                    "sz": sum(len(p) for p in payload),
                    "st": {"live": "verified", "spoof": "rejected"}.get(
                        result["verdict"], "manual_review"),
                    "q": None,
                    "prov": json.dumps(result["signals"]),
                    "reasons": json.dumps(result["reasons"]),
                    "now": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception as exc:  # persistence must never break verification
            logger.error("liveness verdict persistence failed: %s", exc)

        try:  # webhook, fire-and-forget, never raises
            from app import webhooks
            webhooks.emit_event(
                "kyc.verification.completed",
                principal_tenant(principal),
                {"verification_id": verification_id,
                 "document_type": "liveness_frames",
                 "status": result["verdict"]},
            )
        except Exception as exc:
            logger.debug("liveness webhook emit failed: %s", exc)

        return {
            "verification_id": verification_id,
            "performed": True,
            **result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    return router
