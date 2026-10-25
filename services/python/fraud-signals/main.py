"""Fraud Signals API — developing-market fraud detectors behind a mesh service.

Exposes the eight detectors in ``detectors.py`` as POST /api/v1/signals/<name>
endpoints (hyphenated or underscored names accepted). Every evaluation:

  1. merges inline ``events`` with stored history for ``subject_id``
  2. runs the pure detector function -> (score, verdict, factors)
  3. records the triggering event in ``signal_events``
  4. appends a hash-chained row to ``signal_evals`` (tamper-evident audit)
  5. returns {score, verdict, factors, audit_hash}

The service fails honest: if the store is unavailable the detector still runs
on inline events and a ``history_unavailable`` factor records the gap.
"""
from __future__ import annotations

import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detectors import DETECTORS  # noqa: E402
from geo_enrich import enrich_agent_distance  # noqa: E402
from store import get_store, now_iso  # noqa: E402

log = logging.getLogger("fraud-signals")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

app = FastAPI(title="FraudFusion Fraud Signals", version="1.0.0")

# Mesh integration (fail-closed, advisory only)
_INTEGRATION_PATH = os.environ.get(
    "INTEGRATION_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "integration"),
)
if os.path.isdir(_INTEGRATION_PATH) and _INTEGRATION_PATH not in sys.path:
    sys.path.insert(0, _INTEGRATION_PATH)
try:  # pragma: no cover - depends on repo layout
    from mesh import get_mesh  # type: ignore

    INTEGRATION_AVAILABLE = True
except Exception:  # pragma: no cover
    get_mesh = None  # type: ignore
    INTEGRATION_AVAILABLE = False

# Auto-metering: every successful detector evaluation is metered to
# billing-service as a fraud_score usage event (fail-closed — metering
# failure never breaks the request path; see integration/metering.py).
try:  # pragma: no cover - depends on repo layout
    from metering import UsageMeteringMiddleware, metering_stats  # type: ignore

    METERING_AVAILABLE = True
except Exception:  # pragma: no cover
    UsageMeteringMiddleware = None  # type: ignore
    metering_stats = None  # type: ignore
    METERING_AVAILABLE = False

if METERING_AVAILABLE:
    app.add_middleware(
        UsageMeteringMiddleware,
        routes=[("POST", "/api/v1/signals", "fraud_score")],
        service_name="fraud-signals",
    )


class SignalRequest(BaseModel):
    subject_id: str = Field(..., min_length=1)
    payload: Dict[str, Any] = Field(default_factory=dict)
    events: Optional[List[Dict[str, Any]]] = None
    history_days: int = Field(default=90, ge=1, le=3650)
    record_event: bool = True
    event_kind: Optional[str] = None


class EventIngest(BaseModel):
    kind: str = Field(..., min_length=1)
    subject_id: str = Field(..., min_length=1)
    payload: Dict[str, Any] = Field(default_factory=dict)


def _normalize(name: str) -> str:
    return name.replace("-", "_")


@app.get("/health")
def health() -> Dict[str, Any]:
    store_ok = False
    try:
        get_store().query("SELECT 1", {})
        store_ok = True
    except Exception:
        store_ok = False
    try:
        geo_mode = "postgres" if getattr(get_store(), "_is_pg", False) else "embedded"
    except Exception:
        geo_mode = "embedded"
    return {
        "status": "ok" if store_ok else "degraded",
        "store": "ok" if store_ok else "unavailable",
        "geo": geo_mode,
        "detectors": sorted(DETECTORS.keys()),
        "mesh": INTEGRATION_AVAILABLE,
        "metering": metering_stats() if METERING_AVAILABLE else "unavailable",
    }


@app.get("/api/v1/integrations/status")
def integrations_status() -> Dict[str, Any]:
    if not INTEGRATION_AVAILABLE or get_mesh is None:
        return {"status": "unavailable", "reason": "integration module not present"}
    return get_mesh().status()


@app.post("/api/v1/signals/events")
def ingest_event(body: EventIngest) -> Dict[str, Any]:
    store = get_store()
    try:
        store.record_event(str(uuid.uuid4()), body.kind, body.subject_id,
                           body.payload, now_iso())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"event store unavailable: {exc}")
    return {"status": "recorded", "kind": body.kind, "subject_id": body.subject_id}


def _enrich_counterparty_risk(store, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Service-side sender-risk enrichment (Round 22): incoming transfer
    events whose payload names a counterparty but carries no
    counterparty_risk get annotated from the latest stored eval score for
    that counterparty — the detector stays pure; the service composes it
    with its own history. Never fabricates: unknown senders stay
    unannotated."""
    enriched = []
    cache: Dict[str, Optional[float]] = {}
    for e in events:
        payload = dict(e.get("payload") or {})
        cp = payload.get("counterparty")
        if (payload.get("direction") == "in" and cp
                and payload.get("counterparty_risk") is None):
            if cp not in cache:
                try:
                    rows = store.query(
                        "SELECT score FROM signal_evals WHERE subject_id = :s"
                        " ORDER BY created_at DESC, id DESC LIMIT 1",
                        {"s": str(cp)})
                    cache[cp] = float(rows[0]["score"]) if rows else None
                except Exception:  # noqa: BLE001
                    cache[cp] = None
            if cache[cp] is not None:
                payload["counterparty_risk"] = cache[cp]
        enriched.append({**e, "payload": payload})
    return enriched


def _evaluate(name: str, body: SignalRequest, mode: str) -> Dict[str, Any]:
    detector = DETECTORS[name]
    store = get_store()
    events: List[Dict[str, Any]] = list(body.events or [])
    history_note = None
    try:
        since = (datetime.now(timezone.utc)
                 - timedelta(days=body.history_days)).isoformat()
        kind = body.event_kind or name
        stored = store.events(kind, body.subject_id, since)
        events = stored + events
    except Exception as exc:  # noqa: BLE001
        history_note = f"history unavailable: {exc}"

    if name == "mule":
        events = _enrich_counterparty_risk(store, events)

    # Service-side geo enrichment: never trust a caller to measure its own
    # agents. The scored payload copy may gain distance_from_registered_km;
    # the audited event keeps the caller's original payload.
    score_payload = body.payload
    geo_note = None
    if name == "agent":
        score_payload, geo_note = enrich_agent_distance(body.payload, store)

    score, verdict, factors = detector(score_payload, events)
    if history_note:
        factors = factors + [{"code": "history_unavailable",
                              "detail": history_note, "weight": 0.0}]
    if geo_note:
        factors = factors + [{"code": "geo_enrichment",
                              "detail": geo_note, "weight": 0.0}]

    audit_hash = None
    try:
        if body.record_event and mode == "enforce":
            store.record_event(str(uuid.uuid4()), body.event_kind or name,
                               body.subject_id, body.payload, now_iso())
        audit_hash = store.append_eval(str(uuid.uuid4()), name, body.subject_id,
                                       score, verdict, factors, now_iso(),
                                       mode=mode)
    except Exception as exc:  # noqa: BLE001
        log.warning("audit append failed: %s", exc)

    return {
        "detector": name,
        "subject_id": body.subject_id,
        "score": score,
        "verdict": verdict,
        "factors": factors,
        "mode": mode,
        "audit_hash": audit_hash,
        "audit": "ok" if audit_hash else "unavailable",
    }


@app.post("/api/v1/signals/{detector_name}")
def evaluate(detector_name: str, body: SignalRequest) -> Dict[str, Any]:
    name = _normalize(detector_name)
    if name not in DETECTORS:
        raise HTTPException(
            status_code=404,
            detail=f"unknown detector {detector_name!r}; available: {sorted(DETECTORS)}",
        )
    return _evaluate(name, body, mode="enforce")


@app.post("/api/v1/signals/shadow/{detector_name}")
def evaluate_shadow(detector_name: str, body: SignalRequest) -> Dict[str, Any]:
    """Shadow mode: full evaluation + tamper-evident audit row, but the
    triggering event is NOT recorded (live history stays clean) and the eval
    is tagged mode='shadow' so score distributions can be replayed for
    threshold tuning without touching enforcement data."""
    name = _normalize(detector_name)
    if name not in DETECTORS:
        raise HTTPException(
            status_code=404,
            detail=f"unknown detector {detector_name!r}; available: {sorted(DETECTORS)}",
        )
    return _evaluate(name, body, mode="shadow")


@app.get("/api/v1/signals/scores/{detector_name}")
def score_distribution(detector_name: str, mode: str = "shadow") -> Dict[str, Any]:
    """Score/verdict rows for threshold tuning — defaults to shadow evals so
    tuning analysis never mixes with enforcement records."""
    name = _normalize(detector_name)
    if name not in DETECTORS:
        raise HTTPException(status_code=404, detail=f"unknown detector {detector_name!r}")
    if mode not in ("shadow", "enforce"):
        raise HTTPException(status_code=400, detail="mode must be shadow|enforce")
    store = get_store()
    rows = store.query(
        "SELECT subject_id, score, verdict, created_at FROM signal_evals"
        " WHERE detector = :d AND mode = :m ORDER BY created_at",
        {"d": name, "m": mode})
    scores = [r["score"] for r in rows]
    return {"detector": name, "mode": mode, "count": len(rows),
            "min": min(scores) if scores else None,
            "max": max(scores) if scores else None,
            "mean": round(sum(scores) / len(scores), 4) if scores else None,
            "rows": rows}


@app.get("/api/v1/signals/chain/{detector_name}")
def verify_chain(detector_name: str) -> Dict[str, Any]:
    name = _normalize(detector_name)
    if name not in DETECTORS:
        raise HTTPException(status_code=404, detail=f"unknown detector {detector_name!r}")
    store = get_store()
    try:
        result = store.verify_chain(name)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"store unavailable: {exc}")
    return {"detector": name, **result}
