"""A/B model router (FastAPI, port 8200).

Routes /v1/route/score traffic between a champion and challenger model
according to an experiment config (mlops/experiments/*.yaml):

- Deterministic assignment by sha256(customer_id) % 100 < challenger_pct.
- Each model arm is an HTTP scorer (e.g. aml_service instances on different
  ports/models) configured via URL in the experiment YAML.
- Every assignment + score is logged to parquet (ROUTER_LOG_DIR, dt=
  partitions) for offline analysis by mlops/experiments/analyze.py.
- Outcomes (labels) can be attached later via /v1/route/outcome and are
  appended to the same log stream with the same request_id.

Config hot-reload: POST /v1/route/reload re-reads the YAML file.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("model-router")

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path(
    os.getenv("EXPERIMENT_CONFIG", str(REPO_ROOT / "mlops" / "experiments" / "champion_challenger.yaml"))
)
LOG_DIR = Path(os.getenv("ROUTER_LOG_DIR", str(REPO_ROOT / "mlops" / "data" / "router_log")))
UPSTREAM_TIMEOUT = float(os.getenv("ROUTER_UPSTREAM_TIMEOUT", "5.0"))


# ---------------------------------------------------------------------------
# Experiment config
# ---------------------------------------------------------------------------
class Arm(BaseModel):
    name: str
    model_name: str
    model_version: str
    url: str  # e.g. http://localhost:8100/v1/aml/score


class ExperimentConfig(BaseModel):
    experiment_id: str
    champion: Arm
    challenger: Arm
    challenger_traffic_pct: float = Field(ge=0.0, le=100.0, default=10.0)


def load_config(path: Path) -> ExperimentConfig:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return ExperimentConfig.model_validate(raw)


def assign_arm(customer_id: str, experiment_id: str, challenger_pct: float) -> str:
    """Deterministic bucketing: same customer always lands in the same arm."""
    digest = hashlib.sha256(f"{experiment_id}:{customer_id}".encode()).hexdigest()
    bucket = int(digest[:8], 16) % 100
    return "challenger" if bucket < challenger_pct else "champion"


# ---------------------------------------------------------------------------
# Parquet event log (lazy import so router still runs without pyarrow)
# ---------------------------------------------------------------------------
def append_events(events: list[dict[str, Any]]) -> None:
    if not events:
        return
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        partition = LOG_DIR / f"dt={today}"
        partition.mkdir(parents=True, exist_ok=True)
        table = pa.Table.from_pylist(events)
        pq.write_table(table, partition / f"events-{uuid.uuid4().hex[:12]}.parquet", compression="snappy")
    except ImportError:
        fallback = LOG_DIR / "events.jsonl"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        with open(fallback, "a", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event) + "\n")
        logger.warning("pyarrow unavailable; appended %d events to %s", len(events), fallback)


# ---------------------------------------------------------------------------
# Buffered assignment log (P9): previously every request wrote its own
# parquet file synchronously in the hot path — 5-30ms of disk I/O per score
# plus thousands of tiny files. Events now buffer in memory and flush in a
# background thread on a size OR time trigger, with a final flush on shutdown.
# ---------------------------------------------------------------------------
_FLUSH_SIZE = int(os.getenv("ROUTER_LOG_FLUSH_SIZE", "500"))
_FLUSH_INTERVAL = float(os.getenv("ROUTER_LOG_FLUSH_INTERVAL_SECONDS", "5.0"))
_event_buffer: list[dict[str, Any]] = []
_event_lock = threading.Lock()
_flush_now = threading.Event()
_flush_stop = threading.Event()
_flusher_thread: threading.Thread | None = None


def buffer_event(event: dict[str, Any]) -> None:
    """Append an event to the in-memory buffer; never blocks the caller on I/O."""
    with _event_lock:
        _event_buffer.append(event)
        full = len(_event_buffer) >= _FLUSH_SIZE
    if full:
        _flush_now.set()


def flush_events() -> None:
    """Drain the buffer and write one batched parquet file."""
    with _event_lock:
        if not _event_buffer:
            return
        batch = _event_buffer[:]
        _event_buffer.clear()
    try:
        append_events(batch)
    except Exception:  # noqa: BLE001 - never lose events silently
        logger.exception("router log flush failed; requeueing %d events", len(batch))
        with _event_lock:
            _event_buffer[:0] = batch


def _flusher_loop() -> None:
    while not _flush_stop.is_set():
        _flush_now.wait(_FLUSH_INTERVAL)
        _flush_now.clear()
        flush_events()


def start_event_flusher() -> None:
    global _flusher_thread
    if _flusher_thread is None or not _flusher_thread.is_alive():
        _flush_stop.clear()
        _flusher_thread = threading.Thread(target=_flusher_loop, name="router-log-flusher", daemon=True)
        _flusher_thread.start()


def stop_event_flusher() -> None:
    _flush_stop.set()
    _flush_now.set()
    if _flusher_thread is not None:
        _flusher_thread.join(timeout=10)
    flush_events()  # final drain so shutdown never drops buffered events


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class RouteScoreRequest(BaseModel):
    customer_id: str = Field(min_length=1, max_length=128)
    transaction: dict[str, Any]  # forwarded verbatim to the arm's /v1/aml/score


class OutcomeRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=64)
    label: int = Field(ge=0, le=1)  # 1 = confirmed fraud, 0 = legitimate
    source: str = Field(default="investigator", max_length=64)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.config = load_config(CONFIG_PATH)
    app.state.client = httpx.AsyncClient(timeout=httpx.Timeout(UPSTREAM_TIMEOUT))
    start_event_flusher()
    logger.info(
        "Experiment %s loaded: challenger=%s pct=%.1f",
        app.state.config.experiment_id,
        app.state.config.challenger.model_name,
        app.state.config.challenger_traffic_pct,
    )
    yield
    stop_event_flusher()
    await app.state.client.aclose()


app = FastAPI(title="FraudFusion Model Router", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health(request: Request) -> dict[str, Any]:
    cfg: ExperimentConfig = request.app.state.config
    return {
        "status": "healthy",
        "service": "model-router",
        "experiment_id": cfg.experiment_id,
        "champion": cfg.champion.model_dump(),
        "challenger": cfg.challenger.model_dump(),
        "challenger_traffic_pct": cfg.challenger_traffic_pct,
    }


@app.post("/v1/route/reload")
async def reload_config(request: Request) -> dict[str, Any]:
    try:
        request.app.state.config = load_config(CONFIG_PATH)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"config reload failed: {exc}") from exc
    logger.info("Experiment config reloaded from %s", CONFIG_PATH)
    return await health(request)


@app.post("/v1/route/score")
async def route_score(req: RouteScoreRequest, request: Request) -> dict[str, Any]:
    cfg: ExperimentConfig = request.app.state.config
    arm_name = assign_arm(req.customer_id, cfg.experiment_id, cfg.challenger_traffic_pct)
    arm = cfg.champion if arm_name == "champion" else cfg.challenger
    request_id = uuid.uuid4().hex
    start = time.perf_counter()

    error: str | None = None
    score_payload: dict[str, Any] | None = None
    try:
        response = await request.app.state.client.post(arm.url, json=req.transaction)
        response.raise_for_status()
        score_payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.error("Arm %s (%s) scoring failed: %s", arm_name, arm.url, error)
        raise HTTPException(status_code=502, detail=f"upstream {arm_name} scoring failed") from exc
    finally:
        latency_ms = (time.perf_counter() - start) * 1000

    buffer_event({
        "request_id": request_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "experiment_id": cfg.experiment_id,
        "customer_id": req.customer_id,
        "arm": arm_name,
        "model_name": arm.model_name,
        "model_version": arm.model_version,
        "transaction": json.dumps(req.transaction),
        "risk_score": (score_payload or {}).get("risk_score"),
        "risk_level": (score_payload or {}).get("risk_level"),
        "latency_ms": latency_ms,
        "error": error,
        "label": None,
        "label_source": None,
        "event_type": "score",
    })

    return {
        "request_id": request_id,
        "experiment_id": cfg.experiment_id,
        "arm": arm_name,
        "model_name": arm.model_name,
        "model_version": arm.model_version,
        "score": score_payload,
    }


@app.post("/v1/route/outcome")
async def record_outcome(req: OutcomeRequest) -> dict[str, Any]:
    """Label feedback endpoint: investigators attach ground truth to a score."""
    buffer_event({
        "request_id": req.request_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "experiment_id": None,
        "customer_id": None,
        "arm": None,
        "model_name": None,
        "model_version": None,
        "transaction": None,
        "risk_score": None,
        "risk_level": None,
        "latency_ms": None,
        "error": None,
        "label": req.label,
        "label_source": req.source,
        "event_type": "outcome",
    })
    return {"status": "recorded", "request_id": req.request_id, "label": req.label}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8200")))
