"""Delivery worker: HMAC-signed webhook POSTs with retry + dead-letter.

Runs as an in-process asyncio background task (started from the app
lifespan). Each pass delivers every due pending delivery:

  * signs the stored event envelope bytes per the shared contract
    (X-FraudFusion-Signature: t=<unix>,v1=<hex hmac-sha256> over
    "<t>.<body>", key = sha256(endpoint secret) hex — see app/signing.py);
  * POSTs to the endpoint URL (httpx, WEBHOOK_DELIVERY_TIMEOUT seconds);
  * 2xx -> success; anything else -> retry with exponential backoff
    1s -> 5s -> 25s -> 2m -> 10m (BACKOFF_SCHEDULE), max 5 attempts;
  * after the 5th failed attempt the delivery is dead-lettered and the
    endpoint's consecutive_failures counter rises; at
    WEBHOOK_BREAKER_THRESHOLD consecutive dead-lettered deliveries the
    circuit breaker opens (endpoint status -> 'disabled', skipped by
    fan-out and by the worker).

Attempt history is appended to webhook_deliveries.attempts_json; the row's
hash-chain fields (prev_hash/entry_hash) are written once at creation and
never mutated (see app/chain.py).

Honest limitation: this is a single-process, poll-based worker. There is no
Kafka fan-in / distributed queue yet — scale-out would require leader
election or row-level SKIP LOCKED claiming.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

import httpx

from app import chain, signing
from app.db import Database

logger = logging.getLogger("webhook-service.worker")

# Delay applied after attempt N (1-based) fails, before attempt N+1.
BACKOFF_SCHEDULE: list[float] = [1.0, 5.0, 25.0, 120.0, 600.0]
MAX_ATTEMPTS = len(BACKOFF_SCHEDULE)  # 5

DELIVERY_TIMEOUT = float(os.getenv("WEBHOOK_DELIVERY_TIMEOUT_SECONDS", "5"))
POLL_INTERVAL = float(os.getenv("WEBHOOK_WORKER_POLL_SECONDS", "1"))
BREAKER_THRESHOLD = int(os.getenv("WEBHOOK_BREAKER_THRESHOLD", "10"))


def backoff_for_attempt(attempt: int) -> float:
    """Seconds to wait after failed attempt `attempt` (1-based)."""
    idx = min(max(attempt, 1), len(BACKOFF_SCHEDULE)) - 1
    return BACKOFF_SCHEDULE[idx]


def _record_attempt(db: Database, delivery: dict, attempt: dict[str, Any],
                    *, success: bool, now: float) -> str:
    """Fold one attempt into the delivery row; returns the new status."""
    history = json.loads(delivery["attempts_json"] or "[]")
    history.append(attempt)
    attempts = delivery["attempt_count"] + 1
    now_iso = chain.utc_now_iso()
    if success:
        db.execute(
            "UPDATE webhook_deliveries SET status = 'success', attempt_count = :n,"
            " attempts_json = :h, last_status_code = :sc, last_error = NULL,"
            " updated_at = :t, completed_at = :t WHERE id = :id",
            {"n": attempts, "h": json.dumps(history), "sc": attempt.get("status_code"),
             "t": now_iso, "id": delivery["id"]},
        )
        return "success"
    if attempts >= MAX_ATTEMPTS:
        db.execute(
            "UPDATE webhook_deliveries SET status = 'dead_letter', attempt_count = :n,"
            " attempts_json = :h, last_status_code = :sc, last_error = :err,"
            " updated_at = :t, completed_at = :t WHERE id = :id",
            {"n": attempts, "h": json.dumps(history), "sc": attempt.get("status_code"),
             "err": attempt.get("error"), "t": now_iso, "id": delivery["id"]},
        )
        return "dead_letter"
    db.execute(
        "UPDATE webhook_deliveries SET status = 'pending', attempt_count = :n,"
        " attempts_json = :h, last_status_code = :sc, last_error = :err,"
        " next_attempt_at = :next, updated_at = :t WHERE id = :id",
        {"n": attempts, "h": json.dumps(history), "sc": attempt.get("status_code"),
         "err": attempt.get("error"), "next": now + backoff_for_attempt(attempts),
         "t": now_iso, "id": delivery["id"]},
    )
    return "pending"


def _bump_endpoint_failure(db: Database, endpoint_id: str) -> None:
    """Circuit breaker: disable the endpoint after BREAKER_THRESHOLD
    consecutive dead-lettered deliveries."""
    db.execute(
        "UPDATE webhook_endpoints SET consecutive_failures = consecutive_failures + 1,"
        " updated_at = :t WHERE id = :id",
        {"t": chain.utc_now_iso(), "id": endpoint_id},
    )
    if BREAKER_THRESHOLD > 0:
        db.execute(
            "UPDATE webhook_endpoints SET status = 'disabled', updated_at = :t"
            " WHERE id = :id AND consecutive_failures >= :th AND status = 'active'",
            {"t": chain.utc_now_iso(), "id": endpoint_id, "th": BREAKER_THRESHOLD},
        )


async def deliver_attempt(db: Database, client: httpx.AsyncClient,
                          delivery: dict, *, now: float | None = None) -> str:
    """Perform one delivery attempt; returns the resulting status."""
    now = time.time() if now is None else now
    endpoint = db.query_one(
        "SELECT * FROM webhook_endpoints WHERE id = :id", {"id": delivery["endpoint_id"]})
    event = db.query_one(
        "SELECT * FROM webhook_events WHERE id = :id", {"id": delivery["event_id"]})
    attempt_no = delivery["attempt_count"] + 1
    if endpoint is None or endpoint["status"] != "active" or event is None:
        error = "endpoint_inactive" if event is not None else "event_missing"
        _record_attempt(
            db, delivery,
            {"attempt": attempt_no, "at": chain.utc_now_iso(),
             "status_code": None, "error": error, "duration_ms": 0},
            success=False, now=now)
        # Do not count infrastructure gaps against the receiver circuit.
        db.execute(
            "UPDATE webhook_deliveries SET status = 'dead_letter' WHERE id = :id"
            " AND status = 'pending'",
            {"id": delivery["id"]},
        )
        return "dead_letter"

    body = event["payload"].encode("utf-8")
    key = endpoint["secret_hash"].encode("utf-8")  # sha256(secret) hex
    header = signing.build_signature_header(key, int(now), body)
    started = time.monotonic()
    status_code: int | None = None
    error: str | None = None
    try:
        resp = await client.post(
            endpoint["url"], content=body,
            headers={"Content-Type": "application/json",
                     "X-FraudFusion-Signature": header},
            timeout=DELIVERY_TIMEOUT,
        )
        status_code = resp.status_code
        if not (200 <= resp.status_code < 300):
            error = f"http_{resp.status_code}"
    except httpx.HTTPError as exc:
        error = f"{exc.__class__.__name__}"
    duration_ms = int((time.monotonic() - started) * 1000)

    success = error is None
    new_status = _record_attempt(
        db, delivery,
        {"attempt": attempt_no, "at": chain.utc_now_iso(),
         "status_code": status_code, "error": error, "duration_ms": duration_ms},
        success=success, now=now)
    if new_status == "success":
        db.execute(
            "UPDATE webhook_endpoints SET consecutive_failures = 0, updated_at = :t"
            " WHERE id = :id",
            {"t": chain.utc_now_iso(), "id": endpoint["id"]},
        )
    elif new_status == "dead_letter":
        _bump_endpoint_failure(db, endpoint["id"])
        logger.warning("delivery %s dead-lettered to endpoint %s after %d attempts",
                       delivery["id"], endpoint["id"], attempt_no)
    return new_status


async def process_due_deliveries(db: Database, client: httpx.AsyncClient,
                                 *, now: float | None = None,
                                 limit: int = 100) -> int:
    """One worker pass over due pending deliveries. Returns rows processed."""
    now = time.time() if now is None else now
    rows = db.query(
        "SELECT * FROM webhook_deliveries WHERE status = 'pending'"
        " AND next_attempt_at <= :now ORDER BY next_attempt_at, rowid"
        " LIMIT :n" if not db._is_pg else
        "SELECT * FROM webhook_deliveries WHERE status = 'pending'"
        " AND next_attempt_at <= :now ORDER BY next_attempt_at, ctid"
        " LIMIT :n",
        {"now": now, "n": limit},
    )
    for delivery in rows:
        # Re-read inside the loop: an earlier attempt in this pass may have
        # changed nothing for this row, but the row could have been deleted
        # concurrently in the single-process model only by tests.
        await deliver_attempt(db, client, delivery, now=now)
    return len(rows)


async def worker_loop(db: Database, client: httpx.AsyncClient,
                      stop: asyncio.Event, *,
                      poll_interval: float = POLL_INTERVAL) -> None:
    """Poll-based delivery loop until `stop` is set."""
    while not stop.is_set():
        try:
            await process_due_deliveries(db, client)
        except Exception:  # pragma: no cover - defensive: never kill the loop
            logger.exception("delivery worker pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=poll_interval)
        except asyncio.TimeoutError:
            pass
