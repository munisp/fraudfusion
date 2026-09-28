"""Hash-chained audit rows for webhook deliveries (backoffice pattern).

Each webhook_deliveries row is chained at CREATION time over its immutable
fields; in-place attempt updates (status/attempts_json/next_attempt_at) never
touch prev_hash/entry_hash, so the chain stays verifiable for the life of
the row.

Canonical entry text:
  prev_hash|delivery_id|event_id|endpoint_id|tenant_id|created_at
    (created_at as 'YYYY-MM-DDTHH:MM:SS.ffffffZ')

Unlike backoffice_audit_ledger (BIGSERIAL id ordering), delivery ids are
random uuids, so verification walks the prev_hash links from GENESIS
instead of relying on physical ordering — deterministic across SQLite and
PostgreSQL.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from typing import Any  # noqa: F401  (kept for public type hints)

from app.db import Database

GENESIS = "0" * 64

_lock = threading.Lock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical(prev_hash: str, delivery_id: str, event_id: str,
              endpoint_id: str, tenant_id: str, created_at: str) -> str:
    return "|".join([prev_hash, delivery_id, event_id, endpoint_id,
                     tenant_id, created_at])


def _chain_tip(db: Database, tenant_id: str) -> str:
    """entry_hash of the row no other row references as prev_hash (the tip)."""
    row = db.query_one(
        "SELECT d.entry_hash FROM webhook_deliveries d"
        " WHERE d.tenant_id = :t AND NOT EXISTS ("
        "   SELECT 1 FROM webhook_deliveries n"
        "   WHERE n.tenant_id = :t AND n.prev_hash = d.entry_hash)"
        " ORDER BY d.created_at DESC",
        {"t": tenant_id},
    )
    return row["entry_hash"] if row else GENESIS


def insert_chained_delivery(db: Database, *, delivery_id: str, event_id: str,
                            endpoint_id: str, tenant_id: str,
                            next_attempt_at: float) -> dict[str, Any]:
    """Append one pending delivery row as the new chain tip. A process-local
    lock serializes tip lookup + insert (single-writer worker)."""
    with _lock:
        prev_hash = _chain_tip(db, tenant_id)
        created_at = utc_now_iso()
        entry_hash = hashlib.sha256(
            canonical(prev_hash, delivery_id, event_id, endpoint_id,
                      tenant_id, created_at).encode("utf-8")
        ).hexdigest()
        db.execute(
            "INSERT INTO webhook_deliveries (id, event_id, endpoint_id, tenant_id,"
            " status, attempt_count, next_attempt_at, attempts_json, prev_hash,"
            " entry_hash, created_at, updated_at)"
            " VALUES (:id, :eid, :epid, :t, 'pending', 0, :next, '[]', :prev, :hash,"
            " :ts, :ts)",
            {"id": delivery_id, "eid": event_id, "epid": endpoint_id, "t": tenant_id,
             "next": next_attempt_at, "prev": prev_hash, "hash": entry_hash,
             "ts": created_at},
        )
    return {"id": delivery_id, "prev_hash": prev_hash, "entry_hash": entry_hash,
            "created_at": created_at}


def verify_chain(db: Database, tenant_id: str = "default") -> dict[str, Any]:
    """Recompute and walk the chain from GENESIS. Returns broken-link count,
    the first offending row id, and any rows unreachable from GENESIS."""
    rows = db.query(
        "SELECT id, event_id, endpoint_id, tenant_id, prev_hash, entry_hash,"
        " created_at FROM webhook_deliveries WHERE tenant_id = :t",
        {"t": tenant_id},
    )
    by_prev: dict[str, list[dict]] = {}
    for row in rows:
        by_prev.setdefault(row["prev_hash"], []).append(row)

    broken = 0
    first_broken = None
    visited: set[str] = set()

    def _created_iso(value) -> str:
        """Normalise driver-specific created_at (SQLite TEXT / PG timestamptz
        datetime) back to the canonical 'YYYY-MM-DDTHH:MM:SS.ffffffZ'."""
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        text = str(value).replace(" ", "T")
        if text.endswith("+00:00"):
            text = text[:-6] + "Z"
        elif not text.endswith("Z"):
            text += "Z"
        return text

    def _check(row: dict) -> None:
        nonlocal broken, first_broken
        created_at = _created_iso(row["created_at"])
        expected = hashlib.sha256(
            canonical(row["prev_hash"], row["id"], row["event_id"],
                      row["endpoint_id"], row["tenant_id"], created_at)
            .encode("utf-8")
        ).hexdigest()
        if row["entry_hash"] != expected:
            broken += 1
            if first_broken is None:
                first_broken = row["id"]

    frontier = by_prev.get(GENESIS, [])
    while frontier:
        row = frontier.pop()
        if row["id"] in visited:
            continue
        visited.add(row["id"])
        _check(row)
        frontier.extend(by_prev.get(row["entry_hash"], []))

    # Rows not reachable from GENESIS (e.g. a relinked/tampered middle) are
    # chain breaks too.
    orphaned = [r["id"] for r in rows if r["id"] not in visited]
    if orphaned and first_broken is None:
        first_broken = orphaned[0]
    broken += len(orphaned)
    return {"broken_links": broken, "first_broken_id": first_broken,
            "entries": len(rows), "intact": broken == 0}
