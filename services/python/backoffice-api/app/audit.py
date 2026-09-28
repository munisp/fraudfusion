"""Hash-chained audit ledger for backoffice-api.

Every mutation appends an entry to backoffice_audit_ledger whose entry_hash
chains to the previous entry (prev_hash). The chain is independently
verifiable in SQL (verify_backoffice_audit_chain() in
database/20260901_python_services_caveats.sql) and in Python
(verify_chain below). The table is append-only (immutability trigger in the
canonical migration).

Canonical entry text (must match the SQL verifier byte-for-byte):
  prev_hash|event_type|severity|actor_id|resource_type|resource_id|action|
  outcome|<details as jsonb text form>|created_at 'YYYY-MM-DDTHH:MM:SS.ffffffZ'
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from app.db import Database

GENESIS = "0" * 64

_lock = threading.Lock()


def _canonical(details: dict[str, Any], created_at: str, **fields: str) -> str:
    # PostgreSQL jsonb ::text form: keys sorted, ': ' / ', ' separators.
    details_text = json.dumps(details or {}, sort_keys=True)
    return "|".join([
        fields["prev_hash"], fields["event_type"], fields["severity"],
        fields["actor_id"], fields["resource_type"], fields["resource_id"],
        fields["action"], fields["outcome"], details_text, created_at,
    ])


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def append_event(
    db: Database,
    *,
    tenant_id: str,
    event_type: str,
    severity: str = "info",
    actor_id: str | None,
    actor_type: str = "user",
    actor_ip: str | None = None,
    resource_type: str,
    resource_id: str,
    action: str,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one chained entry. Single-writer service: a process-local lock
    serializes chain extension; Postgres is the authority for ordering."""
    with _lock:
        last = db.query_one(
            "SELECT entry_hash FROM backoffice_audit_ledger WHERE tenant_id = :t"
            " ORDER BY id DESC LIMIT 1",
            {"t": tenant_id},
        )
        prev_hash = last["entry_hash"] if last else GENESIS
        created_at = utc_now_iso()
        canonical = _canonical(
            details or {}, created_at,
            prev_hash=prev_hash, event_type=event_type, severity=severity,
            actor_id=actor_id or "", resource_type=resource_type,
            resource_id=resource_id, action=action, outcome=outcome,
        )
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        import json as _json

        db.execute(
            "INSERT INTO backoffice_audit_ledger (tenant_id, event_type, severity, actor_id,"
            " actor_type, actor_ip, resource_type, resource_id, action, outcome, details,"
            " prev_hash, entry_hash, created_at)"
            " VALUES (:t, :et, :sev, :aid, :at, :ip, :rt, :rid, :act, :out, :det, :prev, :hash, :ts)",
            {"t": tenant_id, "et": event_type, "sev": severity, "aid": actor_id,
             "at": actor_type, "ip": actor_ip, "rt": resource_type, "rid": resource_id,
             "act": action, "out": outcome, "det": _json.dumps(details or {}, sort_keys=True),
             "prev": prev_hash, "hash": entry_hash, "ts": created_at},
        )
    return {"prev_hash": prev_hash, "entry_hash": entry_hash, "created_at": created_at}


def verify_chain(db: Database, tenant_id: str = "default") -> dict[str, Any]:
    """Recompute the chain; returns broken-link count and the first offender."""
    rows = db.query(
        "SELECT id, event_type, severity, actor_id, resource_type, resource_id,"
        " action, outcome, details, prev_hash, entry_hash, created_at"
        " FROM backoffice_audit_ledger WHERE tenant_id = :t ORDER BY id",
        {"t": tenant_id},
    )
    prev = GENESIS
    broken = 0
    first_broken = None
    for row in rows:
        details = Database.as_dict(row["details"])
        created_at = str(row["created_at"]).replace(" ", "T")
        if not created_at.endswith("Z"):
            created_at += "Z"
        canonical = _canonical(
            details, created_at,
            prev_hash=row["prev_hash"], event_type=row["event_type"],
            severity=row["severity"], actor_id=row.get("actor_id") or "",
            resource_type=row["resource_type"], resource_id=row["resource_id"],
            action=row["action"], outcome=row["outcome"],
        )
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if row["prev_hash"] != prev or row["entry_hash"] != expected:
            broken += 1
            if first_broken is None:
                first_broken = row["id"]
        prev = row["entry_hash"]
    return {"broken_links": broken, "first_broken_id": first_broken,
            "entries": len(rows), "intact": broken == 0}
