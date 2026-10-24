"""Hash-chained per-parcel evidence trail.

Every mutating event in the land due-diligence module (parcel registration,
consent confirmation, dispute open/resolve, revocation transitions) appends
an entry to ``parcel_evidence_chain``. Each entry binds:

    entry_hash = sha256(prev_hash | payload_hash | event_type | parcel_ref)

so the ordered chain for a parcel is a tamper-evident export: a court or
counterparty can recompute the chain offline and detect any removed,
reordered, or altered entry. Payloads are persisted hash-only (NDPA-aligned);
the caller keeps the source documents.

Chain genesis per parcel uses prev_hash = "GENESIS".
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "GENESIS"


def _payload_hash(payload: dict[str, Any]) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _entry_hash(prev_hash: str, payload_hash: str, event_type: str, parcel_ref: str) -> str:
    return hashlib.sha256(
        f"{prev_hash}|{payload_hash}|{event_type}|{parcel_ref}".encode("utf-8")
    ).hexdigest()


def append_event(store, parcel_ref: str, event_type: str, payload: dict[str, Any],
                 tenant_id: str = "default") -> dict[str, Any]:
    """Append an event to the parcel's evidence chain. Returns the entry."""
    last = store.query_one(
        "SELECT entry_hash FROM parcel_evidence_chain"
        " WHERE tenant_id = :t AND parcel_ref = :p ORDER BY id DESC LIMIT 1",
        {"t": tenant_id, "p": parcel_ref},
    )
    prev_hash = last["entry_hash"] if last else GENESIS
    ph = _payload_hash(payload)
    eh = _entry_hash(prev_hash, ph, event_type, parcel_ref)
    store.execute(
        "INSERT INTO parcel_evidence_chain"
        " (tenant_id, parcel_ref, event_type, payload_hash, prev_hash, entry_hash)"
        " VALUES (:t, :p, :e, :ph, :prev, :eh)",
        {"t": tenant_id, "p": parcel_ref, "e": event_type, "ph": ph, "prev": prev_hash, "eh": eh},
    )
    return {"parcel_ref": parcel_ref, "event_type": event_type,
            "payload_hash": ph, "prev_hash": prev_hash, "entry_hash": eh}


def get_chain(store, parcel_ref: str, tenant_id: str = "default") -> list[dict[str, Any]]:
    return store.query(
        "SELECT id, parcel_ref, event_type, payload_hash, prev_hash, entry_hash, created_at"
        " FROM parcel_evidence_chain WHERE tenant_id = :t AND parcel_ref = :p ORDER BY id",
        {"t": tenant_id, "p": parcel_ref},
    )


def verify_chain(entries: list[dict[str, Any]], parcel_ref: str) -> bool:
    """Recompute the chain; True iff every link is intact and ordered."""
    prev = GENESIS
    for entry in entries:
        expected = _entry_hash(prev, entry["payload_hash"], entry["event_type"], parcel_ref)
        if entry["prev_hash"] != prev or entry["entry_hash"] != expected:
            return False
        prev = entry["entry_hash"]
    return True
