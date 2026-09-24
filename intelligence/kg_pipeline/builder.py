"""KG builder: canonical source rows -> pseudonymized entities + relations.

Pure functions (no I/O) so the built-in executor and the optional cocoindex
adapter share identical semantics. All entity ids are NDPA-pseudonymized via
pseudonymize.entity_id — raw customer/device/employee ids never appear in
the output.

Entities and relations are keyed dicts so deltas merge deterministically:
  entity key   = entity id
  relation key = (src_id, dst_id, type)
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable

from . import schema
from .pseudonymize import entity_id

Entity = dict[str, Any]   # {id, label, props(json str), first_seen, last_seen}
Relation = dict[str, Any]  # {src_id, dst_id, type, props(json str), ts, count}


def _merge_entity(entities: dict[str, Entity], eid: str, label: str,
                  ts: str | None, props: dict[str, Any]) -> None:
    e = entities.get(eid)
    if e is None:
        entities[eid] = Entity(id=eid, label=label, props=json.dumps(props, sort_keys=True),
                               first_seen=ts, last_seen=ts)
        return
    if ts:
        if e["first_seen"] is None or ts < e["first_seen"]:
            e["first_seen"] = ts
        if e["last_seen"] is None or ts > e["last_seen"]:
            e["last_seen"] = ts
    if props:
        merged = json.loads(e["props"])
        merged.update({k: v for k, v in props.items() if v is not None})
        e["props"] = json.dumps(merged, sort_keys=True)


def _merge_relation(relations: dict[tuple, Relation], src: str, dst: str,
                    rtype: str, ts: str | None, props: dict[str, Any]) -> None:
    key = (src, dst, rtype)
    r = relations.get(key)
    if r is None:
        relations[key] = Relation(src_id=src, dst_id=dst, type=rtype,
                                  props=json.dumps(props, sort_keys=True),
                                  ts=ts, count=1)
        return
    r["count"] += 1
    if ts and (r["ts"] is None or ts > r["ts"]):
        r["ts"] = ts
    if props:
        merged = json.loads(r["props"])
        merged.update({k: v for k, v in props.items() if v is not None})
        r["props"] = json.dumps(merged, sort_keys=True)


# --- per-dataset builders ----------------------------------------------------

def build_transactions(rows: Iterable[dict[str, Any]], salt: str | None,
                       entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    for r in rows:
        ts = r.get("ts")
        txn_raw = r.get("txn_id")
        sender, receiver = r.get("sender_id"), r.get("receiver_id")
        if sender:
            s = entity_id(schema.CUSTOMER, sender, salt)
            _merge_entity(entities, s, schema.CUSTOMER, ts, {})
        if receiver:
            # Receivers that look like merchants (merchant_id column present or
            # POS/channel hints) are still modeled as Customer unless an
            # explicit merchant_id field exists — honest, no guessing.
            d = entity_id(schema.CUSTOMER, receiver, salt)
            _merge_entity(entities, d, schema.CUSTOMER, ts, {})
        if sender and receiver:
            s = entity_id(schema.CUSTOMER, sender, salt)
            d = entity_id(schema.CUSTOMER, receiver, salt)
            _merge_relation(relations, s, d, schema.TRANSACTED_WITH, ts,
                            {"channel": r.get("channel")})
        if txn_raw:
            t = entity_id(schema.TRANSACTION, txn_raw, salt)
            _merge_entity(entities, t, schema.TRANSACTION, ts, {
                "amount": r.get("amount"), "channel": r.get("channel")})
            if sender:
                _merge_relation(relations, entity_id(schema.CUSTOMER, sender, salt), t,
                                schema.TRANSACTED_WITH, ts, {"role": "sender"})
            if receiver:
                _merge_relation(relations, t, entity_id(schema.CUSTOMER, receiver, salt),
                                schema.TRANSACTED_WITH, ts, {"role": "receiver"})
        if r.get("merchant_id"):
            m = entity_id(schema.MERCHANT, r["merchant_id"], salt)
            _merge_entity(entities, m, schema.MERCHANT, ts, {})
            if sender:
                _merge_relation(relations, entity_id(schema.CUSTOMER, sender, salt), m,
                                schema.TRANSACTED_WITH, ts, {"channel": r.get("channel")})
        if r.get("device_id") and sender:
            dev = entity_id(schema.DEVICE, r["device_id"], salt)
            _merge_entity(entities, dev, schema.DEVICE, ts, {})
            _merge_relation(relations, entity_id(schema.CUSTOMER, sender, salt), dev,
                            schema.OWNS, ts, {})


def build_accounts(rows: Iterable[dict[str, Any]], salt: str | None,
                   entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    for r in rows:
        ts = r.get("ts")
        cust_raw = r.get("customer_id")
        if not cust_raw:
            continue
        c = entity_id(schema.CUSTOMER, cust_raw, salt)
        _merge_entity(entities, c, schema.CUSTOMER, ts,
                      {"bank": r.get("bank"), "state": r.get("state"),
                       "city": r.get("city"), "is_agent": r.get("is_agent")})
        if r.get("account_id"):
            a = entity_id(schema.ACCOUNT, r["account_id"], salt)
            _merge_entity(entities, a, schema.ACCOUNT, ts, {"bank": r.get("bank")})
            _merge_relation(relations, c, a, schema.OWNS, ts, {})
        addr_parts = [p for p in (r.get("address"), r.get("city"), r.get("state")) if p]
        if addr_parts:
            addr = entity_id(schema.ADDRESS, "|".join(str(p) for p in addr_parts), salt)
            _merge_entity(entities, addr, schema.ADDRESS, ts,
                          {"state": r.get("state"), "city": r.get("city")})
            _merge_relation(relations, c, addr, schema.LOCATED_IN, ts, {})
        if r.get("is_agent"):
            ag = entity_id(schema.AGENT, cust_raw, salt)
            _merge_entity(entities, ag, schema.AGENT, ts, {})


def build_alerts(rows: Iterable[dict[str, Any]], salt: str | None,
                 entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    for r in rows:
        ts = r.get("ts")
        alert_raw = r.get("alert_id") or f"{r.get('alert_type')}:{r.get('customer_id')}:{ts}"
        a = entity_id(schema.ALERT, alert_raw, salt)
        _merge_entity(entities, a, schema.ALERT, ts,
                      {"alert_type": r.get("alert_type"), "risk_level": r.get("risk_level")})
        if r.get("customer_id"):
            c = entity_id(schema.CUSTOMER, r["customer_id"], salt)
            _merge_entity(entities, c, schema.CUSTOMER, ts, {})
            _merge_relation(relations, c, a, schema.FLAGGED_BY, ts,
                            {"alert_type": r.get("alert_type")})
        if r.get("txn_id"):
            t = entity_id(schema.TRANSACTION, r["txn_id"], salt)
            _merge_entity(entities, t, schema.TRANSACTION, ts, {})
            _merge_relation(relations, t, a, schema.FLAGGED_BY, ts,
                            {"alert_type": r.get("alert_type")})


def build_sars(rows: Iterable[dict[str, Any]], salt: str | None,
               entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    for r in rows:
        ts = r.get("ts")
        sar_raw = r.get("sar_id")
        if not sar_raw:
            continue
        s = entity_id(schema.SAR, sar_raw, salt)
        _merge_entity(entities, s, schema.SAR, ts,
                      {"activity_type": r.get("activity_type"), "status": r.get("status")})
        if r.get("customer_id"):
            c = entity_id(schema.CUSTOMER, r["customer_id"], salt)
            _merge_entity(entities, c, schema.CUSTOMER, ts, {})
            _merge_relation(relations, s, c, schema.FILED_AGAINST, ts,
                            {"activity_type": r.get("activity_type"),
                             "status": r.get("status")})


def build_cases(rows: Iterable[dict[str, Any]], salt: str | None,
                entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    for r in rows:
        ts = r.get("ts")
        case_raw = r.get("case_id")
        if not case_raw:
            continue
        k = entity_id(schema.CASE, case_raw, salt)
        _merge_entity(entities, k, schema.CASE, ts, {"status": r.get("status")})
        if r.get("customer_id"):
            c = entity_id(schema.CUSTOMER, r["customer_id"], salt)
            _merge_entity(entities, c, schema.CUSTOMER, ts, {})
            _merge_relation(relations, k, c, schema.FILED_AGAINST, ts,
                            {"status": r.get("status")})


def build_devices(rows: Iterable[dict[str, Any]], salt: str | None,
                  entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    device_users: dict[str, set[str]] = defaultdict(set)
    device_ts: dict[str, str | None] = {}
    for r in rows:
        ts = r.get("ts")
        dev_raw, cust_raw = r.get("device_id"), r.get("customer_id")
        if not dev_raw:
            continue
        d = entity_id(schema.DEVICE, dev_raw, salt)
        _merge_entity(entities, d, schema.DEVICE, ts, {})
        device_ts[str(dev_raw)] = ts
        if cust_raw:
            c = entity_id(schema.CUSTOMER, cust_raw, salt)
            _merge_entity(entities, c, schema.CUSTOMER, ts, {})
            _merge_relation(relations, c, d, schema.OWNS, ts,
                            {"ip_address": r.get("ip_address")})
            device_users[str(dev_raw)].add(str(cust_raw))
    # SHARES_DEVICE: customers touching the same physical device.
    for dev_raw, users in device_users.items():
        users_sorted = sorted(users)
        ts = device_ts.get(dev_raw)
        dev = entity_id(schema.DEVICE, dev_raw, salt)
        for i, u1 in enumerate(users_sorted):
            for u2 in users_sorted[i + 1:]:
                c1, c2 = entity_id(schema.CUSTOMER, u1, salt), entity_id(schema.CUSTOMER, u2, salt)
                _merge_relation(relations, c1, c2, schema.SHARES_DEVICE, ts, {"device": dev})
                _merge_relation(relations, c2, c1, schema.SHARES_DEVICE, ts, {"device": dev})


def build_insider_events(rows: Iterable[dict[str, Any]], salt: str | None,
                         entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    for r in rows:
        ts = r.get("ts")
        emp_raw = r.get("employee_id")
        if not emp_raw:
            continue
        a = entity_id(schema.AGENT, emp_raw, salt)
        _merge_entity(entities, a, schema.AGENT, ts, {"event_type": r.get("event_type")})
        ev_raw = r.get("event_id") or f"{r.get('event_type')}:{emp_raw}:{ts}"
        al = entity_id(schema.ALERT, f"insider:{ev_raw}", salt)
        _merge_entity(entities, al, schema.ALERT, ts,
                      {"alert_type": f"insider:{r.get('event_type')}"})
        _merge_relation(relations, a, al, schema.FLAGGED_BY, ts,
                        {"event_type": r.get("event_type")})
        if r.get("peer_id"):
            p = entity_id(schema.AGENT, r["peer_id"], salt)
            _merge_entity(entities, p, schema.AGENT, ts, {})
            _merge_relation(relations, a, p, schema.WORKS_WITH, ts, {})
            _merge_relation(relations, p, a, schema.WORKS_WITH, ts, {})


def build_merchants(rows: Iterable[dict[str, Any]], salt: str | None,
                    entities: dict[str, Entity], relations: dict[tuple, Relation]) -> None:
    for r in rows:
        m_raw = r.get("merchant_id")
        if not m_raw:
            continue
        m = entity_id(schema.MERCHANT, m_raw, salt)
        _merge_entity(entities, m, schema.MERCHANT, r.get("ts"), {"name": r.get("name")})


BUILDERS = {
    "transactions": build_transactions,
    "accounts": build_accounts,
    "kyc": build_accounts,
    "alerts": build_alerts,
    "sars": build_sars,
    "cases": build_cases,
    "devices": build_devices,
    "insider_events": build_insider_events,
    "merchants": build_merchants,
}


def build(datasets: dict[str, list[dict[str, Any]]],
          salt: str | None = None) -> tuple[list[Entity], list[Relation]]:
    """Build a KG subgraph from canonical dataset rows."""
    entities: dict[str, Entity] = {}
    relations: dict[tuple, Relation] = {}
    for name, rows in datasets.items():
        fn = BUILDERS.get(name)
        if fn is None:
            continue
        fn(rows, salt, entities, relations)
    for e in entities.values():
        e["schema_version"] = schema.KG_SCHEMA_VERSION
    for r in relations.values():
        r["schema_version"] = schema.KG_SCHEMA_VERSION
    return list(entities.values()), list(relations.values())
