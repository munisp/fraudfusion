"""Source readers: lakehouse parquet (primary) and Postgres (optional).

Each dataset reader returns a list of dicts with *canonical* field names so
the builder never has to know which physical source a row came from.
Canonical fields per dataset:

  transactions:   txn_id, sender_id, receiver_id, amount, ts, channel,
                  device_id, merchant_id
  accounts/kyc:   customer_id, account_id, bank, state, city, address, ts,
                  is_agent
  alerts:         alert_id, customer_id, txn_id, alert_type, risk_level, ts
  sars:           sar_id, customer_id, activity_type, status, ts
  cases:          case_id, customer_id, status, ts
  devices:        device_id, customer_id, ip_address, ts
  insider_events: event_id, employee_id, event_type, peer_id, ts
  merchants:      merchant_id, name, ts

Column-name variants are tolerated (sender_id|customer_id|user_id|...).
Missing datasets yield zero rows with a logged note — the KG is best-effort
over whichever sources exist, never fabricated.

Postgres reading is OPTIONAL: it requires psycopg and a DSN
(KG_POSTGRES_DSN / DATABASE_URL). When psycopg is not installed the reader
raises a clear error instead of pretending to have read zero rows.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger("kg_pipeline.sources")

# canonical field -> accepted source column names (first hit wins)
COLUMN_VARIANTS: dict[str, dict[str, tuple[str, ...]]] = {
    "transactions": {
        "txn_id": ("txn_id", "transaction_id", "id"),
        "sender_id": ("sender_id", "sender", "from_account", "customer_id", "user_id"),
        "receiver_id": ("receiver_id", "receiver", "to_account", "counterparty_id", "beneficiary_id"),
        "amount": ("amount_ngn", "amount", "value"),
        "ts": ("ts", "timestamp", "created_at", "txn_ts", "occurred_at"),
        "channel": ("channel", "txn_channel"),
        "device_id": ("device_id", "device_fingerprint"),
        "merchant_id": ("merchant_id", "merchant", "terminal_id"),
    },
    "accounts": {
        "customer_id": ("customer_id", "user_id", "id"),
        "account_id": ("account_id", "account_number", "nuban"),
        "bank": ("bank", "bank_name"),
        "state": ("state",),
        "city": ("city",),
        "address": ("address", "street_address"),
        "ts": ("ts", "created_at", "updated_at"),
        "is_agent": ("is_agent",),
    },
    "kyc": {
        "customer_id": ("customer_id", "user_id", "id"),
        "account_id": ("account_id", "account_number"),
        "state": ("state",),
        "city": ("city",),
        "address": ("address", "street_address"),
        "ts": ("ts", "created_at", "updated_at", "verified_at"),
    },
    "alerts": {
        "alert_id": ("alert_id", "id"),
        "customer_id": ("customer_id", "user_id"),
        "txn_id": ("txn_id", "transaction_id"),
        "alert_type": ("alert_type", "type", "rule"),
        "risk_level": ("risk_level", "severity"),
        "ts": ("ts", "created_at", "detected_at"),
    },
    "sars": {
        "sar_id": ("sar_id", "id"),
        "customer_id": ("customer_id", "user_id"),
        "activity_type": ("activity_type", "sar_type"),
        "status": ("status",),
        "ts": ("ts", "filing_date", "created_at"),
    },
    "cases": {
        "case_id": ("case_id", "id"),
        "customer_id": ("customer_id", "user_id"),
        "status": ("status",),
        "ts": ("ts", "created_at", "opened_at"),
    },
    "devices": {
        "device_id": ("device_id", "fingerprint"),
        "customer_id": ("customer_id", "user_id"),
        "ip_address": ("ip_address", "ip"),
        "ts": ("ts", "last_seen_at", "first_seen_at", "created_at"),
    },
    "insider_events": {
        "event_id": ("event_id", "id"),
        "employee_id": ("employee_id", "agent_id", "user_id"),
        "event_type": ("event_type", "type"),
        "peer_id": ("peer_id", "peer_employee_id", "collaborator_id"),
        "ts": ("ts", "created_at"),
    },
    "merchants": {
        "merchant_id": ("merchant_id", "id"),
        "name": ("name", "merchant_name"),
        "ts": ("ts", "created_at"),
    },
}

# Postgres table -> dataset (used by read_postgres).
POSTGRES_TABLES = {
    "sars": "aml_sars",
    "devices": "device_fingerprints",
    "insider_events": "insider_fraud_events",
    "alerts": "ato_alerts",
}


def _norm_ts(value: Any) -> str | None:
    if value is None:
        return None
    try:
        import pandas as pd
        if pd.isna(value):
            return None
    except Exception:  # noqa: BLE001
        pass
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _canonicalize(dataset: str, raw: dict[str, Any]) -> dict[str, Any]:
    variants = COLUMN_VARIANTS[dataset]
    row: dict[str, Any] = {}
    for field, candidates in variants.items():
        for col in candidates:
            if col in raw and raw[col] is not None:
                val = raw[col]
                try:
                    import pandas as pd
                    if pd.isna(val):
                        continue
                except (TypeError, ValueError):
                    pass
                row[field] = val
                break
    row["ts"] = _norm_ts(row.get("ts"))
    return row


def _read_parquet_files(files: list[Path]) -> list[dict[str, Any]]:
    import pandas as pd
    rows: list[dict[str, Any]] = []
    for f in files:
        try:
            df = pd.read_parquet(f)
        except Exception as e:  # noqa: BLE001
            log.warning("skipping unreadable parquet %s: %s", f, e)
            continue
        rows.extend(df.to_dict(orient="records"))
    return rows


def dataset_files(lakehouse_dir: Path, name: str) -> list[Path]:
    """Locate parquet files for a dataset: flat file or hive-partitioned dir."""
    files: list[Path] = []
    flat = lakehouse_dir / f"{name}.parquet"
    if flat.exists():
        files.append(flat)
    d = lakehouse_dir / name
    if d.is_dir():
        files.extend(sorted(d.rglob("*.parquet")))
    return files


def read_dataset(lakehouse_dir: str | Path, name: str) -> list[dict[str, Any]]:
    """Read + canonicalize one dataset from the lakehouse. Missing -> []."""
    base = Path(lakehouse_dir)
    files = dataset_files(base, name)
    if not files:
        log.info("dataset %r not found under %s; contributing 0 rows", name, base)
        return []
    raw = _read_parquet_files(files)
    return [_canonicalize(name, r) for r in raw]


def read_postgres(dsn: str | None = None,
                  datasets: tuple[str, ...] | None = None,
                  since: dict[str, str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """Read datasets from Postgres tables. Requires psycopg; honest error otherwise."""
    try:
        import psycopg  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "Postgres source requested but psycopg is not installed. "
            "`pip install psycopg[binary]` or use parquet lakehouse sources."
        ) from e
    dsn = dsn or os.environ.get("KG_POSTGRES_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("Postgres source requested but no DSN: set "
                           "KG_POSTGRES_DSN or DATABASE_URL.")
    out: dict[str, list[dict[str, Any]]] = {}
    wanted = datasets or tuple(POSTGRES_TABLES)
    with psycopg.connect(dsn) as conn:
        for name in wanted:
            table = POSTGRES_TABLES.get(name)
            if not table:
                continue
            where = ""
            params: tuple = ()
            mark = (since or {}).get(name)
            if mark:
                where = "WHERE created_at > %s"
                params = (mark,)
            try:
                cur = conn.execute(f"SELECT * FROM {table} {where}", params)  # noqa: S608
                cols = [c.name for c in cur.description]
                out[name] = [_canonicalize(name, dict(zip(cols, r))) for r in cur.fetchall()]
            except Exception as e:  # noqa: BLE001
                log.warning("postgres read of %s failed: %s", table, e)
                out[name] = []
    return out
