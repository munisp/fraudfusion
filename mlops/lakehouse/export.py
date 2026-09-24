"""Production-DB -> parquet lakehouse export.

Extracts scored transactions from Postgres (env DATABASE_URL) into a
partitioned parquet lakehouse matching the ml lane's training contract:

    $LAKEHOUSE_DIR/transactions/dt=YYYY-MM-DD/part-<n>.parquet   (snappy)

Schema (documented in mlops/lakehouse/README.md) — columns consumed by
ml/train/continuous.py are the raw feature columns:
    NUMERIC_FEATURES (16 doubles) + CATEGORICAL_FEATURES (5 strings) + is_fraud
plus serving/lineage columns (transaction_id, customer_id, ts, amount,
currency, country_code, transaction_type, risk_score, label_source).

NDPA / data-protection controls:
    * Every partition carries processing metadata columns
      (processing_purpose, lawful_basis, pii_redacted) so downstream
      consumers can enforce purpose limitation.
    * Direct customer identifiers (customer_id) are pseudonymized by
      default: salted SHA-256 (salt from LAKEHOUSE_PII_SALT). Raw
      identifiers are written only with the explicit --include-pii opt-in,
      which must be justified (e.g. fraud investigation lawful basis).

Modes:
    default      read rows for a date range from Postgres via EXPORT_QUERY
    --synthetic  generate a realistic demo dataset so the loop is
                 demonstrable end-to-end without a database

Usage:
    python mlops/lakehouse/export.py --start 2026-01-01 --end 2026-01-07
    python mlops/lakehouse/export.py --synthetic --days 14 --rows-per-day 500
    python mlops/lakehouse/export.py --start ... --end ... --include-pii \
        --purpose fraud_investigation --lawful-basis legal_obligation
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("lakehouse-export")

LAKEHOUSE_DIR = Path(os.getenv("LAKEHOUSE_DIR", "mlops/data/lakehouse"))
DATASET = "transactions"  # $LAKEHOUSE_DIR/transactions/dt=... (ml lane contract)

# NDPA metadata defaults (overridable via CLI flags / env).
DEFAULT_PURPOSE = os.getenv("EXPORT_PURPOSE", "fraud_detection_model_training")
DEFAULT_LAWFUL_BASIS = os.getenv("EXPORT_LAWFUL_BASIS", "legitimate_interest")
PII_COLUMNS = ("customer_id",)  # direct identifiers pseudonymized by default


def pseudonymize(value: str, salt: str) -> str:
    """Deterministic salted SHA-256 pseudonym for a direct identifier."""
    return "pii_" + hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:32]


def apply_privacy_controls(rows: list[dict], *, include_pii: bool, salt: str,
                           purpose: str, lawful_basis: str) -> list[dict]:
    """Attach purpose/lawful-basis metadata to every row and pseudonymize
    direct customer identifiers unless --include-pii was passed."""
    out = []
    for row in rows:
        record = dict(row)
        if not include_pii:
            for col in PII_COLUMNS:
                if record.get(col):
                    record[col] = pseudonymize(str(record[col]), salt)
        record["processing_purpose"] = purpose
        record["lawful_basis"] = lawful_basis
        record["pii_redacted"] = not include_pii
        out.append(record)
    return out

# ml lane contract (mirrors ml/data/synthetic_nigeria.py — do not import).
NUMERIC_FEATURES = [
    "log_amount", "hour", "dow", "is_month_end", "is_market_day",
    "amount_vs_sender_avg", "sender_txns_24h", "sender_unique_receivers_72h",
    "receiver_fanin_72h", "mins_since_last_txn", "device_emulator",
    "sim_swap_7d", "new_device", "cross_state", "cross_bank", "is_night",
]
CATEGORICAL_FEATURES = ["channel", "sender_bank", "receiver_bank", "sender_state", "device_os"]

CHANNELS = ["agent", "mobile_app", "nip", "pos", "ussd", "web"]
BANKS = ["Access Bank", "First Bank", "GTBank", "Kuda", "Moniepoint", "OPay", "PalmPay", "Stanbic IBTC", "UBA", "Zenith Bank"]
STATES = ["Lagos", "Abuja", "Kano", "Rivers", "Oyo", "Kaduna", "Enugu", "Delta"]
DEVICE_OS = ["android", "ios", "web_browser", "feature_phone", "pos_terminal"]

DEFAULT_QUERY = os.getenv(
    "EXPORT_QUERY",
    """
    SELECT transaction_id, customer_id, created_at AS ts,
           amount, currency, country_code, transaction_type,
           log_amount, hour, dow, is_month_end, is_market_day,
           amount_vs_sender_avg, sender_txns_24h, sender_unique_receivers_72h,
           receiver_fanin_72h, mins_since_last_txn, device_emulator,
           sim_swap_7d, new_device, cross_state, cross_bank, is_night,
           channel, sender_bank, receiver_bank, sender_state, device_os,
           risk_score, is_fraud, label_source
    FROM aml_scored_transactions
    WHERE created_at::date BETWEEN %(start)s AND %(end)s
    ORDER BY created_at
    """,
)


def write_partition(rows: list[dict], dt: str, lakehouse_dir: Path) -> Path:
    import pyarrow as pa
    import pyarrow.parquet as pq

    partition = lakehouse_dir / DATASET / f"dt={dt}"
    partition.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows)
    path = partition / f"part-{uuid.uuid4().hex[:12]}.parquet"
    pq.write_table(table, path, compression="snappy")
    logger.info("wrote %d rows -> %s", len(rows), path)
    return path


def export_from_postgres(start: str, end: str, lakehouse_dir: Path, **privacy) -> int:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL not set; use --synthetic for demo mode")
    import psycopg2
    import psycopg2.extras

    total = 0
    with psycopg2.connect(database_url) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(DEFAULT_QUERY, {"start": start, "end": end})
        by_day: dict[str, list[dict]] = {}
        for row in cur:
            record = dict(row)
            ts = record.get("ts")
            dt = (ts.date() if hasattr(ts, "date") else ts).isoformat() if ts else start
            by_day.setdefault(dt, []).append(record)
        for dt, rows in by_day.items():
            write_partition(apply_privacy_controls(rows, **privacy), dt, lakehouse_dir)
            total += len(rows)
    return total


def synthesize(days: int, rows_per_day: int, lakehouse_dir: Path, seed: int = 42,
               label_fraction: float = 1.0, **privacy) -> int:
    """Deterministic synthetic partitions in the ml lane schema; ~5% fraud
    with separable signal. label_fraction < 1.0 simulates label lag (NULL
    is_fraud); ml/train/continuous.py requires fully labeled rows, so the
    default is 1.0 to keep the loop demonstrable end-to-end."""
    rng = np.random.default_rng(seed)
    today = datetime.now(timezone.utc).date()
    total = 0
    for offset in reversed(range(days)):
        day = today - timedelta(days=offset)
        n = rows_per_day
        fraud = rng.random(n) < 0.05
        log_amount = np.where(fraud, rng.normal(13.5, 1.0, n), rng.normal(10.5, 1.2, n))
        sender_txns_24h = np.where(fraud, rng.integers(5, 25, n), rng.integers(0, 4, n))
        amount_vs_avg = np.where(fraud, rng.uniform(4, 15, n), rng.uniform(0.5, 3, n))
        new_device = (rng.random(n) < np.where(fraud, 0.4, 0.05)).astype(float)
        sim_swap = (rng.random(n) < np.where(fraud, 0.25, 0.01)).astype(float)
        rows = []
        for i in range(n):
            ts = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc) + timedelta(
                seconds=int(rng.integers(0, 86400))
            )
            sender_bank = str(rng.choice(BANKS))
            receiver_bank = str(rng.choice(BANKS))
            sender_state = str(rng.choice(STATES))
            # Synthetic "production score" correlated with fraud + noise.
            risk = float(np.clip(0.15 + 0.6 * fraud[i] + rng.normal(0, 0.1), 0.001, 0.999))
            rows.append({
                "transaction_id": uuid.uuid4().hex,
                "customer_id": f"cust-{int(rng.integers(0, 2000)):05d}",
                "ts": ts,
                "amount": float(np.expm1(log_amount[i])),
                "currency": "NGN",
                "country_code": "NG",
                "transaction_type": str(rng.choice(["transfer", "card", "cash", "crypto"])),
                # --- ml lane numeric features ---
                "log_amount": float(log_amount[i]),
                "hour": float(ts.hour),
                "dow": float(ts.weekday()),
                "is_month_end": float(ts.day >= 28),
                "is_market_day": float(ts.weekday() in (1, 4)),
                "amount_vs_sender_avg": float(amount_vs_avg[i]),
                "sender_txns_24h": float(sender_txns_24h[i]),
                "sender_unique_receivers_72h": float(rng.integers(1, 30 if fraud[i] else 5)),
                "receiver_fanin_72h": float(rng.integers(20, 100) if fraud[i] else rng.integers(0, 5)),
                "mins_since_last_txn": float(rng.uniform(0.5, 30) if fraud[i] else rng.uniform(60, 3000)),
                "device_emulator": float(rng.random() < (0.15 if fraud[i] else 0.005)),
                "sim_swap_7d": float(sim_swap[i]),
                "new_device": float(new_device[i]),
                "cross_state": float(rng.random() < 0.1),
                "cross_bank": float(sender_bank != receiver_bank),
                "is_night": float(ts.hour < 6),
                # --- ml lane categorical features ---
                "channel": str(rng.choice(CHANNELS)),
                "sender_bank": sender_bank,
                "receiver_bank": receiver_bank,
                "sender_state": sender_state,
                "device_os": str(rng.choice(DEVICE_OS)),
                # --- serving / labels ---
                "risk_score": risk,
                "is_fraud": int(bool(fraud[i])) if rng.random() < label_fraction else None,
                "label_source": "synthetic_demo",
            })
        write_partition(apply_privacy_controls(rows, **privacy), day.isoformat(), lakehouse_dir)
        total += n
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", help="YYYY-MM-DD (DB mode)")
    parser.add_argument("--end", help="YYYY-MM-DD (DB mode)")
    parser.add_argument("--synthetic", action="store_true", help="demo mode, no DB needed")
    parser.add_argument("--days", type=int, default=14, help="synthetic: number of partitions")
    parser.add_argument("--rows-per-day", type=int, default=500)
    parser.add_argument("--label-fraction", type=float, default=1.0,
                        help="synthetic: fraction of rows with is_fraud populated (1.0 = fully labeled)")
    parser.add_argument("--include-pii", action="store_true",
                        help="write raw customer identifiers (default: salted-SHA256 pseudonyms); "
                             "requires a documented lawful basis")
    parser.add_argument("--purpose", default=DEFAULT_PURPOSE,
                        help="processing purpose metadata stamped on every exported row")
    parser.add_argument("--lawful-basis", default=DEFAULT_LAWFUL_BASIS,
                        help="NDPA lawful basis metadata stamped on every exported row")
    parser.add_argument("--lakehouse-dir", type=Path, default=LAKEHOUSE_DIR)
    args = parser.parse_args()

    if args.include_pii:
        logger.warning("--include-pii: exporting RAW customer identifiers (purpose=%s, "
                       "lawful_basis=%s). Ensure this is authorized and access-controlled.",
                       args.purpose, args.lawful_basis)
    privacy = {
        "include_pii": args.include_pii,
        "salt": os.getenv("LAKEHOUSE_PII_SALT", "fraudfusion-lakehouse-v1"),
        "purpose": args.purpose,
        "lawful_basis": args.lawful_basis,
    }

    if args.synthetic:
        total = synthesize(args.days, args.rows_per_day, args.lakehouse_dir,
                           label_fraction=args.label_fraction, **privacy)
        logger.info("synthetic export complete: %d rows over %d partitions", total, args.days)
        return
    if not (args.start and args.end):
        raise SystemExit("--start and --end are required in DB mode (or use --synthetic)")
    total = export_from_postgres(args.start, args.end, args.lakehouse_dir, **privacy)
    logger.info("export complete: %d rows", total)


if __name__ == "__main__":
    main()
