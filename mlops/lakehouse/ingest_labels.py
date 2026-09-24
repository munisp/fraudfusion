"""Merge investigator feedback labels back into the lakehouse.

Input: a CSV/JSON file (or Postgres table via DATABASE_URL) of investigator
decisions with columns:
    transaction_id, label (0/1), label_source, decided_at

The script rewrites the affected dt= partitions with the label column filled,
leaving unlabeled rows untouched.

Usage:
    python mlops/lakehouse/ingest_labels.py --file labels.csv
    python mlops/lakehouse/ingest_labels.py --from-db   # uses LABEL_QUERY
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import uuid
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ingest-labels")

LAKEHOUSE_DIR = Path(os.getenv("LAKEHOUSE_DIR", "mlops/data/lakehouse"))

LABEL_QUERY = os.getenv(
    "LABEL_QUERY",
    """
    SELECT transaction_id,
           CASE WHEN confirmed_fraud THEN 1 ELSE 0 END AS label,
           'investigator' AS label_source,
           decided_at
    FROM investigator_decisions
    WHERE exported_to_lakehouse IS NOT TRUE
    """,
)


def load_labels_from_file(path: Path) -> dict[str, dict]:
    labels: dict[str, dict] = {}
    if path.suffix == ".json":
        records = json.loads(path.read_text(encoding="utf-8"))
    else:
        with open(path, newline="", encoding="utf-8") as fh:
            records = list(csv.DictReader(fh))
    for record in records:
        labels[record["transaction_id"]] = {
            "label": int(record["label"]),
            "label_source": record.get("label_source", "investigator"),
        }
    return labels


def load_labels_from_db() -> dict[str, dict]:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL not set")
    import psycopg2

    labels: dict[str, dict] = {}
    with psycopg2.connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(LABEL_QUERY)
        for transaction_id, label, source, _decided_at in cur.fetchall():
            labels[transaction_id] = {"label": int(label), "label_source": source}
    return labels


def apply_labels(labels: dict[str, dict], lakehouse_dir: Path) -> int:
    import pyarrow.parquet as pq

    updated = 0
    for parquet_path in sorted(lakehouse_dir.rglob("*.parquet")):
        table = pq.read_table(parquet_path)
        rows = table.to_pylist()
        touched = False
        for row in rows:
            match = labels.get(row.get("transaction_id"))
            # 'is_fraud' is the ml lane label column; 'label' kept as alias.
            label_col = "is_fraud" if "is_fraud" in row else "label"
            if match and row.get(label_col) != match["label"]:
                row[label_col] = match["label"]
                row["label_source"] = match["label_source"]
                touched = True
                updated += 1
        if touched:
            import pyarrow as pa

            tmp = parquet_path.with_suffix(f".{uuid.uuid4().hex[:8]}.tmp")
            pq.write_table(pa.Table.from_pylist(rows), tmp, compression="snappy")
            tmp.replace(parquet_path)
            logger.info("updated labels in %s", parquet_path)
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="CSV or JSON file of labels")
    source.add_argument("--from-db", action="store_true", help="read LABEL_QUERY from DATABASE_URL")
    parser.add_argument("--lakehouse-dir", type=Path, default=LAKEHOUSE_DIR)
    args = parser.parse_args()

    labels = load_labels_from_db() if args.from_db else load_labels_from_file(args.file)
    logger.info("loaded %d labels", len(labels))
    if not labels:
        return
    updated = apply_labels(labels, args.lakehouse_dir)
    logger.info("applied %d labels to lakehouse partitions", updated)


if __name__ == "__main__":
    main()
