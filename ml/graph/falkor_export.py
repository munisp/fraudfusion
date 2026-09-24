"""Export the account-transaction graph to FalkorDB (Redis-protocol graph).

Mirror of ml/graph/neo4j_export.py for FalkorDB: reads the generated/lakehouse
parquet data, MERGEs Account nodes and Transaction nodes + SENT/TO edges in
batches (idempotent via MERGE on customer_id / txn_id).

Fails LOUDLY (exit 2) if redis-py or the server is missing — nothing faked.
Local server: docker compose -f ml/graph/falkor.compose.yml up -d
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.graph.falkor_client import FalkorClient  # noqa: E402

BATCH = 500


def _maps(rows: list[dict]) -> str:
    """Render a list of dicts as a Cypher list-of-maps literal."""
    def fmt(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return repr(float(v)) if isinstance(v, float) else repr(v)
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'
    return "[" + ", ".join(
        "{" + ", ".join(f"{k}: {fmt(v)}" for k, v in r.items()) + "}"
        for r in rows) + "]"


def export(data_dir: str, max_txns: int | None = None,
           client: FalkorClient | None = None) -> dict:
    try:
        c = client or FalkorClient()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    accts = pd.read_parquet(Path(data_dir) / "accounts.parquet")
    txns = pd.read_parquet(Path(data_dir) / "transactions.parquet")
    if max_txns:
        txns = txns.head(max_txns)

    acct_rows = [dict(
        customer_id=r.customer_id, bank=r.bank, state=r.state,
        age=int(r.age), bureau_score=int(r.bureau_score),
        monthly_income=float(r.monthly_income),
        is_mule=bool(r.is_mule), is_pep=bool(r.is_pep),
        is_agent=bool(getattr(r, "is_agent", False)),
    ) for r in accts.itertuples()]
    txn_rows = [dict(
        txn_id=r.txn_id, sender_id=r.sender_id, receiver_id=r.receiver_id,
        amount_ngn=float(r.amount_ngn), channel=r.channel,
        ts=r.ts.isoformat(), is_fraud=bool(r.is_fraud),
        fraud_typology=r.fraud_typology,
    ) for r in txns.itertuples()]

    for i in range(0, len(acct_rows), BATCH):
        c.query(
            f"UNWIND {_maps(acct_rows[i:i + BATCH])} AS r "
            "MERGE (a:Account {customer_id: r.customer_id}) "
            "SET a += {bank: r.bank, state: r.state, age: r.age, "
            "bureau_score: r.bureau_score, monthly_income: r.monthly_income, "
            "is_mule: r.is_mule, is_pep: r.is_pep, is_agent: r.is_agent}")
        print(f"accounts {i + len(acct_rows[i:i+BATCH])}/{len(acct_rows)}")
    for i in range(0, len(txn_rows), BATCH):
        c.query(
            f"UNWIND {_maps(txn_rows[i:i + BATCH])} AS r "
            "MERGE (t:Transaction {txn_id: r.txn_id}) "
            "SET t += {amount_ngn: r.amount_ngn, channel: r.channel, "
            "ts: r.ts, is_fraud: r.is_fraud, fraud_typology: r.fraud_typology} "
            "WITH t, r "
            "MATCH (s:Account {customer_id: r.sender_id}), "
            "      (d:Account {customer_id: r.receiver_id}) "
            "MERGE (s)-[:SENT]->(t) MERGE (t)-[:TO]->(d)")
        print(f"txns {i + len(txn_rows[i:i+BATCH])}/{len(txn_rows)}")

    n_acc = c.query("MATCH (a:Account) RETURN count(a)", read_only=True)[0][0]
    n_txn = c.query("MATCH (t:Transaction) RETURN count(t)", read_only=True)[0][0]
    return {"accounts": int(n_acc), "transactions": int(n_txn)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=os.environ.get(
        "FRAUDFUSION_DATA", "ml/data/generated"))
    ap.add_argument("--max-txns", type=int, default=None)
    a = ap.parse_args()
    print(export(a.data_dir, a.max_txns))
