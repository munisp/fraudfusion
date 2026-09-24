"""Export the account-transaction graph to Neo4j via the Bolt protocol.

Reads the generated/lakehouse parquet data (accounts + transactions), then
MERGEs Account nodes and TXN relationships in batches. Idempotent (MERGE on
customer_id / txn_id).

Env:
  NEO4J_URI      bolt://localhost:7687 (default)
  NEO4J_USER     neo4j (default)
  NEO4J_PASSWORD password (default)
  FRAUDFUSION_DATA  parquet dir (default ml/data/generated)

The neo4j python driver is OPTIONAL: if it is not installed, or no server is
reachable, this fails with a clear, non-crashy error (exit 2) — nothing is
faked.

A compose fragment for a local Neo4j lives in ml/graph/neo4j.compose.yml.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

BATCH = 2000


def _driver():
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError:
        print("ERROR: neo4j python driver not installed. "
              "`pip install neo4j` (or use ml/graph/neo4j.compose.yml).",
              file=sys.stderr)
        sys.exit(2)
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    auth = (os.environ.get("NEO4J_USER", "neo4j"),
            os.environ.get("NEO4J_PASSWORD", "password"))
    try:
        d = GraphDatabase.driver(uri, auth=auth)
        d.verify_connectivity()
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: cannot connect to Neo4j at {uri}: {e}\n"
              f"Start one with: docker compose -f ml/graph/neo4j.compose.yml up -d",
              file=sys.stderr)
        sys.exit(2)
    return d


def export(data_dir: str, max_txns: int | None = None) -> dict:
    d = _driver()
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

    with d.session() as s:
        s.run("CREATE CONSTRAINT account_id IF NOT EXISTS FOR (a:Account) "
              "REQUIRE a.customer_id IS UNIQUE")
        s.run("CREATE CONSTRAINT txn_id IF NOT EXISTS FOR (t:Transaction) "
              "REQUIRE t.txn_id IS UNIQUE")
        for i in range(0, len(acct_rows), BATCH):
            s.run("UNWIND $rows AS r MERGE (a:Account {customer_id: r.customer_id}) "
                  "SET a += {bank: r.bank, state: r.state, age: r.age, "
                  "bureau_score: r.bureau_score, monthly_income: r.monthly_income, "
                  "is_mule: r.is_mule, is_pep: r.is_pep, is_agent: r.is_agent}",
                  rows=acct_rows[i:i + BATCH])
            print(f"accounts {i + len(acct_rows[i:i+BATCH])}/{len(acct_rows)}")
        for i in range(0, len(txn_rows), BATCH):
            s.run(
                "UNWIND $rows AS r "
                "MERGE (t:Transaction {txn_id: r.txn_id}) "
                "SET t += {amount_ngn: r.amount_ngn, channel: r.channel, "
                "ts: r.ts, is_fraud: r.is_fraud, fraud_typology: r.fraud_typology} "
                "WITH t, r "
                "MATCH (s:Account {customer_id: r.sender_id}), "
                "      (d:Account {customer_id: r.receiver_id}) "
                "MERGE (s)-[:SENT]->(t) MERGE (t)-[:TO]->(d)",
                rows=txn_rows[i:i + BATCH])
            print(f"txns {i + len(txn_rows[i:i+BATCH])}/{len(txn_rows)}")
        n_acc = s.run("MATCH (a:Account) RETURN count(a) AS c").single()["c"]
        n_txn = s.run("MATCH (t:Transaction) RETURN count(t) AS c").single()["c"]
    d.close()
    return {"accounts": n_acc, "transactions": n_txn}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=os.environ.get(
        "FRAUDFUSION_DATA", "ml/data/generated"))
    ap.add_argument("--max-txns", type=int, default=None)
    a = ap.parse_args()
    print(export(a.data_dir, a.max_txns))
