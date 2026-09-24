"""Tests for the KG pipeline + kg-qa service.

Strategy: build a tiny synthetic lakehouse (parquet fixtures), run the
incremental pipeline, then exercise entity linking / path reasoning /
composition over the resulting in-memory store — including the fallback mode
(no FalkorDB, no Neo4j, no ollama), which is the mode that must never fake.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd
import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from intelligence.kg_pipeline import executor, schema  # noqa: E402
from intelligence.kg_pipeline.pseudonymize import entity_id  # noqa: E402
from intelligence.kg_load.common import cypher_str, props_literal  # noqa: E402

SALT = "test-salt"


@pytest.fixture()
def lakehouse(tmp_path: Path) -> Path:
    lh = tmp_path / "lakehouse"
    lh.mkdir()
    pd.DataFrame([
        {"customer_id": "u1", "bank": "GTBank", "state": "Lagos", "city": "Ikeja",
         "ts": "2026-09-01T00:00:00", "is_agent": False},
        {"customer_id": "u2", "bank": "Kuda", "state": "Lagos", "city": "Yaba",
         "ts": "2026-09-01T00:00:00", "is_agent": False},
        {"customer_id": "u3", "bank": "OPay", "state": "Abuja", "city": "Wuse",
         "ts": "2026-09-02T00:00:00", "is_agent": True},
    ]).to_parquet(lh / "accounts.parquet")
    pd.DataFrame([
        {"txn_id": "t1", "sender_id": "u1", "receiver_id": "u2", "amount_ngn": 5000.0,
         "channel": "ussd", "ts": "2026-09-10T10:00:00"},
        {"txn_id": "t2", "sender_id": "u2", "receiver_id": "u3", "amount_ngn": 9000.0,
         "channel": "pos", "merchant_id": "m1", "ts": "2026-09-11T10:00:00"},
    ]).to_parquet(lh / "transactions.parquet")
    pd.DataFrame([
        {"device_id": "d1", "user_id": "u1", "ip_address": "10.0.0.1",
         "last_seen_at": "2026-09-10T09:00:00"},
        {"device_id": "d1", "user_id": "u2", "ip_address": "10.0.0.1",
         "last_seen_at": "2026-09-10T09:05:00"},
    ]).to_parquet(lh / "devices.parquet")
    pd.DataFrame([
        {"alert_id": "a1", "customer_id": "u2", "alert_type": "sim_swap",
         "risk_level": "high", "created_at": "2026-09-12T00:00:00"},
    ]).to_parquet(lh / "alerts.parquet")
    pd.DataFrame([
        {"sar_id": "sar1", "user_id": "u2", "activity_type": "structuring",
         "status": "filed", "filing_date": "2026-09-13T00:00:00"},
    ]).to_parquet(lh / "sars.parquet")
    return lh


@pytest.fixture()
def kg_dir(lakehouse: Path, tmp_path: Path) -> Path:
    out = tmp_path / "kg"
    executor.run(lakehouse, out, salt=SALT)
    return out


# --- pipeline ----------------------------------------------------------------

def test_pipeline_creates_entities_and_relations(kg_dir: Path):
    entities = pd.read_parquet(kg_dir / schema.ENTITIES_FILE)
    relations = pd.read_parquet(kg_dir / schema.RELATIONS_FILE)
    assert len(entities) > 0 and len(relations) > 0
    assert set(entities["label"]) <= set(schema.ENTITY_TYPES)
    assert set(relations["type"]) <= set(schema.REL_TYPES)


def test_entity_ids_are_pseudonymized(kg_dir: Path):
    entities = pd.read_parquet(kg_dir / schema.ENTITIES_FILE)
    for eid in entities["id"]:
        assert "_pii_" in eid
    # raw ids must never appear
    for raw in ("u1", "u2", "u3", "d1", "sar1"):
        assert not any(eid.endswith(raw) or f"_{raw}_" in eid for eid in entities["id"])


def test_shares_device_edge_derived(kg_dir: Path):
    relations = pd.read_parquet(kg_dir / schema.RELATIONS_FILE)
    c1, c2 = entity_id("Customer", "u1", SALT), entity_id("Customer", "u2", SALT)
    sd = relations[relations["type"] == schema.SHARES_DEVICE]
    pairs = set(zip(sd["src_id"], sd["dst_id"]))
    assert (c1, c2) in pairs and (c2, c1) in pairs


def test_sar_filed_against_edge(kg_dir: Path):
    relations = pd.read_parquet(kg_dir / schema.RELATIONS_FILE)
    sar = entity_id("SAR", "sar1", SALT)
    cust = entity_id("Customer", "u2", SALT)
    fa = relations[relations["type"] == schema.FILED_AGAINST]
    assert (sar, cust) in set(zip(fa["src_id"], fa["dst_id"]))


def test_incremental_watermark_no_delta(lakehouse: Path, kg_dir: Path):
    stats = executor.run(lakehouse, kg_dir, salt=SALT)
    assert stats["delta_entities"] == 0 and stats["delta_relations"] == 0
    assert stats.get("note") == "no new rows since last watermark"


def test_tsless_dataset_fingerprint_gated(tmp_path: Path):
    """Dimension rows without timestamps must not re-merge (and inflate
    relation counts) on every run — content fingerprint gates them."""
    lh = tmp_path / "lh"
    lh.mkdir()
    pd.DataFrame([
        {"merchant_id": "m1", "name": "Sabo Market"},
        {"merchant_id": "m2", "name": "Wuse POS"},
    ]).to_parquet(lh / "merchants.parquet")
    out = tmp_path / "kg"
    s1 = executor.run(lh, out, salt=SALT)
    assert s1["delta_entities"] == 2
    rels1 = pd.read_parquet(out / schema.RELATIONS_FILE)
    s2 = executor.run(lh, out, salt=SALT)
    assert s2["delta_entities"] == 0  # unchanged content -> skipped
    # change the dimension table -> reprocessed exactly once more
    pd.DataFrame([
        {"merchant_id": "m1", "name": "Sabo Market"},
        {"merchant_id": "m2", "name": "Wuse POS"},
        {"merchant_id": "m3", "name": "Aba Terminal"},
    ]).to_parquet(lh / "merchants.parquet")
    s3 = executor.run(lh, out, salt=SALT)
    assert s3["delta_entities"] == 3
    ents = pd.read_parquet(out / schema.ENTITIES_FILE)
    assert len(ents) == 3  # MERGE kept m1/m2 single instances
    rels2 = pd.read_parquet(out / schema.RELATIONS_FILE)
    assert len(rels1) == len(rels2)  # no phantom relation growth


def test_incremental_new_rows_extend_graph(lakehouse: Path, kg_dir: Path):
    before = len(pd.read_parquet(kg_dir / schema.ENTITIES_FILE))
    # append a newer SAR against u3
    pd.DataFrame([
        {"sar_id": "sar1", "user_id": "u2", "activity_type": "structuring",
         "status": "filed", "filing_date": "2026-09-13T00:00:00"},
        {"sar_id": "sar2", "user_id": "u3", "activity_type": "ctr_evasion",
         "status": "draft", "filing_date": "2026-09-20T00:00:00"},
    ]).to_parquet(lakehouse / "sars.parquet")
    stats = executor.run(lakehouse, kg_dir, salt=SALT)
    after = pd.read_parquet(kg_dir / schema.ENTITIES_FILE)
    assert stats["datasets"].get("sars") == 1  # only the newer row
    assert len(after) > before
    assert entity_id("SAR", "sar2", SALT) in set(after["id"])


def test_schema_version_guard(lakehouse: Path, kg_dir: Path):
    state_file = kg_dir / schema.STATE_FILE
    state = json.loads(state_file.read_text())
    state["schema_version"] = "0.0.0"
    state_file.write_text(json.dumps(state))
    with pytest.raises(RuntimeError, match="schema_version"):
        executor.run(lakehouse, kg_dir, salt=SALT)
    stats = executor.run(lakehouse, kg_dir, salt=SALT, full_rebuild=True)
    assert stats["full_rebuild"] is True


def test_cypher_literal_escaping():
    assert cypher_str("o'brien\\x") == "'o\\'brien\\\\x'"
    assert cypher_str(None) == "null"
    assert props_literal(json.dumps({"a": 1, "b": "x'y", "c": True})) == \
        "{`a`: 1, `b`: 'x\\'y', `c`: true}"


def test_cocoindex_adapter_parity(lakehouse: Path, tmp_path: Path):
    coco = pytest.importorskip("cocoindex", reason="cocoindex not installed")
    del coco
    from intelligence.kg_pipeline import cocoindex_adapter
    out_builtin = tmp_path / "kg_builtin"
    out_coco = tmp_path / "kg_coco"
    s1 = executor.run(lakehouse, out_builtin, salt=SALT)
    s2 = cocoindex_adapter.run(lakehouse, out_coco, salt=SALT)
    assert s2["engine"].startswith("cocoindex")
    assert s1["total_entities"] == s2["total_entities"]
    assert s1["total_relations"] == s2["total_relations"]


# --- service (fallback in-memory mode) ---------------------------------------

@pytest.fixture()
def client(kg_dir: Path, monkeypatch):
    monkeypatch.delenv("FALKORDB_URL", raising=False)
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    svc_dir = Path(__file__).resolve().parents[1]
    if str(svc_dir) not in sys.path:
        sys.path.insert(0, str(svc_dir))
    from fastapi.testclient import TestClient
    from app import main
    main.KG_DIR = str(kg_dir)
    main._store = None
    return TestClient(main.app)


def test_health_fallback_mode(client):
    r = client.get("/v1/kgqa/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["store_mode"] == "in-memory-parquet"
    assert body["entities"] > 0
    assert body["ollama"]["configured"] is False
    assert body["ollama"]["reachable"] is False


def test_ask_shared_device_question(client):
    r = client.post("/v1/kgqa/ask",
                    json={"question": "Which customers share a device flagged in sim_swap alerts?"})
    assert r.status_code == 200
    body = r.json()
    assert body["llm_used"] is False
    assert body["store_mode"] == "in-memory-parquet"
    assert len(body["linked_entities"]) > 0
    assert len(body["paths"]) > 0
    assert len(body["citations"]) > 0
    # every citation is a real pseudonymized KG entity id
    for c in body["citations"]:
        assert "_pii_" in c["entity_id"]
    # the sim_swap alert appears in some rendered path
    assert any("sim_swap" in p["text"] or "alert" in p["text"].lower()
               for p in body["paths"])


def test_ask_sar_question_uses_filed_against(client):
    r = client.post("/v1/kgqa/ask",
                    json={"question": "Who was structuring SAR filed against?"})
    body = r.json()
    assert r.status_code == 200
    hop_types = [h["type"] for p in body["paths"] for h in p["hops"]]
    assert schema.FILED_AGAINST in hop_types


def test_ask_no_match_is_honest(client):
    r = client.post("/v1/kgqa/ask",
                    json={"question": "xyzzy quux frobnicate nothing matches"})
    body = r.json()
    assert body["paths"] == []
    assert body["citations"] == []
    assert "could not link" in body["answer"]


def test_ask_with_pasted_entity_id(client, kg_dir: Path):
    entities = pd.read_parquet(kg_dir / schema.ENTITIES_FILE)
    cust = entities[entities["label"] == "Customer"].iloc[0]["id"]
    r = client.post("/v1/kgqa/ask", json={"question": f"What is connected to {cust}?"})
    body = r.json()
    assert any(l["entity_id"] == cust for l in body["linked_entities"])
    assert len(body["paths"]) > 0  # context-path mode


def test_ollama_unreachable_degrades(client, monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:9")  # nothing listens
    from app import compose
    monkeypatch.setattr(compose, "OLLAMA_URL", "http://127.0.0.1:9")
    r = client.post("/v1/kgqa/ask",
                    json={"question": "Which customers share a device flagged in sim_swap alerts?"})
    body = r.json()
    assert r.status_code == 200
    assert body["llm_used"] is False
    assert "knowledge graph" in body["answer"] or "path" in body["answer"]


def test_refresh_endpoint(client, lakehouse: Path, kg_dir: Path, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "LAKEHOUSE_DIR", str(lakehouse))
    r = client.post("/v1/kg/refresh", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "total_entities" in body["stats"]


def test_entity_linking_fuzzy(kg_dir: Path):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.entity_linking import link_entities
    from app.graph_store import InMemoryGraphStore
    store = InMemoryGraphStore(kg_dir)
    hits = link_entities("tell me about sim-swap alerts", store)  # hyphen vs underscore
    assert any(h["matched"] == "sim_swap" for h in hits)


def test_path_scoring_prefers_strong_relations(kg_dir: Path):
    from app.path_reasoning import edge_score
    strong = edge_score({"type": schema.FILED_AGAINST, "ts": "2026-09-13T00:00:00"})
    weak = edge_score({"type": schema.LOCATED_IN, "ts": "2026-09-13T00:00:00"})
    assert strong > weak
    stale = edge_score({"type": schema.FILED_AGAINST, "ts": "2020-01-01T00:00:00"})
    assert stale < strong  # recency decay
