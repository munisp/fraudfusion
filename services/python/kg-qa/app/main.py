"""kg-qa service — EPR-KGQA-style analyst question answering (:8300).

Pipeline per question:
  1. entity linking   (app/entity_linking.py — exact + fuzzy)
  2. path reasoning   (app/path_reasoning.py — bounded BFS + scoring)
  3. composition      (app/compose.py — grounded template; optional ollama
                       rephrase; every answer carries KG citations)

Endpoints:
  POST /v1/kgqa/ask      answer an analyst question with KG citations
  GET  /v1/kgqa/health   store mode, graph size, ollama reachability
  POST /v1/kg/refresh    re-run the incremental KG build, then reload the store

Auth note: like other internal services this is expected to sit behind the
apisix + Keycloak edge (deploy/kubernetes/apisix.yaml); it exposes no
public port of its own in the k8s manifests.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

# Repo-root bootstrap so `intelligence.*` imports work both from the repo
# checkout and from the container image (intelligence/ copied to /app).
_THIS = Path(__file__).resolve()
for _cand in (_THIS.parents[3], Path("/app")):  # services/python/kg-qa/app -> repo root
    if (_cand / "intelligence").is_dir() and str(_cand) not in sys.path:
        sys.path.insert(0, str(_cand))

from fastapi import FastAPI

from app import compose, entity_linking, path_reasoning
from app.graph_store import InMemoryGraphStore, get_store
from app.schemas import (AskRequest, AskResponse, Citation, Hop,
                         RefreshRequest, RefreshResponse, ScoredPath)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("kg-qa")

KG_DIR = os.environ.get("KG_DIR", "intelligence/data/kg")
LAKEHOUSE_DIR = os.environ.get("LAKEHOUSE_DIR", "mlops/data/lakehouse")

app = FastAPI(title="FraudFusion KG-QA", version="1.0.0")

_store: Any = None


def store():
    global _store
    if _store is None:
        _store = get_store(KG_DIR)
        logger.info("graph store mode=%s stats=%s", _store.mode, _store.stats())
    return _store


def _collect_entities(store_obj, paths) -> dict[str, dict[str, Any]]:
    ids: set[str] = set()
    for p in paths:
        for h in p["hops"]:
            ids.add(h["src"])
            ids.add(h["dst"])
    return store_obj.get_entities(ids)


@app.post("/v1/kgqa/ask", response_model=AskResponse)
def ask(req: AskRequest) -> AskResponse:
    s = store()
    linked = entity_linking.link_entities(req.question, s)
    linked_ids = [l["entity_id"] for l in linked]
    paths = path_reasoning.enumerate_paths(s, linked_ids, req.max_hops, req.max_paths)
    entities = _collect_entities(s, paths)

    answer = compose.template_answer(req.question, paths, entities, linked)
    llm_text = compose.ollama_rephrase(req.question, answer)
    llm_used = llm_text is not None
    if llm_used:
        answer = llm_text

    path_models = [
        ScoredPath(score=p["score"],
                   hops=[Hop(**h) for h in p["hops"]],
                   text=rendered)
        for p, rendered in zip(paths, [compose.render_path_text(p["hops"], entities)
                                       for p in paths])
    ]
    citations: list[Citation] = []
    seen: set[str] = set()
    for p in paths:
        for h in p["hops"]:
            for eid in (h["src"], h["dst"]):
                if eid not in seen:
                    seen.add(eid)
                    meta = entities.get(eid, {})
                    citations.append(Citation(entity_id=eid,
                                              label=meta.get("label") or "Unknown"))
    return AskResponse(
        question=req.question,
        answer=answer,
        llm_used=llm_used,
        llm_model=compose.OLLAMA_MODEL if llm_used else None,
        store_mode=s.mode,
        linked_entities=[Citation(entity_id=l["entity_id"],
                                  label=l.get("label") or "Unknown",
                                  role="linked") for l in linked],
        citations=citations,
        paths=path_models,
    )


@app.get("/v1/kgqa/health")
def health() -> dict[str, Any]:
    s = store()
    stats = s.stats()
    return {
        "status": "ok",
        "store_mode": s.mode,
        "kg_dir": KG_DIR,
        "entities": stats.get("entities", 0),
        "relations": stats.get("relations", 0),
        "ollama": {
            "url": compose.OLLAMA_URL,
            "model": compose.OLLAMA_MODEL,
            "configured": bool(compose.OLLAMA_URL),
            "reachable": compose.ollama_reachable(),
        },
    }


@app.post("/v1/kg/refresh", response_model=RefreshResponse)
def refresh(req: RefreshRequest) -> RefreshResponse:
    """Re-run the incremental KG build from the lakehouse, then reload."""
    global _store
    try:
        from intelligence.kg_pipeline import executor
    except ImportError as e:
        return RefreshResponse(
            status="unavailable",
            stats={"error": f"intelligence.kg_pipeline not importable: {e}"})
    stats = executor.run(LAKEHOUSE_DIR, KG_DIR, full_rebuild=req.full_rebuild)
    # reload the in-memory store (server-backed stores read live already)
    if _store is None or isinstance(_store, InMemoryGraphStore):
        _store = InMemoryGraphStore(KG_DIR)
    return RefreshResponse(status="ok", stats=stats)
