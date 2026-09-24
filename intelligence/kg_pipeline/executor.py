"""Built-in incremental KG executor (cocoindex-equivalent semantics).

Semantics (identical to the cocoindex adapter in cocoindex_adapter.py):
  * per-dataset watermark = max source event timestamp already incorporated
  * each run reads only rows strictly newer than the watermark; timestamp-
    less rows (dimension tables) are content-fingerprinted and skipped when
    unchanged, so re-runs do not inflate relation counts
  * new rows are transformed by builder.build() into a subgraph delta
  * the delta is MERGEd into the on-disk store (entities.parquet /
    relations.parquet): entities dedupe on id (props merged, first_seen kept
    minimal, last_seen maximal), relations dedupe on (src,dst,type) with
    count accumulation and max(ts)
  * the state file (.kg_state.json) records watermarks, schema version and
    run stats; a store at a different KG_SCHEMA_VERSION is refused unless
    full_rebuild=True, in which case the store is rewritten from scratch

The store layout is plain parquet so the kg-qa service can serve from disk
when no graph server is reachable.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import builder, schema, sources
from .pseudonymize import get_salt

log = logging.getLogger("kg_pipeline.executor")

ENTITY_COLUMNS = ["id", "label", "props", "first_seen", "last_seen", "schema_version"]
RELATION_COLUMNS = ["src_id", "dst_id", "type", "props", "ts", "count", "schema_version"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_state(output_dir: Path) -> dict[str, Any]:
    p = output_dir / schema.STATE_FILE
    if p.exists():
        return json.loads(p.read_text())
    return {"schema_version": schema.KG_SCHEMA_VERSION, "watermarks": {}, "runs": []}


def save_state(output_dir: Path, state: dict[str, Any]) -> None:
    (output_dir / schema.STATE_FILE).write_text(json.dumps(state, indent=2, sort_keys=True))


def _read_store(output_dir: Path) -> tuple[list[dict], list[dict]]:
    import pandas as pd
    e_file, r_file = output_dir / schema.ENTITIES_FILE, output_dir / schema.RELATIONS_FILE
    entities = pd.read_parquet(e_file).to_dict("records") if e_file.exists() else []
    relations = pd.read_parquet(r_file).to_dict("records") if r_file.exists() else []
    return entities, relations


def _write_store(output_dir: Path, entities: list[dict], relations: list[dict]) -> None:
    import pandas as pd
    e_df = pd.DataFrame(entities, columns=ENTITY_COLUMNS)
    r_df = pd.DataFrame(relations, columns=RELATION_COLUMNS)
    e_df.to_parquet(output_dir / schema.ENTITIES_FILE, index=False)
    r_df.to_parquet(output_dir / schema.RELATIONS_FILE, index=False)


def _merge_delta(store_e: list[dict], store_r: list[dict],
                 delta_e: list[dict], delta_r: list[dict]) -> tuple[list[dict], list[dict]]:
    ents: dict[str, dict] = {e["id"]: dict(e) for e in store_e}
    rels: dict[tuple, dict] = {(r["src_id"], r["dst_id"], r["type"]): dict(r) for r in store_r}
    for e in delta_e:
        cur = ents.get(e["id"])
        if cur is None:
            ents[e["id"]] = dict(e)
            continue
        props = json.loads(cur["props"] or "{}")
        props.update(json.loads(e["props"] or "{}"))
        cur["props"] = json.dumps(props, sort_keys=True)
        for f, cmp in (("first_seen", min), ("last_seen", max)):
            vals = [v for v in (cur.get(f), e.get(f)) if v]
            cur[f] = cmp(vals) if vals else None
    for r in delta_r:
        key = (r["src_id"], r["dst_id"], r["type"])
        cur = rels.get(key)
        if cur is None:
            rels[key] = dict(r)
            continue
        cur["count"] = int(cur.get("count") or 0) + int(r.get("count") or 0)
        props = json.loads(cur["props"] or "{}")
        props.update(json.loads(r["props"] or "{}"))
        cur["props"] = json.dumps(props, sort_keys=True)
        vals = [v for v in (cur.get("ts"), r.get("ts")) if v]
        cur["ts"] = max(vals) if vals else None
    return list(ents.values()), list(rels.values())


def _filter_since(rows: list[dict[str, Any]], watermark: str | None) -> list[dict[str, Any]]:
    if not watermark:
        return rows
    return [r for r in rows if r.get("ts") is None or r["ts"] > watermark]


def _rows_fingerprint(rows: list[dict[str, Any]]) -> str:
    import hashlib
    payload = json.dumps(sorted(json.dumps(r, sort_keys=True, default=str) for r in rows))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def filter_incremental(rows: list[dict[str, Any]], name: str,
                       state: dict[str, Any]) -> list[dict[str, Any]]:
    """Watermark + fingerprint incremental filtering (shared by both engines).

    Rows with an event timestamp are filtered by the per-dataset watermark.
    Timestamp-less rows (dimension tables like accounts) cannot be
    watermark-filtered; they are instead content-fingerprinted, and skipped
    entirely when unchanged since the last run — otherwise their relation
    counts would inflate on every re-run. Mixed datasets: only the ts-less
    subset is fingerprint-gated.
    """
    watermark = state.get("watermarks", {}).get(name)
    fresh = _filter_since(rows, watermark)
    ts_less = [r for r in fresh if r.get("ts") is None]
    if not ts_less:
        return fresh
    fp = _rows_fingerprint(ts_less)
    if state.get("fingerprints", {}).get(name) == fp:
        return [r for r in fresh if r.get("ts") is not None]
    # mark pending fingerprint update; committed by record_fingerprint
    state.setdefault("_pending_fingerprints", {})[name] = fp
    return fresh


def commit_fingerprints(state: dict[str, Any]) -> None:
    pending = state.pop("_pending_fingerprints", {})
    if pending:
        state.setdefault("fingerprints", {}).update(pending)


def _max_ts(rows: list[dict[str, Any]]) -> str | None:
    vals = [r["ts"] for r in rows if r.get("ts")]
    return max(vals) if vals else None


def run(lakehouse_dir: str | Path, output_dir: str | Path,
        salt: str | None = None, full_rebuild: bool = False,
        datasets: tuple[str, ...] | None = None,
        postgres_dsn: str | None = None) -> dict[str, Any]:
    """One incremental KG build cycle. Returns run stats."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    salt = get_salt(salt)
    state = load_state(output_dir)

    if state.get("schema_version") != schema.KG_SCHEMA_VERSION and not full_rebuild:
        raise RuntimeError(
            f"KG store at {output_dir} has schema_version="
            f"{state.get('schema_version')!r}, pipeline expects "
            f"{schema.KG_SCHEMA_VERSION!r}. Re-run with full_rebuild=True.")
    if full_rebuild:
        state = {"schema_version": schema.KG_SCHEMA_VERSION, "watermarks": {}, "runs": []}
        for f in (schema.ENTITIES_FILE, schema.RELATIONS_FILE):
            p = output_dir / f
            if p.exists():
                p.unlink()

    wanted = datasets or schema.DATASETS
    collected: dict[str, list[dict[str, Any]]] = {}
    for name in wanted:
        rows = filter_incremental(sources.read_dataset(lakehouse_dir, name), name, state)
        if rows:
            collected[name] = rows
    if postgres_dsn:
        pg = sources.read_postgres(postgres_dsn,
                                   since={k: v for k, v in state["watermarks"].items() if v})
        for name, rows in pg.items():
            collected.setdefault(name, []).extend(rows)

    delta_e, delta_r = builder.build(collected, salt)

    stats: dict[str, Any] = {
        "engine": "builtin",
        "started_at": _now(),
        "full_rebuild": full_rebuild,
        "datasets": {k: len(v) for k, v in collected.items()},
        "delta_entities": len(delta_e),
        "delta_relations": len(delta_r),
        "salt_source": "env" if salt != "fraudfusion-lakehouse-v1" else "default",
    }

    if delta_e or delta_r or full_rebuild:
        store_e, store_r = ({}, {}) if full_rebuild else _read_store(output_dir)
        merged_e, merged_r = _merge_delta(store_e, store_r, delta_e, delta_r)
        _write_store(output_dir, merged_e, merged_r)
        for name, rows in collected.items():
            mark = _max_ts(rows)
            if mark:
                prev = state["watermarks"].get(name)
                state["watermarks"][name] = max(prev, mark) if prev else mark
        stats["total_entities"] = len(merged_e)
        stats["total_relations"] = len(merged_r)
    else:
        store_e, store_r = _read_store(output_dir)
        stats["total_entities"] = len(store_e)
        stats["total_relations"] = len(store_r)
        stats["note"] = "no new rows since last watermark"

    stats["finished_at"] = _now()
    state["runs"].append(stats)
    state["runs"] = state["runs"][-20:]  # bounded history
    commit_fingerprints(state)
    save_state(output_dir, state)
    log.info("kg build: %s", json.dumps(stats["datasets"]))
    return stats
