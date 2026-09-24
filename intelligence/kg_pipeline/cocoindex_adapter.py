"""Optional cocoindex engine adapter for the KG pipeline.

cocoindex (https://cocoindex.io) provides an incremental/memoizing execution
engine. When the package is importable, the per-dataset transform
(builder.build) is executed through cocoindex's `@cocoindex.fn` function
runtime (memoized, versioned), and the resulting subgraph is sunk into the
same parquet store layout (entities.parquet / relations.parquet) the built-in
executor writes — stores are interchangeable between engines.

Honest version note: cocoindex 1.0.x replaced the 0.x declarative "flow +
target spec" API (`cocoindex.op.function`, `FlowDef`, target connectors)
with a component/target-mount runtime. This adapter detects what the
installed version actually provides:
  * >=1.0: transforms run through `@cocoindex.fn`; the custom target is an
    imperative parquet sink (executor._merge_delta/_write_store), because the
    0.x target-connector API no longer exists. Documented, not faked.
  * 0.x (classic): same transforms via `cocoindex.op.function`.
  * not installed: available() is False and run() raises a clear error;
    `--engine auto` falls back to the built-in executor.

Watermark state stays authoritative in executor `.kg_state.json` for both
engines (cocoindex's internal trackers are not used for lakehouse parquet,
whose change unit is the hive partition).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import executor


def available() -> bool:
    try:
        import cocoindex  # noqa: F401
        return True
    except ImportError:
        return False


def version() -> str | None:
    try:
        import importlib.metadata
        return importlib.metadata.version("cocoindex")
    except Exception:  # noqa: BLE001
        return None


def _make_transforms(salt: str | None):
    """Build the dataset->subgraph transform through cocoindex's function
    runtime, using whichever API generation is installed."""
    import cocoindex  # type: ignore

    from . import builder

    def transform(dataset: str, rows: list[dict]) -> dict:
        ents, rels = builder.build({dataset: rows}, salt)
        return {"entities": ents, "relations": rels}

    if hasattr(cocoindex, "fn"):           # cocoindex >= 1.0
        return cocoindex.fn(memo=True)(transform)
    if hasattr(cocoindex, "op") and hasattr(cocoindex.op, "function"):  # 0.x
        return cocoindex.op.function()(transform)
    raise RuntimeError(
        f"installed cocoindex {version() or '?'} exposes neither the 1.x "
        "`fn` runtime nor the 0.x `op.function` API; use --engine builtin.")


def run(lakehouse_dir: str | Path, output_dir: str | Path,
        salt: str | None = None, full_rebuild: bool = False,
        datasets: tuple[str, ...] | None = None,
        postgres_dsn: str | None = None) -> dict[str, Any]:
    """Run the KG build through the cocoindex engine (custom parquet target)."""
    if not available():
        raise RuntimeError(
            "cocoindex engine requested but the package is not installed. "
            "Install it (`pip install cocoindex`) or run with "
            "--engine builtin (the default executor has identical semantics).")

    from . import schema, sources

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    transform = _make_transforms(salt)

    state = executor.load_state(out)
    if state.get("schema_version") != schema.KG_SCHEMA_VERSION and not full_rebuild:
        raise RuntimeError(
            f"KG store at {out} has schema_version="
            f"{state.get('schema_version')!r}, pipeline expects "
            f"{schema.KG_SCHEMA_VERSION!r}. Re-run with full_rebuild=True.")
    if full_rebuild:
        state = {"schema_version": schema.KG_SCHEMA_VERSION, "watermarks": {}, "runs": []}
        for f in (schema.ENTITIES_FILE, schema.RELATIONS_FILE):
            p = out / f
            if p.exists():
                p.unlink()

    collected: dict[str, list[dict]] = {}
    for name in datasets or schema.DATASETS:
        rows = executor.filter_incremental(sources.read_dataset(lakehouse_dir, name),
                                           name, state)
        if rows:
            collected[name] = rows
    if postgres_dsn:
        pg = sources.read_postgres(postgres_dsn,
                                   since={k: v for k, v in state["watermarks"].items() if v})
        for name, rows in pg.items():
            collected.setdefault(name, []).extend(rows)

    entities: list[dict] = []
    relations: list[dict] = []
    for name, rows in collected.items():
        sub = transform(name, rows)  # executed via cocoindex runtime
        entities.extend(sub["entities"])
        relations.extend(sub["relations"])

    # Custom target sink: MERGE into the parquet store (identical to builtin).
    store_e, store_r = ([], []) if full_rebuild else executor._read_store(out)
    merged_e, merged_r = executor._merge_delta(store_e, store_r, entities, relations)
    if entities or relations or full_rebuild:
        executor._write_store(out, merged_e, merged_r)

    for name, rows in collected.items():
        mark = executor._max_ts(rows)
        if mark:
            prev = state["watermarks"].get(name)
            state["watermarks"][name] = max(prev, mark) if prev else mark
    stats = {
        "engine": f"cocoindex-{version() or 'unknown'}",
        "datasets": {k: len(v) for k, v in collected.items()},
        "delta_entities": len(entities),
        "delta_relations": len(relations),
        "total_entities": len(merged_e),
        "total_relations": len(merged_r),
        "full_rebuild": full_rebuild,
    }
    state["runs"].append(stats)
    state["runs"] = state["runs"][-20:]
    executor.commit_fingerprints(state)
    executor.save_state(out, state)
    return stats
