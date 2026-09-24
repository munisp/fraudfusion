"""Shared helpers for KG loaders: read the parquet store, batch rows, escape
Cypher string literals for servers without parameter support (FalkorDB via
raw GRAPH.QUERY)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

BATCH = 2000


def read_store(kg_dir: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    import pandas as pd
    base = Path(kg_dir)
    e_file, r_file = base / "entities.parquet", base / "relations.parquet"
    if not e_file.exists():
        raise FileNotFoundError(
            f"no KG store at {base} — run `python -m intelligence.kg_pipeline` first")
    entities = pd.read_parquet(e_file).to_dict("records")
    relations = pd.read_parquet(r_file).to_dict("records") if r_file.exists() else []
    # normalize NaN -> None
    import math
    def clean(rows):
        out = []
        for r in rows:
            out.append({k: (None if (isinstance(v, float) and math.isnan(v)) else v)
                        for k, v in r.items()})
        return out
    return clean(entities), clean(relations)


def batches(rows: list[dict[str, Any]], size: int = BATCH):
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def cypher_str(value: Any) -> str:
    """Escape a value as a Cypher string literal (null-safe)."""
    if value is None:
        return "null"
    s = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{s}'"


def props_literal(props_json: str | None) -> str:
    """Render the entity/relation props JSON as a Cypher map literal."""
    props = json.loads(props_json) if props_json else {}
    if not props:
        return "{}"
    parts = []
    for k, v in sorted(props.items()):
        key = k.replace("`", "")
        if v is None:
            continue
        if isinstance(v, bool):
            parts.append(f"`{key}`: {'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            parts.append(f"`{key}`: {v}")
        else:
            parts.append(f"`{key}`: {cypher_str(v)}")
    return "{" + ", ".join(parts) + "}" if parts else "{}"
