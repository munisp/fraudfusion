"""CLI: python -m intelligence.kg_load --target falkordb|neo4j --kg-dir ..."""
from __future__ import annotations

import argparse
import json
import os
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kg_load",
                                 description="Load the parquet KG store into a graph server")
    ap.add_argument("--kg-dir", default=os.environ.get("KG_DIR", "intelligence/data/kg"))
    ap.add_argument("--target", choices=["falkordb", "neo4j"], required=True)
    a = ap.parse_args(argv)
    if a.target == "falkordb":
        from . import falkordb_load
        stats = falkordb_load.load(a.kg_dir)
    else:
        from . import neo4j_load
        stats = neo4j_load.load(a.kg_dir)
    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
