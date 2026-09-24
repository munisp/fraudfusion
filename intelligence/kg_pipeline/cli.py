"""CLI: python -m intelligence.kg_pipeline [--engine auto|builtin|cocoindex].

Environment:
  LAKEHOUSE_DIR       source lakehouse root (default mlops/data/lakehouse,
                      matching the ml lane contract)
  KG_DIR              output KG store dir (default intelligence/data/kg)
  LAKEHOUSE_PII_SALT  pseudonymization salt (shared with mlops lakehouse)
  KG_POSTGRES_DSN     optional Postgres DSN for live source tables
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from . import cocoindex_adapter, executor


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kg_pipeline",
                                 description="Incremental KG construction from platform data")
    ap.add_argument("--lakehouse-dir", default=os.environ.get("LAKEHOUSE_DIR", "mlops/data/lakehouse"))
    ap.add_argument("--output-dir", default=os.environ.get("KG_DIR", "intelligence/data/kg"))
    ap.add_argument("--salt", default=None, help="pseudonymization salt (default: LAKEHOUSE_PII_SALT)")
    ap.add_argument("--engine", choices=["auto", "builtin", "cocoindex"], default="auto",
                    help="auto = cocoindex if installed else builtin")
    ap.add_argument("--full-rebuild", action="store_true")
    ap.add_argument("--postgres-dsn", default=os.environ.get("KG_POSTGRES_DSN"))
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s [%(name)s] %(message)s")

    engine = a.engine
    if engine == "auto":
        engine = "cocoindex" if cocoindex_adapter.available() else "builtin"
    if engine == "cocoindex":
        try:
            stats = cocoindex_adapter.run(a.lakehouse_dir, a.output_dir, a.salt,
                                          a.full_rebuild, postgres_dsn=a.postgres_dsn)
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
    else:
        stats = executor.run(a.lakehouse_dir, a.output_dir, a.salt,
                             a.full_rebuild, postgres_dsn=a.postgres_dsn)
    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
