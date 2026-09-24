"""Minimal FalkorDB client over the Redis protocol (redis-py).

FalkorDB speaks the Redis wire protocol and exposes openCypher via the
``GRAPH.QUERY`` / ``GRAPH.RO_QUERY`` module commands, so a full client is a
thin wrapper around redis-py — no bolt driver, no falkordb SDK required.

The ``redis`` package is OPTIONAL: importing this module never fails;
constructing/connecting a client raises a clear RuntimeError if redis-py is
missing or the server is unreachable. ``available()`` lets callers feature-
detect without try/except.

Env:
  FALKOR_HOST  localhost (default)
  FALKOR_PORT  6379 (default)
  FALKOR_GRAPH fraudfusion (default graph key)

Local server: docker compose -f ml/graph/falkor.compose.yml up -d
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _import_redis():
    try:
        import redis  # type: ignore
        return redis
    except ImportError:
        return None


def available() -> bool:
    """True if redis-py is installed AND a FalkorDB server answers PING."""
    redis = _import_redis()
    if redis is None:
        return False
    try:
        c = redis.Redis(host=os.environ.get("FALKOR_HOST", "localhost"),
                        port=int(os.environ.get("FALKOR_PORT", "6379")),
                        socket_connect_timeout=2, socket_timeout=2)
        return bool(c.ping())
    except Exception:  # noqa: BLE001 - any connection failure => unavailable
        return False


@dataclass
class FalkorClient:
    """Thin GRAPH.QUERY wrapper. Raises RuntimeError on unavailability —
    never silently fakes results."""
    host: str = field(default_factory=lambda: os.environ.get("FALKOR_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.environ.get("FALKOR_PORT", "6379")))
    graph: str = field(default_factory=lambda: os.environ.get("FALKOR_GRAPH", "fraudfusion"))

    def __post_init__(self):
        redis = _import_redis()
        if redis is None:
            raise RuntimeError(
                "redis-py not installed: `pip install redis` "
                "(FalkorDB speaks the Redis protocol; no other driver needed).")
        self._r = redis.Redis(host=self.host, port=self.port,
                              socket_connect_timeout=3, decode_responses=True)
        try:
            self._r.ping()
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"cannot reach FalkorDB at {self.host}:{self.port}: {e}. "
                f"Start one with: docker compose -f ml/graph/falkor.compose.yml up -d") from e

    def query(self, cypher: str, params: dict | None = None,
              read_only: bool = False) -> list[list]:
        """Run a Cypher statement; returns the result-set rows (list of lists
        of raw FalkorDB-typed values). Parameterised via CYPHER prelude."""
        if params:
            prelude = "CYPHER " + " ".join(
                f"{k}={self._literal(v)}" for k, v in params.items()) + " "
            cypher = prelude + cypher
        cmd = "GRAPH.RO_QUERY" if read_only else "GRAPH.QUERY"
        res = self._r.execute_command(cmd, self.graph, cypher)
        # FalkorDB reply: [header, rows, stats] — rows is element 1
        if isinstance(res, list) and len(res) >= 2 and isinstance(res[1], list):
            return res[1]
        return []

    def delete_graph(self) -> None:
        self._r.execute_command("GRAPH.DELETE", self.graph)

    @staticmethod
    def _literal(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return repr(v)
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'
