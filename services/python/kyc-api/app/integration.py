"""Bootstrap for the shared service-mesh integration package.

Follows the docverification.py pattern exactly: services/python/integration
is appended to sys.path from INTEGRATION_PATH (or the repo-relative
default); if it is absent, INTEGRATION_AVAILABLE is False and every
cross-service enrichment degrades honestly — nothing is fabricated.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "integration"
_path = os.environ.get("INTEGRATION_PATH", str(_DEFAULT_PATH)).strip()

try:
    if _path and os.path.isdir(_path) and _path not in sys.path:
        sys.path.append(_path)
    import flows as _flows  # noqa: E402
    import mesh as _mesh  # noqa: E402

    mesh = _mesh
    flows = _flows
    INTEGRATION_AVAILABLE = True
    INTEGRATION_UNAVAILABLE_REASON = None
except ImportError as exc:  # pragma: no cover
    mesh = flows = None
    INTEGRATION_AVAILABLE = False
    INTEGRATION_UNAVAILABLE_REASON = (
        f"integration package not importable ({exc}); expected at {_path} "
        "or INTEGRATION_PATH")


def fresh_mesh(transport=None) -> "object | None":
    """A new Mesh reading current env (tests re-point URLs per case)."""
    if not INTEGRATION_AVAILABLE:
        return None
    return mesh.Mesh(transport=transport)
