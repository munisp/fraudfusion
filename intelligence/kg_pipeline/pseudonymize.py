"""NDPA pseudonymization for KG entity identifiers.

Reuses the mlops lakehouse contract (mlops/lakehouse/export.py): salted
SHA-256, truncated to 32 hex chars, prefixed so pseudonyms are visually
distinguishable from raw ids. The salt comes from LAKEHOUSE_PII_SALT (same
env var as the lakehouse export lane) so a customer pseudonymizes to the same
value across both lanes — the KG can be joined back to lakehouse features
without ever storing raw BVN/NIN/customer ids.

Raw identifiers never enter the KG store. Entity ids are
``<kind>_<pseudonym>`` where kind is a lowercase entity label.
"""
from __future__ import annotations

import hashlib
import os

DEFAULT_SALT_ENV = "LAKEHOUSE_PII_SALT"
DEFAULT_SALT = "fraudfusion-lakehouse-v1"


def get_salt(explicit: str | None = None) -> str:
    return explicit or os.environ.get(DEFAULT_SALT_ENV, DEFAULT_SALT)


def pseudonymize(value: str, salt: str | None = None) -> str:
    """Deterministic salted SHA-256 pseudonym for a direct identifier."""
    return "pii_" + hashlib.sha256(
        f"{get_salt(salt)}:{value}".encode("utf-8")
    ).hexdigest()[:32]


def entity_id(kind: str, raw_id: object, salt: str | None = None) -> str:
    """Stable pseudonymized entity id, e.g. ``customer_pii_ab12...``."""
    return f"{kind.lower()}_{pseudonymize(str(raw_id), salt)}"
