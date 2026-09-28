"""Registry adapter interface for BVN/NIN verification.

Adapters:
  * LocalRegistryAdapter — backed by the bvn_registry / nin_registry tables
    (seeded with clearly-marked SYNTHETIC rows; populated in production by the
    admin CSV import endpoint POST /admin/registry/import).
  * HTTPRegistryAdapter — used when the real NIBSS (BVN) / NIMC (NIN)
    endpoints are configured via BVN_REGISTRY_URL / NIN_REGISTRY_URL. Network
    failures fail CLOSED: status "unavailable" with an explicit reason, never
    a fabricated match.

Adapter selection (get_bvn_adapter / get_nin_adapter): HTTP when the env URL
is set, otherwise local. Every result carries `adapter` and `source` so
callers can see exactly which registry answered.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx

from identity_store import IdentityStore, get_store

logger = logging.getLogger(__name__)

BVN_REGISTRY_URL = os.getenv("BVN_REGISTRY_URL", "").strip()
NIN_REGISTRY_URL = os.getenv("NIN_REGISTRY_URL", "").strip()
REGISTRY_TIMEOUT = float(os.getenv("REGISTRY_TIMEOUT_SECONDS", "5"))


class RegistryAdapter:
    """Interface: lookup one identifier, return an honest status dict."""

    name = "abstract"
    id_type = ""  # 'bvn' | 'nin'

    def lookup(self, id_value: str, tenant_id: str = "default") -> dict[str, Any]:
        raise NotImplementedError

    def search_by_contact(self, *, phone: Optional[str] = None,
                          email: Optional[str] = None,
                          tenant_id: str = "default") -> list[dict[str, Any]]:
        """Reverse lookup used by cross-reference clustering."""
        raise NotImplementedError


class LocalRegistryAdapter(RegistryAdapter):
    """Backed by the local bvn_registry / nin_registry tables."""

    def __init__(self, id_type: str, store: IdentityStore | None = None):
        assert id_type in ("bvn", "nin")
        self.id_type = id_type
        self.name = f"local_{id_type}_registry"
        self.table = f"{id_type}_registry"
        self.store = store or get_store()

    def lookup(self, id_value: str, tenant_id: str = "default") -> dict[str, Any]:
        row = self.store.query_one(
            f"SELECT {self.id_type} AS id_value, full_name, date_of_birth, phone_number, email,"
            f" is_synthetic, provenance FROM {self.table}"
            f" WHERE tenant_id = :t AND {self.id_type} = :v",
            {"t": tenant_id, "v": id_value},
        )
        if not row:
            return {
                "status": "not_found",
                "adapter": self.name,
                "source": self.table,
                "reason": f"{self.id_type.upper()} not present in local registry",
            }
        return {
            "status": "found",
            "adapter": self.name,
            "source": self.table,
            "is_synthetic": bool(row["is_synthetic"]),
            "record": {
                "full_name": row["full_name"],
                "date_of_birth": row["date_of_birth"],
                "phone_number": row["phone_number"],
                "email": row["email"],
                "provenance": row["provenance"],
            },
        }

    def search_by_contact(self, *, phone: Optional[str] = None,
                          email: Optional[str] = None,
                          tenant_id: str = "default") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if phone:
            rows += self.store.query(
                f"SELECT {self.id_type} AS id_value, full_name, phone_number, email, is_synthetic"
                f" FROM {self.table} WHERE tenant_id = :t AND phone_number = :v",
                {"t": tenant_id, "v": phone},
            )
        if email:
            rows += self.store.query(
                f"SELECT {self.id_type} AS id_value, full_name, phone_number, email, is_synthetic"
                f" FROM {self.table} WHERE tenant_id = :t AND email = :v",
                {"t": tenant_id, "v": email},
            )
        for r in rows:
            r["adapter"] = self.name
            r["source"] = self.table
            r["is_synthetic"] = bool(r["is_synthetic"])
        return rows


class HTTPRegistryAdapter(RegistryAdapter):
    """Calls the configured NIBSS (BVN) or NIMC (NIN) HTTP endpoint.

    Fail-closed: timeout / network error / non-200 -> status "unavailable"
    with the reason. Never fabricates a match.
    """

    def __init__(self, id_type: str, base_url: str, timeout: float = REGISTRY_TIMEOUT,
                 transport: httpx.BaseTransport | None = None):
        assert id_type in ("bvn", "nin")
        self.id_type = id_type
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.name = f"http_{id_type}_registry"
        self._transport = transport

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, transport=self._transport)

    def lookup(self, id_value: str, tenant_id: str = "default") -> dict[str, Any]:
        try:
            with self._client() as client:
                resp = client.get(
                    f"{self.base_url}/lookup",
                    params={self.id_type: id_value},
                    headers={"X-Tenant-Id": tenant_id},
                )
        except httpx.HTTPError as exc:
            logger.error("%s registry unreachable: %s", self.name, exc)
            return {
                "status": "unavailable",
                "adapter": self.name,
                "source": self.base_url,
                "reason": f"registry endpoint unreachable ({exc.__class__.__name__})",
            }
        if resp.status_code == 404:
            return {"status": "not_found", "adapter": self.name, "source": self.base_url,
                    "reason": "registry returned 404"}
        if resp.status_code != 200:
            return {"status": "unavailable", "adapter": self.name, "source": self.base_url,
                    "reason": f"registry returned HTTP {resp.status_code}"}
        try:
            body = resp.json()
        except ValueError:
            return {"status": "unavailable", "adapter": self.name, "source": self.base_url,
                    "reason": "registry returned non-JSON body"}
        return {
            "status": "found" if body.get("found") else "not_found",
            "adapter": self.name,
            "source": self.base_url,
            "is_synthetic": False,
            "record": body.get("record"),
        }

    def search_by_contact(self, *, phone: Optional[str] = None,
                          email: Optional[str] = None,
                          tenant_id: str = "default") -> list[dict[str, Any]]:
        if not phone and not email:
            return []
        try:
            with self._client() as client:
                resp = client.get(
                    f"{self.base_url}/search",
                    params={k: v for k, v in (("phone", phone), ("email", email)) if v},
                    headers={"X-Tenant-Id": tenant_id},
                )
            if resp.status_code != 200:
                logger.error("%s search returned HTTP %s", self.name, resp.status_code)
                return []
            return [dict(r, adapter=self.name, source=self.base_url) for r in resp.json().get("records", [])]
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("%s search failed closed: %s", self.name, exc)
            return []


def get_bvn_adapter(store: IdentityStore | None = None) -> RegistryAdapter:
    if BVN_REGISTRY_URL:
        return HTTPRegistryAdapter("bvn", BVN_REGISTRY_URL)
    return LocalRegistryAdapter("bvn", store)


def get_nin_adapter(store: IdentityStore | None = None) -> RegistryAdapter:
    if NIN_REGISTRY_URL:
        return HTTPRegistryAdapter("nin", NIN_REGISTRY_URL)
    return LocalRegistryAdapter("nin", store)
