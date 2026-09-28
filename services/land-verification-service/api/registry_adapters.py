"""Lands registry adapter interface for the land-verification-service.

Adapters (selected per-state by `get_lands_adapter`):
  * HttpLandsRegistryAdapter      — when the state lands-registry endpoint is
                                    configured (LAGOS_LANDS_URL, FCT_LANDS_URL,
                                    RIVERS_LANDS_URL, OGUN_LANDS_URL,
                                    KANO_LANDS_URL). Fail-closed: errors return
                                    status "unavailable" with the reason.
  * FileImportLandsRegistryAdapter — fallback backed by the
                                    lands_registry_records table (rows carry a
                                    `provenance` field identifying the import
                                    file / feed they came from).

Every result carries `source` and `provenance` so callers can see exactly
where a claim about a parcel came from.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx

from api.data_store import LandDataStore, get_land_store

logger = logging.getLogger(__name__)

REGISTRY_TIMEOUT = float(os.getenv("REGISTRY_TIMEOUT_SECONDS", "5"))

STATE_ENV = {
    "lagos": "LAGOS_LANDS_URL",
    "fct": "FCT_LANDS_URL",
    "rivers": "RIVERS_LANDS_URL",
    "ogun": "OGUN_LANDS_URL",
    "kano": "KANO_LANDS_URL",
}


class LandsRegistryAdapter:
    """Interface for state lands registries."""

    name = "abstract"

    def owner(self, *, state: str, certificate_number: Optional[str] = None,
              property_address: Optional[str] = None,
              tenant_id: str = "default") -> dict[str, Any]:
        raise NotImplementedError

    def history(self, *, state: str, certificate_number: Optional[str] = None,
                property_address: Optional[str] = None,
                tenant_id: str = "default") -> dict[str, Any]:
        raise NotImplementedError


class FileImportLandsRegistryAdapter(LandsRegistryAdapter):
    """Reads lands_registry_records populated by file imports (provenance-
    tracked). Returns empty/unavailable honestly when nothing was imported."""

    name = "file_import"

    def __init__(self, store: LandDataStore | None = None):
        self.store = store or get_land_store()

    def _rows(self, state: str, certificate_number: Optional[str],
              property_address: Optional[str], tenant_id: str) -> list[dict[str, Any]]:
        if certificate_number:
            return self.store.query(
                "SELECT * FROM lands_registry_records WHERE tenant_id = :t AND lower(state) = lower(:s)"
                " AND certificate_number = :c ORDER BY transfer_date, imported_at",
                {"t": tenant_id, "s": state, "c": certificate_number},
            )
        if property_address:
            return self.store.query(
                "SELECT * FROM lands_registry_records WHERE tenant_id = :t AND lower(state) = lower(:s)"
                " AND lower(property_address) = lower(:a) ORDER BY transfer_date, imported_at",
                {"t": tenant_id, "s": state, "a": property_address},
            )
        return []

    def owner(self, *, state: str, certificate_number: Optional[str] = None,
              property_address: Optional[str] = None,
              tenant_id: str = "default") -> dict[str, Any]:
        rows = [r for r in self._rows(state, certificate_number, property_address, tenant_id)
                if r.get("status") == "active"]
        if not rows:
            return {"status": "not_found", "source": "lands_registry_records",
                    "provenance": None,
                    "reason": "no active registry record (import the state registry extract)"}
        latest = rows[-1]
        return {
            "status": "found",
            "source": "lands_registry_records",
            "provenance": latest["provenance"],
            "name": latest["owner_name"],
            "certificate_number": latest["certificate_number"],
            "state": latest["state"],
            "plot_number": latest["plot_number"],
            "is_synthetic": latest["provenance"] == "seed-synthetic",
        }

    def history(self, *, state: str, certificate_number: Optional[str] = None,
                property_address: Optional[str] = None,
                tenant_id: str = "default") -> dict[str, Any]:
        rows = self._rows(state, certificate_number, property_address, tenant_id)
        records = [
            {
                "owner": r["owner_name"],
                "start_date": r.get("transfer_date") or r["imported_at"],
                "end_date": None,
                "transfer_type": r.get("transfer_type") or "registration",
                "document_ref": r.get("certificate_number"),
                "verified": True,
                "provenance": r["provenance"],
            }
            for r in rows
        ]
        return {
            "status": "ok",
            "source": "lands_registry_records",
            "ownership_history": records,
        }


class HttpLandsRegistryAdapter(LandsRegistryAdapter):
    """Calls the configured state lands-registry HTTP API. Fails closed."""

    name = "http_lands_registry"

    def __init__(self, base_url: str, timeout: float = REGISTRY_TIMEOUT,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def _get(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
                resp = client.get(f"{self.base_url}{path}", params=params)
        except httpx.HTTPError as exc:
            logger.error("lands registry %s unreachable: %s", self.base_url, exc)
            return {"status": "unavailable", "source": self.base_url,
                    "reason": f"registry endpoint unreachable ({exc.__class__.__name__})"}
        if resp.status_code == 404:
            return {"status": "not_found", "source": self.base_url,
                    "reason": "registry returned 404"}
        if resp.status_code != 200:
            return {"status": "unavailable", "source": self.base_url,
                    "reason": f"registry returned HTTP {resp.status_code}"}
        try:
            body = resp.json()
        except ValueError:
            return {"status": "unavailable", "source": self.base_url,
                    "reason": "registry returned non-JSON body"}
        return dict(body, status=body.get("status", "found"), source=self.base_url)

    def owner(self, *, state: str, certificate_number: Optional[str] = None,
              property_address: Optional[str] = None,
              tenant_id: str = "default") -> dict[str, Any]:
        params = {"state": state}
        if certificate_number:
            params["certificate_number"] = certificate_number
        if property_address:
            params["property_address"] = property_address
        return self._get("/owner", params)

    def history(self, *, state: str, certificate_number: Optional[str] = None,
                property_address: Optional[str] = None,
                tenant_id: str = "default") -> dict[str, Any]:
        params = {"state": state}
        if certificate_number:
            params["certificate_number"] = certificate_number
        if property_address:
            params["property_address"] = property_address
        result = self._get("/history", params)
        if result.get("status") in ("found", "ok"):
            result.setdefault("ownership_history", result.get("records", []))
        return result


def get_lands_adapter(state: str, store: LandDataStore | None = None) -> LandsRegistryAdapter:
    """HTTP adapter when the state URL is configured, else the file-import
    fallback backed by lands_registry_records (provenance-tracked)."""
    url = os.getenv(STATE_ENV.get(state.lower(), ""), "").strip()
    if url:
        return HttpLandsRegistryAdapter(url)
    return FileImportLandsRegistryAdapter(store)


def registry_health() -> dict[str, str]:
    configured = {state: os.getenv(env, "").strip()
                  for state, env in STATE_ENV.items()}
    return {
        "http_registries_configured": ",".join(s for s, u in configured.items() if u) or "none",
        "fallback": "file_import (lands_registry_records, provenance-tracked)",
    }
