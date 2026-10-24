"""Fail-closed HTTP adapters for Nigerian live registries (Round 10, Lane R).

Follows services/python/identity-theft-detector/registry.py exactly: env-based
selection, timeout/non-200/malformed -> status "unavailable" WITH THE REASON,
adapter+source provenance on every result, NOTHING fabricated.

These adapters are PLUG-READY: the NIBSS/NIMC/CAC contracts are procurement
steps outside the code. Point the env URLs at the live services (or at the
developer sandbox's registry doubles for an end-to-end dry run) and the same
codepath activates. No credentials -> honest unavailable, always.

  NIBSS_BVN_URL / NIBSS_BVN_TOKEN   BVN lookup (NIBSS)
  NIMC_API_URL   / NIMC_API_TOKEN   NIN verification (NIMC)
  CAC_API_URL    / CAC_API_TOKEN    CAC public company search

Transport is injectable for the conformance harness (MockTransport).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

REGISTRY_TIMEOUT = float(os.getenv("REGISTRY_TIMEOUT_SECONDS", "10"))


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


class RegistryHTTPAdapter:
    """Base: availability honesty + GET-with-token plumbing."""

    name = "abstract_registry"
    url_env = ""
    token_env = ""

    def __init__(self, transport: Optional[httpx.BaseTransport] = None):
        self.base_url = _env(self.url_env).rstrip("/")
        self.token = _env(self.token_env)
        self._transport = transport

    @property
    def available(self) -> bool:
        return bool(self.base_url)

    @property
    def unavailable_reason(self) -> Optional[str]:
        if self.available:
            return None
        return f"{self.url_env} not configured"

    def availability(self) -> dict[str, Any]:
        return {"adapter": self.name, "available": self.available,
                "reason": None if self.available else self.unavailable_reason}

    def _get(self, path: str, params: dict[str, str]) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        with httpx.Client(timeout=REGISTRY_TIMEOUT,
                          transport=self._transport) as client:
            return client.get(f"{self.base_url}{path}", params=params,
                              headers=headers)

    def _unavailable(self, reason: str, **extra: Any) -> dict[str, Any]:
        return {"status": "unavailable", "adapter": self.name,
                "source": self.base_url or None, "reason": reason, **extra}

    def _parse(self, resp: httpx.Response) -> dict[str, Any] | None:
        """Shared response handling; returns None to continue, else a result."""
        if resp.status_code == 404:
            return {"status": "not_found", "adapter": self.name,
                    "source": self.base_url, "reason": "registry returned 404"}
        if resp.status_code != 200:
            return self._unavailable(f"registry returned HTTP {resp.status_code}")
        try:
            resp.json()
        except ValueError:
            return self._unavailable("registry returned non-JSON body")
        return None


class NibssBvnAdapter(RegistryHTTPAdapter):
    name = "nibss_bvn"
    url_env = "NIBSS_BVN_URL"
    token_env = "NIBSS_BVN_TOKEN"

    def verify_bvn(self, bvn: str) -> dict[str, Any]:
        if not self.available:
            return self._unavailable(self.unavailable_reason or "unconfigured")
        try:
            resp = self._get("/bvn/verify", {"bvn": bvn})
        except httpx.HTTPError as exc:
            logger.error("NIBSS BVN registry unreachable: %s", exc)
            return self._unavailable(
                f"registry endpoint unreachable ({exc.__class__.__name__})")
        early = self._parse(resp)
        if early is not None:
            return early
        body = resp.json()
        return {"status": "verified" if body.get("match") else "mismatch",
                "adapter": self.name, "source": self.base_url,
                "verified_fields": body.get("verified_fields", []),
                "registry_reference": body.get("reference")}


class NimcNinAdapter(RegistryHTTPAdapter):
    name = "nimc_nin"
    url_env = "NIMC_API_URL"
    token_env = "NIMC_API_TOKEN"

    def verify_nin(self, nin: str) -> dict[str, Any]:
        if not self.available:
            return self._unavailable(self.unavailable_reason or "unconfigured")
        try:
            resp = self._get("/nin/verify", {"nin": nin})
        except httpx.HTTPError as exc:
            logger.error("NIMC registry unreachable: %s", exc)
            return self._unavailable(
                f"registry endpoint unreachable ({exc.__class__.__name__})")
        early = self._parse(resp)
        if early is not None:
            return early
        body = resp.json()
        return {"status": "verified" if body.get("match") else "mismatch",
                "adapter": self.name, "source": self.base_url,
                "verified_fields": body.get("verified_fields", []),
                "registry_reference": body.get("reference")}


class CacRegistryAdapter(RegistryHTTPAdapter):
    name = "cac_public"
    url_env = "CAC_API_URL"
    token_env = "CAC_API_TOKEN"

    def lookup_company(self, rc_number: str) -> dict[str, Any]:
        if not self.available:
            return self._unavailable(self.unavailable_reason or "unconfigured")
        try:
            resp = self._get("/company/lookup", {"rc": rc_number})
        except httpx.HTTPError as exc:
            logger.error("CAC registry unreachable: %s", exc)
            return self._unavailable(
                f"registry endpoint unreachable ({exc.__class__.__name__})")
        early = self._parse(resp)
        if early is not None:
            return early
        body = resp.json()
        company = body.get("company")
        if not company:
            return {"status": "not_found", "adapter": self.name,
                    "source": self.base_url,
                    "reason": "registry returned no company record"}
        return {"status": "found", "adapter": self.name,
                "source": self.base_url,
                "company": {
                    "rc_number": company.get("rc_number"),
                    "name": company.get("name"),
                    "status": company.get("status"),
                    "registration_date": company.get("registration_date"),
                }}


# --- env-based selection (call-time, so env changes take effect) -----------

def get_bvn_adapter(transport: Optional[httpx.BaseTransport] = None) -> NibssBvnAdapter:
    return NibssBvnAdapter(transport=transport)


def get_nin_adapter(transport: Optional[httpx.BaseTransport] = None) -> NimcNinAdapter:
    return NimcNinAdapter(transport=transport)


def get_cac_adapter(transport: Optional[httpx.BaseTransport] = None) -> CacRegistryAdapter:
    return CacRegistryAdapter(transport=transport)
