"""Credit-bureau adapter interface.

Nigerian credit bureaus (CRC Credit Bureau, FirstCentral, CreditRegistry)
require licensed API credentials. No provider is configured in this
deployment, so the default adapter reports `unavailable` honestly instead of
fabricating a score. To integrate: subclass CreditBureauAdapter, implement
`check`/`score_only` against the provider API, and register it via
CREDIT_BUREAU_ADAPTER / provider config.
"""

from __future__ import annotations

import os
from typing import Optional

KNOWN_PROVIDERS = ("crc", "firstcentral", "creditregistry")


class CreditBureauUnavailable(RuntimeError):
    def __init__(self, provider: str):
        self.provider = provider
        super().__init__(
            f"credit bureau provider '{provider}' is not configured in this deployment"
        )


class CreditBureauAdapter:
    """Interface for credit-bureau integrations."""

    name = "unconfigured"

    def check(self, bvn: str, first_name: str, last_name: str) -> dict:
        raise NotImplementedError

    def score_only(self, bvn: str, first_name: str, last_name: str) -> dict:
        raise NotImplementedError


class UnavailableCreditBureauAdapter(CreditBureauAdapter):
    """Honest default: no licensed provider integration configured."""

    name = "unavailable"

    def _unavailable(self, provider: str) -> dict:
        return {
            "provider": provider,
            "status": "unavailable",
            "detail": (
                f"No {provider} credit-bureau integration is configured "
                "(licensed API credentials absent); no credit data was retrieved"
            ),
            "score": None,
            "report": None,
        }

    def check(self, bvn: str, first_name: str, last_name: str,
              provider: str = "crc") -> dict:
        return self._unavailable(provider)

    def score_only(self, bvn: str, first_name: str, last_name: str,
                   provider: str = "crc") -> dict:
        return self._unavailable(provider)


def get_adapter() -> CreditBureauAdapter:
    # Extension point: CREDIT_BUREAU_ADAPTER="module:Class" loads a real adapter.
    spec = os.getenv("CREDIT_BUREAU_ADAPTER", "").strip()
    if spec:
        import importlib

        module_name, _, class_name = spec.partition(":")
        module = importlib.import_module(module_name)
        return getattr(module, class_name)()
    return UnavailableCreditBureauAdapter()


def validate_provider(provider: Optional[str]) -> str:
    provider = (provider or "crc").lower()
    if provider not in KNOWN_PROVIDERS:
        raise ValueError(
            f"unknown credit bureau provider {provider!r}; known: {', '.join(KNOWN_PROVIDERS)}"
        )
    return provider
