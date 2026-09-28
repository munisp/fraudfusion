"""Phone-number tenure / recycled-number risk (fail-closed telco feed adapter).

Nigerian telcos recycle released MSISDNs; a number released by the network and
reissued can still be tied to the previous owner's identity and bank accounts.
At onboarding this means a "fresh" phone number may carry inherited account
linkages — a classic vector for account takeover and identity confusion.

Mirrors the fail-closed adapter pattern of
services/python/identity-theft-detector/registry.py:

  * PhoneTenureAdapter — interface: lookup one MSISDN, return an honest dict.
  * HTTPTenureAdapter — used when TELCO_TENURE_URL is configured; calls the
    telco tenure feed. Timeout / network error / non-200 / non-JSON all fail
    CLOSED: status "unavailable" with an explicit reason, never a fabricated
    clean bill.
  * UnavailablePhoneTenureAdapter — default when TELCO_TENURE_URL is unset:
    status "unavailable". A missing feed NEVER silently passes; the assessment
    surfaces state "unverified".

Feed signals consumed (when provided): number_age_days (days since the current
subscriber activated the number), reassigned_recently (bool), and
prior_owner_linked_accounts (count of financial accounts still linked to a
previous owner, if the feed reports it).

Risk policy (documented, rules only):
  * recycled within the reassignment window (default 180 days, env
    RECYCLED_NUMBER_WINDOW_DAYS): +0.15 — the number may still resolve to the
    previous owner's identity/accounts;
  * prior_owner_linked_accounts > 0: additional +0.10 — live inherited
    account linkage observed;
  * feed unavailable: +0.05 honest-degradation contribution and state
    "unverified" (same convention as the credit-bureau adapter).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

TENURE_TIMEOUT = float(os.getenv("TELCO_TENURE_TIMEOUT_SECONDS", "5"))
DEFAULT_REASSIGNMENT_WINDOW_DAYS = int(os.getenv("RECYCLED_NUMBER_WINDOW_DAYS", "180"))

# Risk contributions (kept here so the wiring in app/main.py stays declarative).
RISK_CONTRIB_RECYCLED = 0.15
RISK_CONTRIB_PRIOR_OWNER_LINKS = 0.10
RISK_CONTRIB_UNVERIFIED = 0.05


class PhoneTenureAdapter:
    """Interface: look up one phone number, return an honest status dict."""

    name = "abstract"

    def lookup(self, phone: str) -> dict[str, Any]:
        raise NotImplementedError


class UnavailablePhoneTenureAdapter(PhoneTenureAdapter):
    """Default when no telco tenure feed is configured. Fails closed:

    status "unavailable" — the caller must surface 'unverified', never treat
    the number as confirmed clean."""

    name = "unconfigured"

    def lookup(self, phone: str) -> dict[str, Any]:
        return {
            "status": "unavailable",
            "adapter": self.name,
            "phone_checked": False,
            "reason": "telco tenure feed not configured (TELCO_TENURE_URL unset); "
                      "recycled-number risk is unverified",
        }


class HTTPTenureAdapter(PhoneTenureAdapter):
    """Calls the configured telco tenure feed (TELCO_TENURE_URL).

    Fail-closed: timeout / network error / non-200 / non-JSON body -> status
    "unavailable" with the reason. Never fabricates tenure.
    """

    name = "http_telco_tenure"

    def __init__(self, base_url: str, timeout: float = TENURE_TIMEOUT,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, transport=self._transport)

    def lookup(self, phone: str) -> dict[str, Any]:
        try:
            with self._client() as client:
                resp = client.get(f"{self.base_url}/tenure", params={"phone": phone})
        except httpx.HTTPError as exc:
            logger.error("telco tenure feed unreachable: %s", exc)
            return {
                "status": "unavailable",
                "adapter": self.name,
                "source": self.base_url,
                "phone_checked": False,
                "reason": f"tenure feed unreachable ({exc.__class__.__name__})",
            }
        if resp.status_code == 404:
            return {"status": "not_found", "adapter": self.name, "source": self.base_url,
                    "phone_checked": True, "reason": "tenure feed returned 404"}
        if resp.status_code != 200:
            return {"status": "unavailable", "adapter": self.name, "source": self.base_url,
                    "phone_checked": False,
                    "reason": f"tenure feed returned HTTP {resp.status_code}"}
        try:
            body = resp.json()
        except ValueError:
            return {"status": "unavailable", "adapter": self.name, "source": self.base_url,
                    "phone_checked": False, "reason": "tenure feed returned non-JSON body"}

        def _int_or_none(value: Any) -> Optional[int]:
            try:
                return None if value is None else int(value)
            except (TypeError, ValueError):
                return None

        return {
            "status": "ok",
            "adapter": self.name,
            "source": self.base_url,
            "phone_checked": True,
            "number_age_days": _int_or_none(body.get("number_age_days")),
            "reassigned_recently": bool(body.get("reassigned_recently")),
            "prior_owner_linked_accounts": _int_or_none(body.get("prior_owner_linked_accounts")),
        }


def get_phone_tenure_adapter() -> PhoneTenureAdapter:
    """HTTP adapter when TELCO_TENURE_URL is set, otherwise the fail-closed
    unavailable adapter. Env is read at call time so deployments/tests can
    configure it per-process."""
    url = os.getenv("TELCO_TENURE_URL", "").strip()
    if url:
        return HTTPTenureAdapter(url)
    return UnavailablePhoneTenureAdapter()


def assess_recycled_number(
    phone: Optional[str],
    adapter: PhoneTenureAdapter | None = None,
    window_days: int = DEFAULT_REASSIGNMENT_WINDOW_DAYS,
) -> dict[str, Any]:
    """Assess recycled-number risk for an onboarding phone number.

    Returns an explicit dict for the verification results:
      state: 'verified_clean' | 'recycled' | 'unverified' | 'not_provided'
      recycled_number_risk: bool — True only on positive recycled evidence
      risk_contribution: float — additive risk-score contribution
      window_days, signals, reason.

    A number is recycled-within-window when the feed says
    reassigned_recently=true, or when number_age_days <= window_days
    (boundary inclusive: activation exactly window_days ago still counts as
    recently reassigned).
    """
    if not phone:
        return {
            "state": "not_provided",
            "recycled_number_risk": False,
            "risk_contribution": 0.0,
            "window_days": window_days,
            "reason": "no phone number supplied at onboarding",
        }
    adapter = adapter or get_phone_tenure_adapter()
    result = adapter.lookup(phone)
    base = {
        "adapter": result.get("adapter"),
        "window_days": window_days,
        "recycled_number_risk": False,
        "signals": {
            "number_age_days": result.get("number_age_days"),
            "reassigned_recently": result.get("reassigned_recently"),
            "prior_owner_linked_accounts": result.get("prior_owner_linked_accounts"),
        },
    }
    if result.get("status") != "ok":
        # Fail closed: never silently pass. State is honestly 'unverified'.
        return {
            **base,
            "state": "unverified",
            "risk_contribution": RISK_CONTRIB_UNVERIFIED,
            "reason": result.get("reason", "tenure feed unavailable"),
        }

    age = result.get("number_age_days")
    recycled = bool(result.get("reassigned_recently")) or (
        age is not None and age <= window_days
    )
    contribution = 0.0
    reasons = []
    if recycled:
        contribution += RISK_CONTRIB_RECYCLED
        reasons.append(
            f"number reassigned within {window_days}d window"
            + (f" (number_age_days={age})" if age is not None else " (feed: reassigned_recently)")
        )
    linked = result.get("prior_owner_linked_accounts")
    if linked:
        contribution += RISK_CONTRIB_PRIOR_OWNER_LINKS
        reasons.append(f"prior owner still linked to {linked} account(s)")
    return {
        **base,
        "state": "recycled" if recycled else "verified_clean",
        "recycled_number_risk": recycled,
        "risk_contribution": round(contribution, 3),
        "reason": "; ".join(reasons) if reasons else "tenure feed reports no recent reassignment",
    }
