"""FraudFusion Python SDK — synchronous httpx client.

Auth model: every request carries ``X-API-Key: ffk_live_...`` (live) or
``ffk_test_...`` (test/sandbox). Keys are issued via the onboarding portal /
billing-service and are tenant-scoped.

Retry semantics: 429 and 5xx responses (and transport-level connection
errors) are retried up to ``max_retries`` times (default 3) with exponential
backoff + full jitter; a server-supplied ``Retry-After`` header on 429 is
honoured when it exceeds the computed backoff.

Idempotency: every POST automatically carries an ``Idempotency-Key`` header
(random UUID) unless you pass ``idempotency_key=...`` (to replay a key
deliberately) or ``idempotency_key=False`` (to opt out). The kyc-api verify
endpoints replay the first response for 24h on a repeated key and return
409 on same-key-different-payload.
"""

from __future__ import annotations

import base64
import binascii
import random
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Optional, Union

import httpx

from .exceptions import FraudFusionError, error_for_status

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_DELAY = 0.5  # seconds; attempt i waits ~base * 2**i + jitter

# The sandbox service (services/python/sandbox) mirrors the data-plane shapes
# with deterministic synthetic fixtures; it accepts only ffk_test_ keys.
SANDBOX_BASE_URL = "http://localhost:8091"
# There is no single canonical production host in the repo (services are
# fronted by the deployment's ingress); pass base_url explicitly for live.
DEFAULT_BASE_URL = SANDBOX_BASE_URL

USER_AGENT = "fraudfusion-python/0.1.0"

FileLike = Union[bytes, BinaryIO, str, Path]

_KYC_LEVELS = ("basic", "enhanced", "premium")


def new_idempotency_key() -> str:
    """Generate a fresh Idempotency-Key (UUID4 hex)."""
    return uuid.uuid4().hex


class FraudFusionClient:
    """Synchronous FraudFusion API client.

    Parameters
    ----------
    api_key:        ``ffk_live_...`` or ``ffk_test_...`` key (X-API-Key header).
    base_url:       Deployment base URL. Defaults to the local sandbox
                    (http://localhost:8091) — pass your live gateway URL for
                    production.
    timeout:        Per-request timeout in seconds.
    max_retries:    Number of RETRIES (not total attempts) on 429/5xx and
                    connection errors. Default 3.
    retry_base_delay:
                    Base for exponential backoff with jitter (seconds).
    auto_idempotency:
                    Automatically attach a fresh Idempotency-Key to POST
                    requests (default True).
    transport:      Optional httpx transport (used by tests with
                    httpx.MockTransport).
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_base_delay: float = DEFAULT_RETRY_BASE_DELAY,
        auto_idempotency: bool = True,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        if not api_key or not isinstance(api_key, str):
            raise ValueError("api_key is required (ffk_live_... or ffk_test_...)")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.max_retries = max(0, int(max_retries))
        self.retry_base_delay = float(retry_base_delay)
        self.auto_idempotency = auto_idempotency
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            headers={
                "X-API-Key": api_key,
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "FraudFusionClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # core request machinery
    # ------------------------------------------------------------------
    def _backoff_delay(self, attempt: int, retry_after: Optional[float]) -> float:
        """Exponential backoff with full jitter; honours Retry-After."""
        cap = self.retry_base_delay * (2 ** attempt)
        delay = random.uniform(0.0, cap) if cap > 0 else 0.0
        if retry_after is not None and retry_after > delay:
            delay = retry_after
        return delay

    @staticmethod
    def _retry_after_seconds(response: httpx.Response) -> Optional[float]:
        raw = response.headers.get("Retry-After")
        if raw is None:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            return None

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Optional[dict[str, Any]] = None,
        files: Optional[dict[str, Any]] = None,
        form: Optional[dict[str, Any]] = None,
        idempotency_key: Union[str, bool, None] = None,
    ) -> Any:
        headers: dict[str, str] = {}
        if method.upper() == "POST":
            if isinstance(idempotency_key, str):
                headers["Idempotency-Key"] = idempotency_key
            elif idempotency_key is not False and self.auto_idempotency:
                headers["Idempotency-Key"] = new_idempotency_key()

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.request(
                    method,
                    path,
                    json=json_body,
                    params=params,
                    files=files,
                    data=form,
                    headers=headers,
                )
            except httpx.TransportError as exc:
                # Connection-level failure: safe to retry (idempotency key
                # protects mutating endpoints against double-application).
                last_error = exc
                if attempt < self.max_retries:
                    time.sleep(self._backoff_delay(attempt, None))
                    continue
                raise FraudFusionError(
                    f"connection to {self.base_url} failed after "
                    f"{self.max_retries + 1} attempts: {exc}") from exc

            if response.status_code < 400:
                if not response.content:
                    return None
                ctype = response.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    return response.json()
                return response.text

            retryable = response.status_code == 429 or response.status_code >= 500
            if retryable and attempt < self.max_retries:
                time.sleep(self._backoff_delay(attempt, self._retry_after_seconds(response)))
                continue

            try:
                body: Any = response.json()
            except ValueError:
                body = {"detail": response.text[:500]}
            raise error_for_status(response.status_code, body)

        # Unreachable, but keeps type-checkers honest.
        raise FraudFusionError(f"request to {path} failed: {last_error}")

    @staticmethod
    def _drop_none(payload: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in payload.items() if v is not None}

    # ------------------------------------------------------------------
    # KYC (kyc-api)
    # ------------------------------------------------------------------
    def kyc_verify(
        self,
        *,
        customer_id: str,
        first_name: str,
        last_name: str,
        level: str = "basic",
        bvn: Optional[str] = None,
        nin: Optional[str] = None,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        date_of_birth: Optional[str] = None,
        address_evidence: Optional[dict[str, str]] = None,
        check_pep: Optional[bool] = None,
        check_sanctions: Optional[bool] = None,
        nationality: Optional[str] = None,
        check_credit_bureau: Optional[bool] = None,
        credit_bureau_provider: Optional[str] = None,
        idempotency_key: Union[str, bool, None] = None,
    ) -> dict[str, Any]:
        """Run a KYC verification: POST /api/v1/kyc/verify/{basic|enhanced|premium}.

        ``address_evidence`` is ``{"method": "physical_visit"|"utility_bill"|
        "agent_confirmation"|"electronic", "verified_at": "<iso8601>"}``.
        Screening flags (check_pep / check_sanctions) apply to enhanced and
        premium; the credit-bureau flags apply to premium only.
        """
        if level not in _KYC_LEVELS:
            raise ValueError(f"level must be one of {_KYC_LEVELS}, got {level!r}")
        payload = self._drop_none({
            "customer_id": customer_id,
            "first_name": first_name,
            "last_name": last_name,
            "bvn": bvn,
            "nin": nin,
            "phone": phone,
            "email": email,
            "date_of_birth": date_of_birth,
            "address_evidence": address_evidence,
        })
        if level in ("enhanced", "premium"):
            payload.update(self._drop_none({
                "check_pep": check_pep,
                "check_sanctions": check_sanctions,
                "nationality": nationality,
            }))
        if level == "premium":
            payload.update(self._drop_none({
                "check_credit_bureau": check_credit_bureau,
                "credit_bureau_provider": credit_bureau_provider,
            }))
        return self._request("POST", f"/api/v1/kyc/verify/{level}",
                             json_body=payload, idempotency_key=idempotency_key)

    def kyc_status(self, request_id: str) -> dict[str, Any]:
        """GET /api/v1/kyc/status/{request_id}."""
        return self._request("GET", f"/api/v1/kyc/status/{request_id}")

    def document_verify(
        self,
        document: FileLike,
        document_type: str,
        *,
        check_forgery: bool = True,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        idempotency_key: Union[str, bool, None] = None,
    ) -> dict[str, Any]:
        """Multipart upload to POST /api/v1/document/verify.

        ``document`` may be raw bytes, an open binary file, or a filesystem
        path. Returns the layered verification verdict (verification_id,
        status, detected_format, structural checks, forgery analysis).
        """
        file_tuple = self._file_tuple(document, filename, content_type)
        return self._request(
            "POST",
            "/api/v1/document/verify",
            files={"document": file_tuple},
            form={"document_type": document_type,
                  "check_forgery": "true" if check_forgery else "false"},
            idempotency_key=idempotency_key,
        )

    def biometric_verify(
        self,
        selfie: Union[str, bytes],
        reference: Union[str, bytes, None] = None,
        *,
        check_liveness: bool = True,
        idempotency_key: Union[str, bool, None] = None,
    ) -> dict[str, Any]:
        """POST /api/v1/biometric/verify (JSON, base64 images).

        ``selfie``/``reference`` accept either a base64 string or raw bytes
        (bytes are base64-encoded for you).
        """
        payload = {
            "selfie_image_base64": self._to_base64(selfie, "selfie"),
            "check_liveness": check_liveness,
        }
        if reference is not None:
            payload["reference_image_base64"] = self._to_base64(reference, "reference")
        return self._request("POST", "/api/v1/biometric/verify",
                             json_body=payload, idempotency_key=idempotency_key)

    @staticmethod
    def _to_base64(value: Union[str, bytes], field: str) -> str:
        if isinstance(value, bytes):
            return base64.b64encode(value).decode("ascii")
        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"{field} is neither raw bytes nor valid base64") from exc
        return value

    @staticmethod
    def _file_tuple(document: FileLike, filename: Optional[str],
                    content_type: Optional[str]) -> Any:
        data: Any
        name = filename
        if isinstance(document, (str, Path)):
            path = Path(document)
            data = path.read_bytes()
            name = name or path.name
        elif isinstance(document, bytes):
            data = document
            name = name or "document.bin"
        else:  # file-like
            data = document.read()
            name = name or getattr(document, "name", "document.bin")
        if content_type:
            return (name, data, content_type)
        return (name, data)

    # ------------------------------------------------------------------
    # KYB (onboarding-service)
    # ------------------------------------------------------------------
    def kyb_submit(
        self,
        *,
        business_name: str,
        cac_number: str,
        contact_email: str,
        documents: list[dict[str, Any]],
        business_type: str = "limited_liability",
        idempotency_key: Union[str, bool, None] = None,
    ) -> dict[str, Any]:
        """POST /api/v1/onboarding/kyb — submit a KYB application.

        ``documents`` is a list of ``{"type": "cac_certificate"|"memart"|
        "utility_bill"|"board_resolution", "reference": "...", "content":
        <optional base64>}`` — content is verified but never persisted
        server-side (hash-only). Returns the KybApplicationView
        (camelCase keys: applicationId, businessName, ...).
        """
        payload = {
            "businessName": business_name,
            "cacNumber": cac_number,
            "businessType": business_type,
            "contactEmail": contact_email,
            "documents": documents,
        }
        return self._request("POST", "/api/v1/onboarding/kyb",
                             json_body=payload, idempotency_key=idempotency_key)

    def kyb_get(self, application_id: str) -> dict[str, Any]:
        """GET /api/v1/onboarding/kyb/{application_id}."""
        return self._request("GET", f"/api/v1/onboarding/kyb/{application_id}")

    def kyb_get_verification(self, application_id: str) -> dict[str, Any]:
        """GET /api/v1/onboarding/kyb/{application_id}/verification — the full
        per-document content-verification verdict (404 when no verification
        has run, e.g. reference-only submissions)."""
        return self._request("GET",
                             f"/api/v1/onboarding/kyb/{application_id}/verification")

    # ------------------------------------------------------------------
    # Intelligence (intel-service)
    # ------------------------------------------------------------------
    def intel_national_summary(self) -> dict[str, Any]:
        """GET /v1/intel/national/summary — national fraud-rate posterior,
        trend, top typologies, 4-week forecast."""
        return self._request("GET", "/v1/intel/national/summary")

    def intel_states(self) -> dict[str, Any]:
        """GET /v1/intel/states — 37 states ranked with credible intervals;
        low-volume cells are k-anonymity suppressed."""
        return self._request("GET", "/v1/intel/states")

    def intel_state(self, code: str) -> dict[str, Any]:
        """GET /v1/intel/states/{code} — state detail incl. LGA table for
        pilot states."""
        return self._request("GET", f"/v1/intel/states/{code}")

    def intel_hotspots(self, k: int = 10, threshold: Optional[float] = None) -> dict[str, Any]:
        """GET /v1/intel/hotspots — posterior-ranked hotspots."""
        params: dict[str, Any] = {"k": k}
        if threshold is not None:
            params["threshold"] = threshold
        return self._request("GET", "/v1/intel/hotspots", params=params)

    def intel_typology_mix(self) -> dict[str, Any]:
        """GET /v1/intel/typology-mix — per-zone Dirichlet-multinomial mix."""
        return self._request("GET", "/v1/intel/typology-mix")

    def intel_cultural_calendar(self, date: str, state: str = "lagos") -> dict[str, Any]:
        """GET /v1/intel/cultural/calendar?date=YYYY-MM-DD&state=... —
        active cultural events and their uplift posteriors."""
        return self._request("GET", "/v1/intel/cultural/calendar",
                             params={"date": date, "state": state})

    def intel_cultural_ajo_assess(
        self,
        *,
        n_members: int,
        contribution_cv: float,
        cadence_cv: float,
        rotation_coverage: float,
        payout_ratio: float,
        tenure_days: float,
    ) -> dict[str, Any]:
        """POST /v1/intel/cultural/ajo/assess — legitimacy posterior for an
        ajo/esusu rotating-savings group (PATTERN-LEVEL features only)."""
        return self._request("POST", "/v1/intel/cultural/ajo/assess", json_body={
            "n_members": n_members,
            "contribution_cv": contribution_cv,
            "cadence_cv": cadence_cv,
            "rotation_coverage": rotation_coverage,
            "payout_ratio": payout_ratio,
            "tenure_days": tenure_days,
        })

    def intel_cultural_score(
        self,
        indicators: dict[str, float],
        *,
        claimed_event: Optional[str] = None,
        date: Optional[str] = None,
        state: Optional[str] = None,
        network_consistent_with_claimed_norm: bool = False,
        ajo_pattern: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """POST /v1/intel/cultural/score — weighted cultural-fraud indicator
        score with authenticity discounts."""
        payload: dict[str, Any] = {
            "indicators": indicators,
            "network_consistent_with_claimed_norm": network_consistent_with_claimed_norm,
        }
        if claimed_event is not None:
            payload["claimed_event"] = claimed_event
        if date is not None:
            payload["date"] = date
        if state is not None:
            payload["state"] = state
        if ajo_pattern is not None:
            payload["ajo_pattern"] = ajo_pattern
        return self._request("POST", "/v1/intel/cultural/score", json_body=payload)

    def intel_legitimacy_assess(
        self,
        *,
        requesting_entity_type: str,
        fields_requested: list[str],
        channel: str,
        link_present: bool = False,
    ) -> dict[str, Any]:
        """POST /v1/intel/request-legitimacy/assess — is this data-collection
        request consistent with what such an entity legitimately needs?
        (entity-TYPE heuristic; never vouches for a specific sender.)"""
        return self._request("POST", "/v1/intel/request-legitimacy/assess", json_body={
            "requesting_entity_type": requesting_entity_type,
            "fields_requested": fields_requested,
            "channel": channel,
            "link_present": link_present,
        })

    def intel_legitimacy_matrix(self) -> dict[str, Any]:
        """GET /v1/intel/request-legitimacy/matrix — the auditable
        appropriateness matrix behind legitimacy scoring."""
        return self._request("GET", "/v1/intel/request-legitimacy/matrix")

    # ------------------------------------------------------------------
    # Webhooks (webhook-service)
    # ------------------------------------------------------------------
    def webhooks_list(self) -> Any:
        """GET /v1/webhooks — the tenant's registered webhook endpoints."""
        return self._request("GET", "/v1/webhooks")

    def webhook_create(
        self,
        url: str,
        event_types: list[str],
        *,
        description: Optional[str] = None,
    ) -> dict[str, Any]:
        """POST /v1/webhooks — register an endpoint. The signing secret
        (``whsec_...``) is returned ONCE in this response; store it
        immediately — only its hash is retained server-side."""
        payload: dict[str, Any] = {"url": url, "event_types": event_types}
        if description is not None:
            payload["description"] = description
        return self._request("POST", "/v1/webhooks", json_body=payload)

    def webhook_delete(self, endpoint_id: str) -> Any:
        """DELETE /v1/webhooks/{endpoint_id}."""
        return self._request("DELETE", f"/v1/webhooks/{endpoint_id}")

    def webhook_deliveries(self, endpoint_id: str) -> Any:
        """GET /v1/webhooks/{endpoint_id}/deliveries — delivery history with
        attempt history / dead-letter status for the tenant."""
        return self._request("GET", f"/v1/webhooks/{endpoint_id}/deliveries")
