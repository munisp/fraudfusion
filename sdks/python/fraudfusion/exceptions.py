"""FraudFusion Python SDK — typed exceptions.

HTTP status mapping (applied by the client for every non-2xx response):

  400/422 -> ValidationError      (request rejected by the API's schema checks)
  401     -> AuthenticationError  (missing/invalid/revoked X-API-Key)
  403     -> PermissionError      (key valid but lacks the scope, or tenant mismatch)
  404     -> NotFoundError        (resource does not exist / not visible to tenant)
  409     -> ConflictError        (idempotency-key conflict, state-machine conflict)
  429     -> RateLimitError       (carries retry_after when the server sends it)
  5xx     -> ServerError          (server-side failure; the client retries these)

All exceptions carry ``status_code``, the raw response ``body`` (when
available) and the parsed ``detail`` string the FastAPI services return.
"""

from __future__ import annotations

from typing import Any, Optional


class FraudFusionError(Exception):
    """Base class for every error raised by the SDK."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        detail: Optional[str] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.body = body

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}(status_code={self.status_code}, detail={self.detail!r})"


class AuthenticationError(FraudFusionError):
    """401 — the X-API-Key is missing, malformed, revoked or expired."""


class PermissionError(FraudFusionError):  # noqa: A001 - intentional, mirrors HTTP 403
    """403 — the key is valid but lacks the required scope, or the resource
    belongs to a different tenant.

    NOTE: this intentionally shadows the builtin ``PermissionError`` inside
    this package's namespace (it does NOT subclass the builtin); import it as
    ``fraudfusion.PermissionError`` or via ``fraudfusion.exceptions``.
    """


class NotFoundError(FraudFusionError):
    """404 — resource not found (or not visible to this tenant)."""


class ConflictError(FraudFusionError):
    """409 — conflict, e.g. an Idempotency-Key replayed with a different
    payload, or an appeal/state transition that is no longer valid."""


class RateLimitError(FraudFusionError):
    """429 — rate limited. ``retry_after`` carries the server's Retry-After
    hint (seconds) when present."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None, **kw: Any) -> None:
        super().__init__(message, **kw)
        self.retry_after = retry_after


class ValidationError(FraudFusionError):
    """400/422 — the request failed the API's schema validation."""


class ServerError(FraudFusionError):
    """5xx — server-side failure. The client retries these (see
    ``max_retries``); this is raised only after retries are exhausted."""


class WebhookSignatureError(ValueError):
    """Raised when a webhook signature header is malformed (unparseable,
    missing t=/v1= components). A *mismatching* or *expired* signature does
    NOT raise — ``verify_webhook_signature`` returns False for those."""


_STATUS_MAP = {
    401: AuthenticationError,
    403: PermissionError,
    404: NotFoundError,
    409: ConflictError,
    429: RateLimitError,
}


def error_for_status(status_code: int, body: Any) -> FraudFusionError:
    """Build the typed exception for a non-2xx response."""
    detail: Optional[str] = None
    if isinstance(body, dict):
        raw = body.get("detail", body.get("error", body.get("message")))
        detail = raw if isinstance(raw, str) else (str(raw) if raw is not None else None)
    message = detail or f"HTTP {status_code}"
    kwargs: dict[str, Any] = {"status_code": status_code, "detail": detail, "body": body}
    if status_code >= 500:
        return ServerError(message, **kwargs)
    if status_code in (400, 422):
        return ValidationError(message, **kwargs)
    exc_cls = _STATUS_MAP.get(status_code)
    if exc_cls is RateLimitError:
        retry_after = None
        if isinstance(body, dict):
            raw_ra = body.get("retry_after")
            if isinstance(raw_ra, (int, float)):
                retry_after = float(raw_ra)
        return RateLimitError(message, retry_after=retry_after, **kwargs)
    if exc_cls is not None:
        return exc_cls(message, **kwargs)
    return FraudFusionError(message, **kwargs)
