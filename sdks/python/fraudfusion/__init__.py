"""fraudfusion — official Python SDK for the FraudFusion API.

Quickstart::

    from fraudfusion import FraudFusionClient

    client = FraudFusionClient(
        api_key="ffk_test_...",
        base_url="http://localhost:8091",   # sandbox; pass live URL in prod
    )
    result = client.kyc_verify(
        customer_id="cust_001",
        first_name="Ada",
        last_name="Lovelace",
        level="basic",
        bvn="12345678900",
    )
"""

from .client import (
    DEFAULT_BASE_URL,
    SANDBOX_BASE_URL,
    FraudFusionClient,
    new_idempotency_key,
)
from .exceptions import (
    AuthenticationError,
    ConflictError,
    FraudFusionError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
    ValidationError,
    WebhookSignatureError,
)
from .webhook import (
    DEFAULT_TOLERANCE_SECONDS,
    SIGNATURE_HEADER,
    compute_signature,
    derive_signing_key,
    parse_signature_header,
    verify_webhook_signature,
)

__version__ = "0.1.0"

__all__ = [
    "FraudFusionClient",
    "new_idempotency_key",
    "DEFAULT_BASE_URL",
    "SANDBOX_BASE_URL",
    "SIGNATURE_HEADER",
    "DEFAULT_TOLERANCE_SECONDS",
    "compute_signature",
    "derive_signing_key",
    "parse_signature_header",
    "verify_webhook_signature",
    "FraudFusionError",
    "AuthenticationError",
    "PermissionError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "ValidationError",
    "ServerError",
    "WebhookSignatureError",
    "__version__",
]
