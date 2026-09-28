"""FraudFusion developer sandbox (:8091).

A self-contained FastAPI service that mirrors the SHAPES of the key
FraudFusion data-plane endpoints with deterministic SYNTHETIC data, so third
parties can integrate end-to-end without real data or credentials:

  POST /api/v1/kyc/verify/{basic,enhanced,premium}  (mirrors kyc-api)
  POST /api/v1/kyc/verify                           (alias for basic)
  POST /api/v1/document/verify                      (mirrors kyc-api)
  POST /api/v1/onboarding/kyb                       (mirrors onboarding-service)
  GET  /api/v1/onboarding/kyb/{id}/verification     (mirrors onboarding-service)
  GET  /v1/intel/national/summary                   (mirrors intel-service)
  POST /v1/intel/request-legitimacy/assess          (mirrors intel-service)
  POST /v1/intel/cultural/score                     (mirrors intel-service)
  POST /sandbox/trigger-event                       (signed webhook simulation)
  GET  /sandbox/fixtures                            (the documented fixtures)

SANDBOX IS SYNTHETIC — NO REAL VERIFICATION OCCURS. Every response carries
"environment": "sandbox" and "synthetic": true.

Auth: any X-API-Key with the ffk_test_ prefix; ffk_live_* is explicitly
rejected; missing key -> 401. Rate limit: 60 rpm sliding window per key.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app import fixtures, intel, kyc, kyb, webhooks
from app.auth import SlidingWindowRateLimiter, require_sandbox_key

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("sandbox")

SERVICE_NAME = "fraudfusion-sandbox"
SERVICE_VERSION = "1.0.0"


class TriggerEventRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    event_type: str
    payload_overrides: Optional[dict] = None


def create_app() -> FastAPI:
    app = FastAPI(
        title=SERVICE_NAME,
        version=SERVICE_VERSION,
        description="Developer sandbox — deterministic synthetic mirrors of "
                    "the FraudFusion data plane. SYNTHETIC ONLY: no real "
                    "verification occurs.")
    app.state.rate_limiter = SlidingWindowRateLimiter()
    app.state.kyb_verdicts = {}  # application_id -> verdict envelope

    @app.get("/health")
    def health() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME,
                "version": SERVICE_VERSION, "environment": "sandbox",
                "synthetic": True, "timestamp": kyc._now()}

    # ----------------------------- KYC (kyc-api shapes) --------------------

    def _kyc(level: str, payload: kyc.BasicKYCRequest) -> dict:
        return kyc.run_kyc_verification(level, payload)

    @app.post("/api/v1/kyc/verify")
    def kyc_verify(payload: kyc.BasicKYCRequest,
                   _key: str = Depends(require_sandbox_key)) -> dict:
        """Alias for /verify/basic (the plan's canonical sandbox path)."""
        return _kyc("basic", payload)

    @app.post("/api/v1/kyc/verify/basic")
    def kyc_verify_basic(payload: kyc.BasicKYCRequest,
                         _key: str = Depends(require_sandbox_key)) -> dict:
        return _kyc("basic", payload)

    @app.post("/api/v1/kyc/verify/enhanced")
    def kyc_verify_enhanced(payload: kyc.EnhancedKYCRequest,
                            _key: str = Depends(require_sandbox_key)) -> dict:
        return _kyc("enhanced", payload)

    @app.post("/api/v1/kyc/verify/premium")
    def kyc_verify_premium(payload: kyc.PremiumKYCRequest,
                           _key: str = Depends(require_sandbox_key)) -> dict:
        return _kyc("premium", payload)

    @app.post("/api/v1/document/verify")
    async def document_verify(
        document: UploadFile = File(...),
        document_type: str = Form(...),
        check_forgery: bool = Form(default=True),
        _key: str = Depends(require_sandbox_key),
    ) -> dict:
        data = await document.read()
        if not data:
            raise HTTPException(status_code=422,
                                detail="uploaded file is empty")
        if len(data) > kyc.MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413,
                                detail="upload exceeds 10MB limit")
        return kyc.document_checks(data, document_type, check_forgery,
                                   filename=document.filename or "")

    # --------------------- KYB (onboarding-service shapes) -----------------

    @app.post("/api/v1/onboarding/kyb", status_code=201)
    def submit_kyb(payload: kyb.KybSubmission,
                   key: str = Depends(require_sandbox_key)) -> dict:
        verdict = kyb.build_kyb_verdict(payload)
        view = kyb.build_application_view(payload, verdict, key)
        app.state.kyb_verdicts[view["applicationId"]] = verdict
        logger.info("sandbox kyb: id=%s verdict=%s",
                    view["applicationId"], verdict["verdict"])
        return view

    @app.get("/api/v1/onboarding/kyb/{application_id}/verification")
    def get_kyb_verification(application_id: str,
                             _key: str = Depends(require_sandbox_key)) -> dict:
        verdict = app.state.kyb_verdicts.get(application_id)
        if verdict is None:
            raise HTTPException(
                status_code=404,
                detail="no verification has run for this application "
                       "(unknown id, or the sandbox process restarted — the "
                       "sandbox registry is in-memory only)")
        return verdict

    # ------------------------- Intel (intel-service shapes) ----------------

    @app.get("/v1/intel/national/summary")
    def national_summary(_key: str = Depends(require_sandbox_key)) -> dict:
        return {**intel.NATIONAL_SUMMARY, **intel.SANDBOX_MARKERS}

    @app.post("/v1/intel/request-legitimacy/assess")
    def request_legitimacy_assess(
            req: intel.RequestLegitimacyAssessRequest,
            _key: str = Depends(require_sandbox_key)) -> dict:
        return intel.assess_legitimacy(req)

    @app.post("/v1/intel/cultural/score")
    def cultural_score(req: intel.CulturalScoreRequest,
                       _key: str = Depends(require_sandbox_key)) -> dict:
        return intel.cultural_score(req)

    # --------------------------- Sandbox utilities -------------------------

    @app.post("/sandbox/trigger-event")
    def trigger_event(payload: TriggerEventRequest,
                      _key: str = Depends(require_sandbox_key)) -> dict:
        """Fire a synthetic SIGNED webhook to the caller's URL.

        Signing scheme (shared contract): header
        ``X-FraudFusion-Signature: t=<unix>,v1=<hex>`` where ``v1`` is
        HMAC-SHA256 over ``"<t>.<raw body>"`` keyed by
        ``sha256(secret).hexdigest().encode()``; the demo secret is
        ``whsec_demo0000000000000000000000000000``.
        """
        from urllib.parse import urlparse
        parsed = urlparse(payload.url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise HTTPException(
                status_code=422,
                detail="url must be an absolute http(s) URL the sandbox can "
                       "POST to (your webhook receiver)")
        if payload.event_type not in fixtures.WEBHOOK_EVENT_TYPES:
            raise HTTPException(
                status_code=422,
                detail=f"unknown event_type '{payload.event_type}'; supported: "
                       f"{list(fixtures.WEBHOOK_EVENT_TYPES)}")
        event = webhooks.build_event(payload.event_type,
                                     payload.payload_overrides)
        result = webhooks.deliver_event(payload.url, event,
                                        fixtures.WEBHOOK_DEMO_SECRET)
        result.update(environment="sandbox", synthetic=True)
        return result

    @app.get("/sandbox/fixtures")
    def list_fixtures(_key: str = Depends(require_sandbox_key)) -> dict:
        """The documented deterministic fixtures (test customers, magic values)."""
        return {
            "test_customers": fixtures.TEST_CUSTOMERS,
            "test_businesses": fixtures.TEST_BUSINESSES,
            "webhook_event_types": list(fixtures.WEBHOOK_EVENT_TYPES),
            "webhook_demo_secret": fixtures.WEBHOOK_DEMO_SECRET,
            **kyc.SANDBOX_MARKERS,
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8091")))
