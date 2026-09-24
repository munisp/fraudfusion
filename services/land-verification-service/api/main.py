"""
Land Document Verification Service - Main API
FastAPI service for Nigerian land document verification.

Authentication: Keycloak bearer-token introspection (fail-closed); see api/auth.py.
CORS: comma-separated allow-list via LAND_VERIFY_CORS_ORIGINS (never '*').
"""

import asyncio
import os
import uuid
from datetime import datetime

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api.auth import get_current_user
from api.verification_workflow import get_workflow
from models.schemas import (
    DocumentType,
    DocumentUploadRequest,
    State,
    VerificationRequest,
)
from reports.generator import get_generator

DOC_TYPE_MAP = {
    "c_of_o": DocumentType.CERTIFICATE_OF_OCCUPANCY,
    "certificate_of_occupancy": DocumentType.CERTIFICATE_OF_OCCUPANCY,
    "survey_plan": DocumentType.SURVEY_PLAN,
    "deed": DocumentType.DEED_OF_ASSIGNMENT,
    "deed_of_assignment": DocumentType.DEED_OF_ASSIGNMENT,
    "allocation": DocumentType.GOVERNMENT_ALLOCATION,
    "government_allocation": DocumentType.GOVERNMENT_ALLOCATION,
}

STATE_MAP = {
    "lagos": State.LAGOS,
    "fct": State.FCT,
    "abuja": State.FCT,
    "rivers": State.RIVERS,
    "ogun": State.OGUN,
    "kano": State.KANO,
}

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB


class VerificationStatusResponse(BaseModel):
    """Verification status response"""

    verification_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    """Health check response"""

    status: str
    timestamp: str
    version: str
    services: dict


def _parse_document_type(raw: str) -> DocumentType:
    doc_type = DOC_TYPE_MAP.get(raw.strip().lower())
    if doc_type is None:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid document type. Must be one of: {sorted(DOC_TYPE_MAP)}",
        )
    return doc_type


def _parse_state(raw: str) -> State:
    state = STATE_MAP.get(raw.strip().lower())
    if state is None:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid state. Must be one of: {sorted(STATE_MAP)}",
        )
    return state


def _build_request(
    file_name: str | None,
    file_size: int,
    mime_type: str | None,
    document_type: str,
    state: str,
    user_id: str,
) -> VerificationRequest:
    upload = DocumentUploadRequest(
        document_type=_parse_document_type(document_type),
        file_name=file_name,
        file_size=file_size,
        mime_type=mime_type,
        user_id=user_id,
        state=_parse_state(state),
    )
    return VerificationRequest(
        verification_id=str(uuid.uuid4()),
        document_upload=upload,
        user_id=user_id,
        priority="normal",
    )


def _result_to_response(result) -> dict:
    return {
        "verification_id": result.verification_id,
        "status": result.status.value,
        "document_type": result.document_type.value,
        "extracted_data": result.extracted_data,
        "ocr_confidence": result.ocr_confidence,
        "registry_verification": result.registry_verification,
        "cac_verification": result.cac_verification,
        "surveyor_verification": result.surveyor_verification,
        "coordinate_verification": result.coordinate_verification,
        "fraud_detection": result.fraud_detection,
        "timestamp": result.verification_timestamp.isoformat(),
        "processing_time_seconds": result.processing_time_seconds,
    }


async def _read_upload(file: UploadFile, max_bytes: int) -> bytes:
    """Stream an upload in 1MB chunks, aborting as soon as the cap is
    exceeded instead of buffering an unbounded body in memory."""
    chunks = bytearray()
    while True:
        chunk = await file.read(1 << 20)
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > max_bytes:
            raise HTTPException(status_code=400, detail="File too large (max 50MB)")
    if not chunks:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    return bytes(chunks)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Land Document Verification Service",
        description="Nigerian land document verification with fraud detection",
        version="1.0.0",
    )

    cors_origins = [
        origin.strip()
        for origin in os.getenv(
            "LAND_VERIFY_CORS_ORIGINS", "http://localhost:3000,http://localhost:3001"
        ).split(",")
        if origin.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    workflow = get_workflow()
    report_generator = get_generator()

    @app.get("/", response_model=dict)
    async def root():
        return {
            "service": "Land Document Verification",
            "version": "1.0.0",
            "status": "operational",
            "endpoints": {
                "health": "/health",
                "verify": "/api/v1/verify",
                "status": "/api/v1/status/{verification_id}",
                "report": "/api/v1/report/{verification_id}",
            },
        }

    @app.get("/health", response_model=HealthResponse)
    async def health_check():
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow().isoformat(),
            version="1.0.0",
            services={
                "document_analysis": "operational",
                "land_registry": "pending-integration",
                "cac": "pending-integration",
                "surveyor_general": "pending-integration",
                "fraud_detection": "operational",
            },
        )

    @app.post("/api/v1/verify", response_model=dict)
    async def verify_document(
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
        document_type: str = Form(...),
        state: str = Form(...),
        generate_report: bool = Form(False),
        user_id: str = Depends(get_current_user),
    ):
        """Verify a land document. The user id comes from the Keycloak token."""
        try:
            file_data = await _read_upload(file, MAX_UPLOAD_BYTES)

            request = _build_request(
                file.filename, len(file_data), file.content_type, document_type, state, user_id
            )
            result = await workflow.verify_document(file_data, request)
            response = _result_to_response(result)

            if generate_report:
                background_tasks.add_task(
                    report_generator.generate_report,
                    response,
                    f"report_{request.verification_id}.pdf",
                )
                response["report_url"] = f"/api/v1/report/{request.verification_id}"
            return response
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Verification failed: {exc}")

    @app.get("/api/v1/status/{verification_id}", response_model=VerificationStatusResponse)
    async def get_verification_status(
        verification_id: str, user_id: str = Depends(get_current_user)
    ):
        status = await asyncio.to_thread(workflow.get_status, verification_id)
        if status is None:
            raise HTTPException(status_code=404, detail="Verification not found")
        return VerificationStatusResponse(
            verification_id=verification_id,
            status=status.value,
            message=f"Verification is in state '{status.value}'",
        )

    @app.get("/api/v1/report/{verification_id}")
    async def get_verification_report(
        verification_id: str, user_id: str = Depends(get_current_user)
    ):
        report_path = report_generator.output_dir / f"report_{verification_id}.pdf"
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        return FileResponse(
            path=str(report_path),
            media_type="application/pdf",
            filename=f"land_verification_{verification_id}.pdf",
        )

    @app.post("/api/v1/batch-verify", response_model=dict)
    async def batch_verify_documents(
        files: list[UploadFile] = File(...),
        document_types: str = Form(...),
        states: str = Form(...),
        user_id: str = Depends(get_current_user),
    ):
        try:
            doc_types = document_types.split(",")
            state_list = states.split(",")
            if len(files) != len(doc_types) or len(files) != len(state_list):
                raise HTTPException(
                    status_code=400,
                    detail="Number of files, document types, and states must match",
                )

            documents = []
            for i, file in enumerate(files):
                try:
                    file_data = await _read_upload(file, MAX_UPLOAD_BYTES)
                except HTTPException:
                    raise HTTPException(
                        status_code=400, detail=f"Invalid file (empty or >50MB) for {file.filename}"
                    )
                documents.append(
                    (
                        file_data,
                        _build_request(
                            file.filename,
                            len(file_data),
                            file.content_type,
                            doc_types[i],
                            state_list[i],
                            user_id,
                        ),
                    )
                )

            results = await workflow.batch_verify(documents)
            return {
                "total": len(results),
                "results": [
                    {
                        "verification_id": r.verification_id,
                        "status": r.status.value,
                        "document_type": r.document_type.value,
                        "fraud_probability": (
                            r.fraud_detection.get("fraud_probability") if r.fraud_detection else 0.0
                        ),
                    }
                    for r in results
                ],
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Batch verification failed: {exc}")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    # reload=True is a dev auto-reload mode — never in the production path.
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8002")),
        workers=int(os.getenv("UVICORN_WORKERS", "4")),
        loop="uvloop",
        http="httptools",
        reload=False,
    )
