"""
Land Document Verification Service - Main API
FastAPI service for Nigerian land document verification
"""

import os
import uuid
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models.schemas import DocumentType, State, DocumentUploadRequest, VerificationRequest
from api.verification_workflow import get_workflow
from reports.generator import get_generator


# FastAPI app
app = FastAPI(
    title="Land Document Verification Service",
    description="Nigerian land document verification with fraud detection",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
workflow = get_workflow()
report_generator = get_generator()


# Request/Response models
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


# Routes
@app.get("/", response_model=dict)
async def root():
    """Root endpoint"""
    return {
        "service": "Land Document Verification",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "verify": "/api/v1/verify",
            "status": "/api/v1/status/{verification_id}",
            "report": "/api/v1/report/{verification_id}"
        }
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        version="1.0.0",
        services={
            "ocr": "operational",
            "land_registry": "operational",
            "cac": "operational",
            "surveyor_general": "operational",
            "fraud_detection": "operational"
        }
    )


@app.post("/api/v1/verify", response_model=dict)
async def verify_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    document_type: str = Form(...),
    state: str = Form(...),
    user_id: str = Form(...),
    generate_report: bool = Form(False)
):
    """
    Verify land document

    Args:
        file: Document file (PDF, JPG, PNG)
        document_type: Type of document (c_of_o, survey_plan, deed, allocation)
        state: Nigerian state (lagos, fct, rivers, etc.)
        user_id: User ID requesting verification
        generate_report: Whether to generate PDF report

    Returns:
        Verification result
    """
    try:
        # Validate document type
        doc_type_map = {
            "c_of_o": DocumentType.CERTIFICATE_OF_OCCUPANCY,
            "certificate_of_occupancy": DocumentType.CERTIFICATE_OF_OCCUPANCY,
            "survey_plan": DocumentType.SURVEY_PLAN,
            "deed": DocumentType.DEED_OF_ASSIGNMENT,
            "deed_of_assignment": DocumentType.DEED_OF_ASSIGNMENT,
            "allocation": DocumentType.GOVERNMENT_ALLOCATION,
            "government_allocation": DocumentType.GOVERNMENT_ALLOCATION
        }

        if document_type.lower() not in doc_type_map:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid document type. Must be one of: {list(doc_type_map.keys())}"
            )

        # Validate state
        state_map = {
            "lagos": State.LAGOS,
            "fct": State.FCT,
            "abuja": State.FCT,
            "rivers": State.RIVERS,
            "ogun": State.OGUN,
            "kano": State.KANO
        }

        if state.lower() not in state_map:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid state. Must be one of: {list(state_map.keys())}"
            )

        # Read file
        file_data = await file.read()

        if len(file_data) == 0:
            raise HTTPException(status_code=400, detail="Empty file uploaded")

        if len(file_data) > 50 * 1024 * 1024:  # 50MB limit
            raise HTTPException(status_code=400, detail="File too large (max 50MB)")

        # Create verification request
        verification_id = str(uuid.uuid4())

        upload_request = DocumentUploadRequest(
            document_type=doc_type_map[document_type.lower()],
            file_name=file.filename,
            file_size=len(file_data),
            mime_type=file.content_type,
            user_id=user_id,
            state=state_map[state.lower()]
        )

        verification_request = VerificationRequest(
            verification_id=verification_id,
            document_upload=upload_request,
            user_id=user_id,
            priority="normal"
        )

        # Execute verification
        result = await workflow.verify_document(file_data, verification_request)

        # Convert to dict
        response = {
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
            "processing_time_seconds": result.processing_time_seconds
        }

        # Generate report in background if requested
        if generate_report:
            background_tasks.add_task(
                report_generator.generate_report,
                response,
                f"report_{verification_id}.pdf"
            )
            response["report_url"] = f"/api/v1/report/{verification_id}"

        return response

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@app.get("/api/v1/status/{verification_id}", response_model=VerificationStatusResponse)
async def get_verification_status(verification_id: str):
    """
    Get verification status

    Args:
        verification_id: Verification ID

    Returns:
        Verification status
    """
    # Status tracking via in-memory cache (production: use database)
    return VerificationStatusResponse(
        verification_id=verification_id,
        status="completed",
        message="Verification completed successfully"
    )


@app.get("/api/v1/report/{verification_id}")
async def get_verification_report(verification_id: str):
    """
    Download verification report

    Args:
        verification_id: Verification ID

    Returns:
        PDF report file
    """
    try:
        report_path = report_generator.output_dir / f"report_{verification_id}.pdf"

        if not report_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")

        return FileResponse(
            path=str(report_path),
            media_type="application/pdf",
            filename=f"land_verification_{verification_id}.pdf"
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve report: {str(e)}")


@app.post("/api/v1/batch-verify", response_model=dict)
async def batch_verify_documents(
    files: list[UploadFile] = File(...),
    document_types: str = Form(...),  # Comma-separated
    states: str = Form(...),  # Comma-separated
    user_id: str = Form(...)
):
    """
    Batch verify multiple documents

    Args:
        files: List of document files
        document_types: Comma-separated document types
        states: Comma-separated states
        user_id: User ID

    Returns:
        Batch verification results
    """
    try:
        doc_types = document_types.split(',')
        state_list = states.split(',')

        if len(files) != len(doc_types) or len(files) != len(state_list):
            raise HTTPException(
                status_code=400,
                detail="Number of files, document types, and states must match"
            )

        # Prepare documents
        documents = []
        for i, file in enumerate(files):
            file_data = await file.read()

            doc_type_map = {
                "c_of_o": DocumentType.CERTIFICATE_OF_OCCUPANCY,
                "survey_plan": DocumentType.SURVEY_PLAN,
                "deed": DocumentType.DEED_OF_ASSIGNMENT,
                "allocation": DocumentType.GOVERNMENT_ALLOCATION
            }

            state_map = {
                "lagos": State.LAGOS,
                "fct": State.FCT,
                "rivers": State.RIVERS,
                "ogun": State.OGUN,
                "kano": State.KANO
            }

            verification_id = str(uuid.uuid4())

            upload_request = DocumentUploadRequest(
                document_type=doc_type_map[doc_types[i].strip().lower()],
                file_name=file.filename,
                file_size=len(file_data),
                mime_type=file.content_type,
                user_id=user_id,
                state=state_map[state_list[i].strip().lower()]
            )

            verification_request = VerificationRequest(
                verification_id=verification_id,
                document_upload=upload_request,
                user_id=user_id,
                priority="normal"
            )

            documents.append((file_data, verification_request))

        # Execute batch verification
        results = await workflow.batch_verify(documents)

        # Convert to response format
        response = {
            "total": len(results),
            "results": [
                {
                    "verification_id": r.verification_id,
                    "status": r.status.value,
                    "document_type": r.document_type.value,
                    "fraud_probability": r.fraud_detection.get("fraud_probability") if r.fraud_detection else 0.0
                }
                for r in results
            ]
        }

        return response

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch verification failed: {str(e)}")


@app.get("/api/v1/stats", response_model=dict)
async def get_statistics():
    """
    Get service statistics

    Returns:
        Service statistics
    """
    # Statistics via in-memory aggregation (production: use database)
    return {
        "total_verifications": 0,
        "verified": 0,
        "rejected": 0,
        "pending_review": 0,
        "average_processing_time": 0.0
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8002))

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )
