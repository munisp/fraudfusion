"""
Verification workflow orchestration for Nigerian land documents.

Pipeline (state machine):
    RECEIVED -> DOCUMENT_ANALYSIS -> REGISTRY_LOOKUP
             -> SITE_INSPECTION | FRAUD_REVIEW -> COMPLETED | REJECTED

State transitions are persisted to PostgreSQL (DATABASE_URL required).
Tests use embedded pgserver via services/python/integration/embedded_pg.py.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager
import hashlib
import time
from datetime import datetime
from typing import Any, Optional

from models.schemas import (
    ALLOWED_TRANSITIONS,
    DocumentType,
    Parcel,
    Party,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()


class StateTransitionError(RuntimeError):
    """Raised when an illegal state transition is attempted."""


class VerificationStore:
    """Persistence for verification state transitions.

    PostgreSQL only: DATABASE_URL must be a postgres(ql):// DSN.
    """

    def __init__(self, database_url: str = DATABASE_URL):
        if not database_url.startswith(("postgres://", "postgresql://")):
            raise RuntimeError(
                "PostgreSQL is required: set DATABASE_URL=postgresql://... — "
                "the verification workflow store has no SQLite fallback.")
        self.database_url = database_url
        self._pg = True
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "DATABASE_URL points at PostgreSQL but the 'psycopg' driver "
                "is not installed. Add psycopg[binary] to the environment."
            ) from exc

        # Connection pooling: previously every state transition opened and
        # closed a brand-new connection (6+ connect/query/close cycles per
        # verification, each a TCP+TLS+auth handshake on PostgreSQL).
        self._pool = None
        try:
            from psycopg_pool import ConnectionPool

            self._pool = ConnectionPool(
                self.database_url,
                min_size=1,
                max_size=int(os.getenv("DB_POOL_MAX", "4")),
                open=False,
            )
            self._pool.open()
        except ImportError:
            pass  # fall back to per-call connections below
        self._init_schema()

    @contextmanager
    def _connection(self):
        # Yield a pooled PostgreSQL connection, or a per-call connection when
        # psycopg_pool is unavailable.
        if self._pool is not None:
            with self._pool.connection() as conn:
                yield conn
        else:
            import psycopg

            conn = psycopg.connect(self.database_url)
            try:
                yield conn
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS verification_states (
                    id SERIAL PRIMARY KEY,
                    verification_id TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    reason TEXT DEFAULT '',
                    actor TEXT DEFAULT 'system',
                    created_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS verification_results (
                    verification_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def record_transition(
        self,
        verification_id: str,
        from_status: Optional[VerificationStatus],
        to_status: VerificationStatus,
        reason: str = "",
        actor: str = "system",
    ) -> None:
        if from_status is not None and to_status not in ALLOWED_TRANSITIONS.get(from_status, set()):
            raise StateTransitionError(
                f"Illegal transition {from_status.value} -> {to_status.value}"
            )
        with self._connection() as conn:
            conn.cursor().execute(
                "INSERT INTO verification_states "
                "(verification_id, from_status, to_status, reason, actor, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    verification_id,
                    from_status.value if from_status else None,
                    to_status.value,
                    reason,
                    actor,
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()

    def current_status(self, verification_id: str) -> Optional[VerificationStatus]:
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT to_status FROM verification_states WHERE verification_id = %s"
                " ORDER BY id DESC LIMIT 1",
                (verification_id,),
            )
            row = cur.fetchone()
            return VerificationStatus(row[0]) if row else None

    def history(self, verification_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT from_status, to_status, reason, actor, created_at "
                "FROM verification_states WHERE verification_id = %s ORDER BY id",
                (verification_id,),
            )
            return [
                {
                    "from_status": row[0],
                    "to_status": row[1],
                    "reason": row[2],
                    "actor": row[3],
                    "created_at": row[4],
                }
                for row in cur.fetchall()
            ]

    def save_result(self, verification_id: str, payload: str) -> None:
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO verification_results (verification_id, payload, updated_at) "
                "VALUES (%s, %s, %s) "
                "ON CONFLICT (verification_id) DO UPDATE SET payload = EXCLUDED.payload, "
                "updated_at = EXCLUDED.updated_at",
                (verification_id, payload, datetime.utcnow().isoformat()),
            )
            conn.commit()

    def load_result(self, verification_id: str) -> Optional[str]:
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT payload FROM verification_results WHERE verification_id = %s",
                (verification_id,),
            )
            row = cur.fetchone()
            return row[0] if row else None


class VerificationWorkflow:
    """Orchestrates document analysis, registry lookup, and inspection states."""

    def __init__(self, store: Optional[VerificationStore] = None):
        self.store = store or VerificationStore()

    async def _record(self, *args) -> None:
        # Pooled but still blocking driver calls; keep them off the event loop.
        await asyncio.to_thread(self.store.record_transition, *args)

    async def _save(self, *args) -> None:
        await asyncio.to_thread(self.store.save_result, *args)

    async def verify_document(
        self, file_data: bytes, request: VerificationRequest
    ) -> VerificationResult:
        started = time.monotonic()
        vid = request.verification_id
        doc_type = request.document_upload.document_type

        await self._record(vid, None, VerificationStatus.RECEIVED, "document uploaded")

        # ---- Document analysis (OCR + structure checks) ---------------------
        await self._record(
            vid, VerificationStatus.RECEIVED, VerificationStatus.DOCUMENT_ANALYSIS, "OCR started"
        )
        extracted, ocr_confidence = await asyncio.to_thread(self._analyze_document_sync, file_data, doc_type)

        # ---- Fraud screening on the extracted content -----------------------
        fraud = self._detect_fraud(file_data, extracted, ocr_confidence)
        if fraud["fraud_probability"] >= 0.8:
            await self._record(
                vid,
                VerificationStatus.DOCUMENT_ANALYSIS,
                VerificationStatus.FRAUD_REVIEW,
                "high fraud probability",
            )
            await self._record(
                vid, VerificationStatus.FRAUD_REVIEW, VerificationStatus.REJECTED, "auto-rejected"
            )
            rejected = self._result(vid, VerificationStatus.REJECTED, doc_type, extracted,
                                    ocr_confidence, fraud, started)
            await self._save(vid, rejected.model_dump_json())
            return rejected

        # ---- Land registry lookup -------------------------------------------
        await self._record(
            vid, VerificationStatus.DOCUMENT_ANALYSIS, VerificationStatus.REGISTRY_LOOKUP,
            "registry query",
        )
        registry = await self._registry_lookup(extracted, request)
        cac = self._cac_check(extracted) if extracted.get("cac_number") else None
        surveyor = self._surveyor_check(extracted) if doc_type == DocumentType.SURVEY_PLAN else None
        coordinates = (
            self._coordinate_check(extracted) if extracted.get("beacon_coordinates") else None
        )

        registry_ok = registry.get("registered", False)
        if not registry_ok:
            # Unregistered parcels need a physical site inspection before a verdict.
            await self._record(
                vid, VerificationStatus.REGISTRY_LOOKUP, VerificationStatus.SITE_INSPECTION,
                "registry miss; inspection required",
            )
            status = VerificationStatus.SITE_INSPECTION
        else:
            await self._record(
                vid, VerificationStatus.REGISTRY_LOOKUP, VerificationStatus.COMPLETED,
                "registry match",
            )
            status = VerificationStatus.COMPLETED

        result = self._result(vid, status, doc_type, extracted, ocr_confidence, fraud, started)
        result.registry_verification = registry
        result.cac_verification = cac
        result.surveyor_verification = surveyor
        result.coordinate_verification = coordinates
        result.parcel = self._parcel_from(extracted, request)
        result.parties = self._parties_from(extracted)
        await self._save(vid, result.model_dump_json())
        return result

    async def batch_verify(
        self, documents: list[tuple[bytes, VerificationRequest]]
    ) -> list[VerificationResult]:
        return list(
            await asyncio.gather(*(self.verify_document(data, req) for data, req in documents))
        )

    def get_status(self, verification_id: str) -> Optional[VerificationStatus]:
        return self.store.current_status(verification_id)

    def get_history(self, verification_id: str) -> list[dict[str, Any]]:
        return self.store.history(verification_id)

    # ---------------------------------------------------- site inspection ---
    def record_inspection_report(
        self, verification_id: str, report: dict[str, Any], actor: str = "inspector"
    ) -> None:
        """File a site-inspection report. Only legal from SITE_INSPECTION —
        the previous state machine stranded verifications there forever."""
        current = self.store.current_status(verification_id)
        if current is None:
            raise StateTransitionError(f"unknown verification {verification_id}")
        self.store.record_transition(
            verification_id, current, VerificationStatus.INSPECTION_REPORT,
            "site inspection report filed", actor=actor,
        )
        self.store.save_result(
            verification_id,
            __import__("json").dumps({"inspection_report": report}),
        )

    def complete_inspection(
        self,
        verification_id: str,
        target: VerificationStatus,
        reason: str = "",
        actor: str = "inspector",
    ) -> None:
        """Decide a verification after its inspection report. Only legal from
        INSPECTION_REPORT and only to COMPLETED or REJECTED."""
        if target not in (VerificationStatus.COMPLETED, VerificationStatus.REJECTED):
            raise StateTransitionError(
                f"inspection decision must be completed|rejected, got {target.value}"
            )
        current = self.store.current_status(verification_id)
        if current is None:
            raise StateTransitionError(f"unknown verification {verification_id}")
        self.store.record_transition(
            verification_id, current, target, reason or "inspection decision", actor=actor,
        )

    # ------------------------------------------------------------------ steps
    def _analyze_document_sync(
        self, file_data: bytes, doc_type: DocumentType
    ) -> tuple[dict[str, Any], float]:
        """Extract structured data from the document.

        Text-bearing documents are parsed for embedded field markers; binary
        scans go through the configured OCR adapter (api/ocr.py: HTTP service
        or local tesseract). When no OCR engine is available the extraction is
        honestly empty with `ocr: unavailable` recorded — text is never
        fabricated.
        """
        from api.ocr import get_ocr_adapter

        extracted: dict[str, Any] = {"document_type": doc_type.value}
        # Binary documents (image/PDF scans) must go through the OCR adapter;
        # decoding them as text would yield garbage "content".
        is_binary = file_data.startswith((b"\x89PNG", b"\xff\xd8\xff", b"%PDF", b"GIF8", b"RIFF"))
        text = "" if is_binary else file_data.decode("utf-8", errors="ignore")
        if is_binary or not text.strip():
            adapter = get_ocr_adapter()
            if adapter is None:
                extracted["ocr"] = "unavailable"
                extracted["ocr_detail"] = (
                    "no OCR engine configured (OCR_SERVICE_URL unset, no tesseract binary)"
                )
                return extracted, 0.0
            result = adapter.extract_text(file_data)
            if result["status"] != "ok":
                extracted["ocr"] = "unavailable"
                extracted["ocr_detail"] = result.get("reason")
                return extracted, 0.0
            text = result["text"]
            extracted["ocr_engine"] = result["engine"]
            ocr_base = result["confidence"] if result["confidence"] is not None else 0.5
        else:
            ocr_base = 0.5
        for marker, key in (
            ("PLOT:", "plot_number"),
            ("PLAN:", "survey_plan_number"),
            ("LGA:", "lga"),
            ("CAC:", "cac_number"),
            ("CERT:", "certificate_number"),
            ("ASSIGNOR:", "assignor"),
            ("ASSIGNEE:", "assignee"),
            ("BEACONS:", "beacon_coordinates"),
        ):
            for line in text.splitlines():
                if line.startswith(marker):
                    value = line[len(marker):].strip()
                    extracted[key] = value.split(",") if key == "beacon_coordinates" else value
        coverage = sum(1 for k in ("plot_number", "survey_plan_number", "lga") if k in extracted)
        ocr_confidence = min(0.99, ocr_base + 0.15 * coverage) if text.strip() else 0.2
        return extracted, round(ocr_confidence, 3)

    def _detect_fraud(
        self, file_data: bytes, extracted: dict[str, Any], ocr_confidence: float
    ) -> dict[str, Any]:
        indicators: list[str] = []
        probability = 0.05
        if ocr_confidence < 0.4:
            indicators.append("low_ocr_confidence")
            probability += 0.25
        if "plot_number" not in extracted:
            indicators.append("missing_plot_reference")
            probability += 0.2
        digest = hashlib.sha256(file_data).hexdigest()
        if not file_data.strip():
            indicators.append("empty_document")
            probability += 0.6
        probability = min(probability, 0.99)
        return {
            "fraud_probability": round(probability, 3),
            "indicators": indicators,
            "document_sha256": digest,
            "model": "rules-v1",
        }

    async def _registry_lookup(
        self, extracted: dict[str, Any], request: VerificationRequest
    ) -> dict[str, Any]:
        """Query the state land registry through the configured adapter
        (api/registry_adapters.py): the state HTTP endpoint when its URL is
        configured (LAGOS_LANDS_URL etc.), otherwise the provenance-tracked
        file-import table (lands_registry_records). Unavailable registries are
        reported honestly, never silently 'registered'."""
        from api.registry_adapters import get_lands_adapter

        state = request.document_upload.state.value
        adapter = get_lands_adapter(state)
        result = await asyncio.to_thread(
            adapter.owner,
            state=state,
            certificate_number=extracted.get("certificate_number"),
            property_address=extracted.get("property_address"),
        )
        status = result.get("status")
        if status == "unavailable":
            return {
                "registry": f"{state}_land_registry",
                "queried": False,
                "registered": False,
                "status": "unavailable",
                "adapter": adapter.name,
                "note": result.get("reason", "registry unavailable"),
            }
        return {
            "registry": f"{state}_land_registry",
            "queried": True,
            "registered": status == "found",
            "status": status,
            "adapter": adapter.name,
            "source": result.get("source"),
            "provenance": result.get("provenance"),
            "plot_number": extracted.get("plot_number"),
            "owner_name": result.get("name"),
            "note": None if status == "found" else result.get("reason"),
        }

    def _cac_check(self, extracted: dict[str, Any]) -> dict[str, Any]:
        return {
            "cac_number": extracted.get("cac_number"),
            "verified": False,
            "note": "CAC public search integration pending.",
        }

    def _surveyor_check(self, extracted: dict[str, Any]) -> dict[str, Any]:
        return {
            "survey_plan_number": extracted.get("survey_plan_number"),
            "lodged_with_surveyor_general": False,
            "note": "Surveyor-General lodgement check pending integration.",
        }

    def _coordinate_check(self, extracted: dict[str, Any]) -> dict[str, Any]:
        coords = extracted.get("beacon_coordinates") or []
        return {
            "beacons": coords,
            "overlap_detected": False,
            "within_state_boundary": None,
            "note": "Geospatial overlap analysis pending GIS integration.",
        }

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parcel_from(extracted: dict[str, Any], request: VerificationRequest) -> Parcel:
        return Parcel(
            plot_number=extracted.get("plot_number"),
            survey_plan_number=extracted.get("survey_plan_number"),
            state=request.document_upload.state,
            lga=extracted.get("lga"),
            beacon_coordinates=extracted.get("beacon_coordinates") or [],
        )

    @staticmethod
    def _parties_from(extracted: dict[str, Any]) -> list[Party]:
        parties: list[Party] = []
        if extracted.get("assignor"):
            parties.append(Party(name=extracted["assignor"], role="assignor"))
        if extracted.get("assignee"):
            parties.append(Party(name=extracted["assignee"], role="assignee"))
        return parties

    @staticmethod
    def _result(
        vid: str,
        status: VerificationStatus,
        doc_type: DocumentType,
        extracted: dict[str, Any],
        ocr_confidence: float,
        fraud: dict[str, Any],
        started: float,
    ) -> VerificationResult:
        return VerificationResult(
            verification_id=vid,
            status=status,
            document_type=doc_type,
            extracted_data=extracted,
            ocr_confidence=ocr_confidence,
            fraud_detection=fraud,
            processing_time_seconds=round(time.monotonic() - started, 3),
        )


_workflow: Optional[VerificationWorkflow] = None


def get_workflow() -> VerificationWorkflow:
    global _workflow
    if _workflow is None:
        _workflow = VerificationWorkflow()
    return _workflow
