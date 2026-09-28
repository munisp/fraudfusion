"""Identity Theft Detector Service.

HARDENED: no fabricated verification results.
- Biometric / face matching is served by a pluggable torch embedding model
  (ml/artifacts/identity_embedder/v1/model.pt, override IDENTITY_MODEL_PATH).
  When the model is absent the endpoints FAIL CLOSED with
  status="model_unavailable" (HTTP 503) instead of returning fake matches.
- External registry lookups (NIMC/NIBSS/telco) require configured
  connectivity; unconfigured checks are reported as "unavailable", never
  silently "verified".
- Every route is protected by Keycloak token introspection (fail-closed;
  requires KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import time
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field

try:
    from identity_store import IdentityStore, get_store
    from registry import get_bvn_adapter, get_nin_adapter
    from cross_reference import cross_reference
except ImportError:  # when imported as a package from the repo root
    sys_path_added = str(Path(__file__).resolve().parent)
    import sys

    if sys_path_added not in sys.path:
        sys.path.insert(0, sys_path_added)
    from identity_store import IdentityStore, get_store
    from registry import get_bvn_adapter, get_nin_adapter
    from cross_reference import cross_reference

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger(__name__)

ADMIN_ROLES = {"admin", "identity_admin"}

SERVICE_NAME = "identity-theft-detector"
REPO_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = Path(os.getenv(
    "IDENTITY_MODEL_PATH",
    str(REPO_ROOT / "ml" / "artifacts" / "identity_embedder" / "v1" / "model.pt"),
))
MATCH_THRESHOLD = float(os.getenv("IDENTITY_MATCH_THRESHOLD", "0.8"))
EMBEDDING_DIM = int(os.getenv("IDENTITY_EMBEDDING_DIM", "128"))

# ---------------------------------------------------------------------------
# Keycloak auth (fail-closed)
# ---------------------------------------------------------------------------


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured")
    return value


# --- Introspection result cache (P3): token-hash TTL cache + singleflight ---
_TOKEN_CACHE_TTL = float(os.getenv("AUTH_CACHE_TTL_SECONDS", "45"))
_TOKEN_NEG_TTL = 5.0
_TOKEN_CACHE_MAX = 10000
_token_cache: dict = {}  # hash -> (expires_at, claims, exc)
_token_inflight: dict = {}
_token_cache_lock = asyncio.Lock()


def _store_token_cache(key: str, entry) -> None:
    if len(_token_cache) >= _TOKEN_CACHE_MAX:
        now = time.monotonic()
        for k in [k for k, v in _token_cache.items() if v[0] <= now]:
            del _token_cache[k]
        if len(_token_cache) >= _TOKEN_CACHE_MAX:
            return  # correctness never depends on the cache
    _token_cache[key] = entry


async def _introspect_cached(client: httpx.AsyncClient, endpoint: str, token: str, data: dict) -> dict:
    """Introspect via a bounded TTL cache keyed by token SHA-256 with
    singleflight dedup; only a cold cache hits Keycloak."""
    key = hashlib.sha256(token.encode()).hexdigest()
    async with _token_cache_lock:
        entry = _token_cache.get(key)
        if entry and entry[0] > time.monotonic():
            _, claims, exc = entry
            if exc is not None:
                raise exc
            return claims
        fut = _token_inflight.get(key)
        leader = fut is None
        if leader:
            fut = asyncio.get_running_loop().create_future()
            _token_inflight[key] = fut
    if not leader:
        claims, exc = await fut
        if exc is not None:
            raise exc
        return claims
    try:
        response = await client.post(endpoint, data=data)
        response.raise_for_status()
        claims = response.json()
        ttl = _TOKEN_CACHE_TTL if claims.get("active") is True else _TOKEN_NEG_TTL
        _store_token_cache(key, (time.monotonic() + ttl, claims, None))
        fut.set_result((claims, None))
        return claims
    except (httpx.HTTPError, ValueError) as exc:
        _store_token_cache(key, (time.monotonic() + _TOKEN_NEG_TTL, None, exc))
        fut.set_result((None, exc))
        raise
    finally:
        async with _token_cache_lock:
            _token_inflight.pop(key, None)


async def authenticate(request: Request) -> dict[str, Any]:
    """Introspect the bearer token against Keycloak. Fails closed."""
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not authorization[7:].strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required")
    token = authorization[7:].strip()

    try:
        keycloak_url = _required_env("KEYCLOAK_URL").rstrip("/")
        realm = _required_env("KEYCLOAK_REALM")
        client_id = _required_env("KEYCLOAK_CLIENT_ID")
        client_secret = _required_env("KEYCLOAK_CLIENT_SECRET")
    except RuntimeError as exc:
        # Fail closed: auth is not optional.
        logger.error("auth misconfigured: %s", exc)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="auth unavailable") from exc

    endpoint = f"{keycloak_url}/realms/{realm}/protocol/openid-connect/token/introspect"
    try:
        claims = await _introspect_cached(
            request.app.state.http_client,
            endpoint,
            token,
            {"token": token, "client_id": client_id, "client_secret": client_secret},
        )
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token validation unavailable") from exc

    if claims.get("active") is not True:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="inactive token")
    return claims


# ---------------------------------------------------------------------------
# Pluggable torch embedding model
# ---------------------------------------------------------------------------


class IdentityEmbeddingModel:
    """Torch embedding hook.

    Loads a TorchScript or state_dict checkpoint. Expected interface:
    forward(x: float32[B, D]) -> float32[B, E] embedding, where D is the
    capture-SDK feature dimension (IDENTITY_EMBEDDING_DIM). Absent weights
    mean every biometric check fails closed.
    """

    def __init__(self) -> None:
        self.model = None
        self.mode = "model_unavailable"
        if not MODEL_PATH.exists():
            logger.warning(
                "IDENTITY EMBEDDING MODEL MISSING at %s — biometric/face endpoints will FAIL CLOSED "
                "(model_unavailable). Export weights via ml/train to enable scoring.", MODEL_PATH,
            )
            return
        try:
            import torch

            try:
                self.model = torch.jit.load(str(MODEL_PATH), map_location="cpu")
            except Exception:
                from .model_def import IdentityEmbedder  # ml lane architecture hook

                self.model = IdentityEmbedder()
                self.model.load_state_dict(torch.load(str(MODEL_PATH), map_location="cpu"))
            self.model.eval()
            self.mode = "model_loaded"
            logger.info("Loaded identity embedding model from %s", MODEL_PATH)
        except Exception as exc:  # noqa: BLE001
            self.model = None
            logger.warning("IDENTITY EMBEDDING MODEL FAILED TO LOAD (%s) — failing closed.", exc)

    def embed(self, features: List[float]) -> Optional[List[float]]:
        if self.model is None:
            return None
        import torch

        with torch.no_grad():
            tensor = torch.tensor([features], dtype=torch.float32)
            embedding = self.model(tensor)[0]
            norm = embedding.norm().clamp_min(1e-9)
            return (embedding / norm).tolist()

    @staticmethod
    def cosine(a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)


def get_model(request: Request) -> IdentityEmbeddingModel:
    model = getattr(request.app.state, "embedding_model", None)
    if model is None:
        model = request.app.state.embedding_model = IdentityEmbeddingModel()
    return model


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------


class IdentityVerificationRequest(BaseModel):
    user_id: str
    nin: Optional[str] = None
    bvn: Optional[str] = None
    first_name: str
    last_name: str
    date_of_birth: str
    phone_number: str
    email: Optional[str] = None
    address: Optional[str] = None


class DocumentVerificationRequest(BaseModel):
    user_id: str
    document_type: str  # NIN, BVN, DRIVERS_LICENSE, PASSPORT, VOTERS_CARD
    document_number: str
    document_image: Optional[str] = None  # Base64 encoded
    selfie_image: Optional[str] = None  # For face matching
    # Precomputed capture-SDK feature vectors for real face matching.
    document_face_features: Optional[List[float]] = None
    selfie_face_features: Optional[List[float]] = None


class BiometricVerificationRequest(BaseModel):
    user_id: str
    biometric_type: str  # FACIAL, FINGERPRINT
    # Precomputed probe + reference feature vectors from the capture SDK.
    probe_features: Optional[List[float]] = None
    reference_features: Optional[List[float]] = None
    liveness_features: Optional[List[float]] = None


class SyntheticIdentityRequest(BaseModel):
    user_id: str
    identity_data: Dict


class CrossReferenceRequest(BaseModel):
    user_id: str
    nin: Optional[str] = None
    bvn: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    device_id: Optional[str] = None


# Nigerian document validation patterns
NIN_PATTERN = r'^\d{11}$'
BVN_PATTERN = r'^\d{11}$'
PHONE_PATTERN = r'^\+?234[0-9]{10}$|^0[0-9]{10}$'


def validate_nin(nin: str) -> bool:
    return bool(re.match(NIN_PATTERN, nin))


def validate_bvn(bvn: str) -> bool:
    return bool(re.match(BVN_PATTERN, bvn))


def validate_phone(phone: str) -> bool:
    return bool(re.match(PHONE_PATTERN, phone))


def calculate_identity_hash(identity_data: Dict) -> str:
    data_string = f"{identity_data.get('first_name', '')}{identity_data.get('last_name', '')}{identity_data.get('date_of_birth', '')}"
    return hashlib.sha256(data_string.encode()).hexdigest()


def detect_synthetic_identity_indicators(identity_data: Dict) -> List[str]:
    indicators = []
    if identity_data.get('age_from_nin') and identity_data.get('age_from_bvn'):
        if abs(identity_data['age_from_nin'] - identity_data['age_from_bvn']) > 2:
            indicators.append('age_mismatch')
    if identity_data.get('nin_issue_date'):
        issue_date = datetime.fromisoformat(identity_data['nin_issue_date'])
        if (datetime.now() - issue_date).days < 90:
            indicators.append('recently_created_nin')
    if identity_data.get('nin_address') and identity_data.get('bvn_address'):
        if identity_data['nin_address'].lower() != identity_data['bvn_address'].lower():
            indicators.append('address_mismatch')
    return indicators


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http_client = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    app.state.embedding_model = IdentityEmbeddingModel()
    yield
    await app.state.http_client.aclose()


app = FastAPI(title="Identity Theft Detector", version="2.0.0", lifespan=lifespan)


@app.get("/health")
async def health_check(request: Request, _: dict = Depends(authenticate),
                       store: IdentityStore = Depends(get_store)):
    model = get_model(request)
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "model_mode": model.mode,
        "model_path": str(MODEL_PATH),
        "registries": {
            "bvn": get_bvn_adapter(store).name,
            "nin": get_nin_adapter(store).name,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/verify-identity")
async def verify_identity(request: IdentityVerificationRequest, _: dict = Depends(authenticate),
                          store: IdentityStore = Depends(get_store)):
    """Format-level identity verification. Registry lookups fail closed."""
    logger.info("Identity verification request for user %s", request.user_id)

    risk_score = 0
    verification_results: Dict[str, Any] = {}
    red_flags: List[str] = []

    nin_adapter = get_nin_adapter(store)
    bvn_adapter = get_bvn_adapter(store)
    registry_statuses: List[str] = []

    if request.nin:
        verification_results['nin_valid'] = validate_nin(request.nin)
        if not verification_results['nin_valid']:
            risk_score += 30
            red_flags.append('invalid_nin_format')
        else:
            nin_lookup = nin_adapter.lookup(request.nin)
            registry_statuses.append(nin_lookup['status'])
            verification_results['nin_registry'] = nin_lookup['status']
            verification_results['nin_registry_adapter'] = nin_lookup.get('adapter')
            if nin_lookup['status'] == 'not_found':
                risk_score += 25
                red_flags.append('nin_not_in_registry')
            elif nin_lookup['status'] == 'found':
                record = nin_lookup.get('record') or {}
                if record.get('is_synthetic') or nin_lookup.get('is_synthetic'):
                    verification_results['nin_registry_synthetic'] = True

    if request.bvn:
        verification_results['bvn_valid'] = validate_bvn(request.bvn)
        if not verification_results['bvn_valid']:
            risk_score += 30
            red_flags.append('invalid_bvn_format')
        else:
            bvn_lookup = bvn_adapter.lookup(request.bvn)
            registry_statuses.append(bvn_lookup['status'])
            verification_results['bvn_registry'] = bvn_lookup['status']
            verification_results['bvn_registry_adapter'] = bvn_lookup.get('adapter')
            if bvn_lookup['status'] == 'not_found':
                risk_score += 25
                red_flags.append('bvn_not_in_registry')

    verification_results['phone_valid'] = validate_phone(request.phone_number)
    if not verification_results['phone_valid']:
        risk_score += 10
        red_flags.append('invalid_phone_format')

    # Stolen-identity check: real query against the alerts store.
    alerts = store.query(
        "SELECT id FROM identity_theft_alerts WHERE user_id = :u LIMIT 1",
        {"u": request.user_id},
    )
    verification_results['stolen_identity_registry'] = 'flagged' if alerts else 'clear'
    if alerts:
        risk_score += 40
        red_flags.append('prior_identity_theft_alert')
    identity_hash = calculate_identity_hash(request.model_dump())
    verification_results['identity_hash'] = identity_hash

    # Fail-closed posture: "verified" requires at least one registry to have
    # actually confirmed the identifier; unavailable/not_found never verify.
    registry_available = bool(registry_statuses) and all(s == 'found' for s in registry_statuses)
    if risk_score >= 70:
        risk_level = 'critical'
    elif risk_score >= 40:
        risk_level = 'high'
    elif risk_score >= 20:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    return {
        'user_id': request.user_id,
        'is_verified': registry_available and risk_score < 40,
        'verification_status': (
            'registry_verified' if registry_available else
            ('registry_unavailable' if any(s == 'unavailable' for s in registry_statuses) or not registry_statuses
             else 'registry_checked')
        ),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'verification_results': verification_results,
        'red_flags': red_flags,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@app.post("/verify-document")
async def verify_document(request: DocumentVerificationRequest, http_request: Request, _: dict = Depends(authenticate)):
    """Document format validation + real face matching via embedding model."""
    logger.info("Document verification for user %s, type %s", request.user_id, request.document_type)

    risk_score = 0
    verification_details: Dict[str, Any] = {}

    format_lengths = {'DRIVERS_LICENSE': 10, 'PASSPORT': 8, 'VOTERS_CARD': 10}
    if request.document_type == 'NIN':
        verification_details['format_valid'] = validate_nin(request.document_number)
    elif request.document_type == 'BVN':
        verification_details['format_valid'] = validate_bvn(request.document_number)
    elif request.document_type in format_lengths:
        verification_details['format_valid'] = len(request.document_number) >= format_lengths[request.document_type]
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"unsupported document_type {request.document_type}")
    if not verification_details['format_valid']:
        risk_score += 40

    # Real face matching: requires both feature vectors AND the model.
    if request.selfie_face_features and request.document_face_features:
        model = get_model(http_request)
        # torch CPU inference holds the GIL — run it in a worker thread.
        probe = await asyncio.to_thread(model.embed, request.selfie_face_features)
        reference = await asyncio.to_thread(model.embed, request.document_face_features)
        if probe is None or reference is None:
            logger.warning("face_match requested but model unavailable — failing closed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"status": "model_unavailable", "detail": "face matching model not loaded"},
            )
        match_score = model.cosine(probe, reference)
        verification_details['face_match'] = {
            'match_score': round(match_score, 6),
            'is_match': match_score >= MATCH_THRESHOLD,
            'model_mode': model.mode,
        }
        if match_score < MATCH_THRESHOLD:
            risk_score += 50
    elif request.selfie_image or request.document_image:
        # Raw images without a featurizer cannot be matched honestly.
        verification_details['face_match'] = {
            'status': 'unavailable',
            'detail': 'provide capture-SDK feature vectors (selfie_face_features/document_face_features)',
        }

    if risk_score >= 60:
        risk_level, is_authentic = 'high', False
    elif risk_score >= 30:
        risk_level, is_authentic = 'medium', True
    else:
        risk_level, is_authentic = 'low', True

    return {
        'user_id': request.user_id,
        'document_type': request.document_type,
        'is_authentic': is_authentic,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'verification_details': verification_details,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@app.post("/verify-biometric")
async def verify_biometric(request: BiometricVerificationRequest, http_request: Request, _: dict = Depends(authenticate)):
    """Biometric matching via the torch embedding model. Fails closed."""
    logger.info("Biometric verification for user %s, type %s", request.user_id, request.biometric_type)

    if request.biometric_type not in {'FACIAL', 'FINGERPRINT'}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported biometric_type")
    if not request.probe_features or not request.reference_features:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="probe_features and reference_features are required (capture-SDK feature vectors)",
        )

    model = get_model(http_request)
    probe = await asyncio.to_thread(model.embed, request.probe_features)
    reference = await asyncio.to_thread(model.embed, request.reference_features)
    if probe is None or reference is None:
        logger.warning("biometric requested but model unavailable — failing closed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "model_unavailable", "detail": "biometric embedding model not loaded"},
        )

    match_score = model.cosine(probe, reference)
    verification_result = {
        'match_score': round(match_score, 6),
        'is_match': match_score >= MATCH_THRESHOLD,
        'model_mode': model.mode,
        # Liveness requires a dedicated liveness model; never fabricate it.
        'liveness': 'not_evaluated',
    }

    return {
        'user_id': request.user_id,
        'biometric_type': request.biometric_type,
        'verification_result': verification_result,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@app.post("/detect-synthetic-identity")
async def detect_synthetic_identity(request: SyntheticIdentityRequest, _: dict = Depends(authenticate)):
    indicators = detect_synthetic_identity_indicators(request.identity_data)
    risk_score = len(indicators) * 20

    if risk_score >= 60:
        risk_level, is_synthetic = 'critical', True
    elif risk_score >= 40:
        risk_level, is_synthetic = 'high', True
    else:
        risk_level, is_synthetic = 'low', False

    return {
        'user_id': request.user_id,
        'is_synthetic': is_synthetic,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'indicators': indicators,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@app.post("/cross-reference-check")
async def cross_reference_check(request: CrossReferenceRequest, _: dict = Depends(authenticate),
                                  store: IdentityStore = Depends(get_store)):
    """Real cross-reference over customer_identifiers + BVN/NIN registries +
    identity_theft_alerts. Returns matched identity clusters with evidence
    links; `searched_sources` always lists every consulted source so an empty
    result demonstrably means "no matches", never "didn't look"."""
    logger.info("Cross-reference check for user %s", request.user_id)

    result = await asyncio.to_thread(
        cross_reference,
        store,
        get_bvn_adapter(store),
        get_nin_adapter(store),
        user_id=request.user_id,
        nin=request.nin,
        bvn=request.bvn,
        phone=request.phone_number,
        email=request.email,
        device=request.device_id,
    )

    return {
        'user_id': request.user_id,
        'matched_customers': result['matched_customers'],
        'clusters': result['clusters'],
        'alerts': result['alerts'],
        'cross_reference_results': result['source_results'],
        'inconsistencies': result['inconsistencies'],
        'risk_score': result['risk_score'],
        'all_checks_passed': not result['clusters'] and not result['alerts']
                             and not result['inconsistencies'],
        'searched_sources': result['searched_sources'],
        'checks_status': result['checks_status'],
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@app.post("/admin/registry/import")
async def import_registry(
    registry: str = Form(...),
    file: UploadFile = File(...),
    claims: dict = Depends(authenticate),
    store: IdentityStore = Depends(get_store),
):
    """Admin CSV import for the local BVN/NIN registries.

    CSV header: `<bvn|nin>,full_name,date_of_birth,phone_number,email`
    Rows are upserted with provenance `admin-import:<filename>` and the
    importing principal recorded. Requires the admin or identity_admin realm
    role. Rows imported here are REAL data (is_synthetic=false) — unlike the
    clearly-marked synthetic seed rows.
    """
    roles = set((claims.get("realm_access") or {}).get("roles") or [])
    if not roles & ADMIN_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"requires one of: {sorted(ADMIN_ROLES)}")
    if registry not in ("bvn", "nin"):
        raise HTTPException(status_code=400, detail="registry must be 'bvn' or 'nin'")
    raw = await file.read()
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV exceeds 20MB limit")
    if not raw.strip():
        raise HTTPException(status_code=422, detail="empty CSV")

    import csv
    import io

    table = f"{registry}_registry"
    provenance = f"admin-import:{file.filename or 'upload.csv'}"
    imported_by = claims.get("sub", "unknown")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace")))
    required = {registry, "full_name"}
    if not reader.fieldnames or not required <= {f.strip() for f in reader.fieldnames}:
        raise HTTPException(status_code=422,
                            detail=f"CSV header must include {sorted(required)}")

    imported, rejected = 0, []
    validator = validate_bvn if registry == "bvn" else validate_nin
    for i, row in enumerate(reader, start=2):  # header is line 1
        id_value = (row.get(registry) or "").strip()
        full_name = (row.get("full_name") or "").strip()
        if not id_value or not full_name:
            rejected.append({"line": i, "reason": "missing id or full_name"})
            continue
        if not validator(id_value):
            rejected.append({"line": i, "reason": f"invalid {registry} format"})
            continue
        if store._is_pg:
            store.execute(
                f"INSERT INTO {table} ({registry}, full_name, date_of_birth, phone_number, email,"
                f" is_synthetic, provenance, imported_by) VALUES (:idv, :name, :dob, :phone, :email,"
                f" FALSE, :prov, :by) ON CONFLICT (tenant_id, {registry}) DO UPDATE SET"
                f" full_name = EXCLUDED.full_name, date_of_birth = EXCLUDED.date_of_birth,"
                f" phone_number = EXCLUDED.phone_number, email = EXCLUDED.email,"
                f" provenance = EXCLUDED.provenance, imported_by = EXCLUDED.imported_by",
                {"idv": id_value, "name": full_name, "dob": (row.get("date_of_birth") or "").strip() or None,
                 "phone": (row.get("phone_number") or "").strip() or None,
                 "email": (row.get("email") or "").strip() or None,
                 "prov": provenance, "by": imported_by},
            )
        else:
            store.execute(
                f"INSERT INTO {table} ({registry}, full_name, date_of_birth, phone_number, email,"
                f" is_synthetic, provenance, imported_by) VALUES (:idv, :name, :dob, :phone, :email,"
                f" 0, :prov, :by) ON CONFLICT (tenant_id, {registry}) DO UPDATE SET"
                f" full_name = excluded.full_name, date_of_birth = excluded.date_of_birth,"
                f" phone_number = excluded.phone_number, email = excluded.email,"
                f" provenance = excluded.provenance, imported_by = excluded.imported_by",
                {"idv": id_value, "name": full_name, "dob": (row.get("date_of_birth") or "").strip() or None,
                 "phone": (row.get("phone_number") or "").strip() or None,
                 "email": (row.get("email") or "").strip() or None,
                 "prov": provenance, "by": imported_by},
            )
        imported += 1
    logger.info("registry import: table=%s imported=%d rejected=%d by=%s",
                table, imported, len(rejected), imported_by)
    return {
        "registry": table,
        "imported": imported,
        "rejected": rejected[:100],
        "rejected_count": len(rejected),
        "provenance": provenance,
        "imported_by": imported_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/identity-theft-alerts")
async def get_identity_theft_alerts(_: dict = Depends(authenticate)):
    """Alerts require a configured alert store (DATABASE_URL); fail closed."""
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="alert store not configured (set DATABASE_URL)",
        )
    import psycopg2

    try:
        with psycopg2.connect(database_url) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT alert_id, user_id, alert_type, risk_level, created_at "
                "FROM identity_theft_alerts ORDER BY created_at DESC LIMIT 50"
            )
            alerts = [
                {
                    'alert_id': row[0], 'user_id': row[1], 'alert_type': row[2],
                    'risk_level': row[3], 'timestamp': row[4].isoformat(),
                }
                for row in cur.fetchall()
            ]
    except Exception as exc:  # noqa: BLE001
        logger.error("alert store query failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="alert store unavailable") from exc
    return {'alerts': alerts, 'count': len(alerts)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8089")))
