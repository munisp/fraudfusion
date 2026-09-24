"""AML ML inference service (FastAPI, port 8100).

Called by services/go/aml-monitor at http://localhost:8100/v1/aml/score.

Loads the champion fraud model from the ml/ lane artifact contract:
    ml/artifacts/fraud_net/v1/model.onnx   (CPU, onnxruntime; also accepts
    fraud_net.onnx for forward compatibility with the lane's export naming)

Feature contract (mirrors ml/data/synthetic_nigeria.py — kept in sync by
convention, no code import across lanes):
    x_num: NUMERIC_FEATURES (16, standardized with preprocess.npz scaler)
    x_cat: CATEGORICAL_FEATURES (5, encoded via vocab.json, OOV -> 0)
    output: fraud_prob in [0, 1]

If the ONNX artifact is missing (or fails to load), the service falls back
to a transparent rule-based scorer and logs a LOUD warning. The fallback is
never silent: /health and every response carry ``"model_mode": "rule_fallback"``.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("aml-service")

SERVICE_NAME = "aml-ml-service"
MODEL_NAME = os.getenv("AML_MODEL_NAME", "fraud_net")
MODEL_VERSION = os.getenv("AML_MODEL_VERSION", "v1")
def _default_artifact_dir() -> Path:
    rel = Path("ml") / "artifacts" / MODEL_NAME / MODEL_VERSION
    # Repo checkout: <repo>/mlops/serving/aml_service.py -> <repo>/ml/...
    repo_root = Path(__file__).resolve().parents[2]
    for candidate in (repo_root / rel, Path.cwd() / rel, Path("/app") / rel):
        if candidate.exists():
            return candidate
    return repo_root / rel  # default (reported in load error)


ARTIFACT_DIR = Path(os.getenv("AML_ARTIFACT_DIR", str(_default_artifact_dir())))
# The ml lane exports model.onnx; fraud_net.onnx kept as an accepted alias.
MODEL_PATH = Path(os.getenv("AML_MODEL_PATH", "")) if os.getenv("AML_MODEL_PATH") else next(
    (p for p in (ARTIFACT_DIR / f"{MODEL_NAME}.onnx", ARTIFACT_DIR / "model.onnx") if p.exists()),
    ARTIFACT_DIR / "model.onnx",
)

# ml lane contract (mirrors ml/data/synthetic_nigeria.py — do not import).
NUMERIC_FEATURES = [
    "log_amount", "hour", "dow", "is_month_end", "is_market_day",
    "amount_vs_sender_avg", "sender_txns_24h", "sender_unique_receivers_72h",
    "receiver_fanin_72h", "mins_since_last_txn", "device_emulator",
    "sim_swap_7d", "new_device", "cross_state", "cross_bank", "is_night",
]
CATEGORICAL_FEATURES = ["channel", "sender_bank", "receiver_bank", "sender_state", "device_os"]
HIGH_RISK_THRESHOLD = float(os.getenv("AML_HIGH_RISK_THRESHOLD", "0.7"))
MEDIUM_RISK_THRESHOLD = float(os.getenv("AML_MEDIUM_RISK_THRESHOLD", "0.4"))

# Kept for backwards compatibility with single-input ONNX models only.
FEATURE_NAMES: list[str] = NUMERIC_FEATURES

# ---------------------------------------------------------------------------
# Metrics (Prometheus textfile exposition, no hard dependency on a registry)
# ---------------------------------------------------------------------------
try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

    REQUEST_COUNT = Counter(
        "aml_score_requests_total", "Total /v1/aml/score requests", ["model_mode", "risk_level"]
    )
    REQUEST_LATENCY = Histogram(
        "aml_score_latency_seconds",
        "End-to-end scoring latency",
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
    )
    INFER_LATENCY = Histogram(
        "aml_model_inference_seconds", "ONNX inference latency only"
    )
    FALLBACK_COUNT = Counter(
        "aml_rule_fallback_total", "Requests served by the rule-based fallback"
    )
    PROMETHEUS = True
except ImportError:  # pragma: no cover - metrics optional
    PROMETHEUS = False
    logger.warning("prometheus_client not installed; /metrics endpoint disabled")


# ---------------------------------------------------------------------------
# Model wrapper
# ---------------------------------------------------------------------------
class FraudModel:
    """ONNX-backed scorer implementing the ml lane artifact contract.

    Loads vocab.json + preprocess.npz from the artifact dir when present and
    encodes (x_num standardized, x_cat via vocab). Falls back to a generic
    single-input float vector when the model has one input and no vocab.
    """

    def __init__(self) -> None:
        self.session = None
        self.input_names: list[str] = []
        self.model_mode = "rule_fallback"
        self.load_error: str | None = None
        self.vocab: dict[str, dict[str, int]] = {}
        self.scaler_mean: np.ndarray | None = None
        self.scaler_std: np.ndarray | None = None
        self._try_load()

    def _try_load(self) -> None:
        if not MODEL_PATH.exists():
            self.load_error = f"artifact not found: {MODEL_PATH}"
            logger.warning(
                "AML MODEL ARTIFACT MISSING at %s — serving with RULE-BASED FALLBACK. "
                "Scores are heuristic, NOT ML. Train/export via ml/train to enable the ONNX model.",
                MODEL_PATH,
            )
            return
        try:
            import onnxruntime as ort

            vocab_path = ARTIFACT_DIR / "vocab.json"
            if vocab_path.exists():
                self.vocab = json.loads(vocab_path.read_text())
            preprocess_path = ARTIFACT_DIR / "preprocess.npz"
            if preprocess_path.exists():
                prep = np.load(preprocess_path)
                self.scaler_mean, self.scaler_std = prep["scaler_mean"], prep["scaler_std"]

            self.session = ort.InferenceSession(
                str(MODEL_PATH), providers=["CPUExecutionProvider"]
            )
            self.input_names = [i.name for i in self.session.get_inputs()]
            self.model_mode = "onnx"
            logger.info(
                "Loaded AML ONNX model from %s (inputs=%s, vocab=%s, scaler=%s)",
                MODEL_PATH, self.input_names, bool(self.vocab), self.scaler_mean is not None,
            )
        except Exception as exc:  # noqa: BLE001 - never crash on load
            self.session = None
            self.load_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "AML MODEL FAILED TO LOAD (%s) — serving with RULE-BASED FALLBACK. "
                "Scores are heuristic, NOT ML.",
                self.load_error,
            )

    def encode(self, features: dict[str, float], categoricals: dict[str, str]) -> dict[str, np.ndarray]:
        """Build model inputs per the ml lane contract."""
        if "x_num" in self.input_names:
            x_num = np.array(
                [[float(features.get(f, 0.0)) for f in NUMERIC_FEATURES]], dtype=np.float32
            )
            if self.scaler_mean is not None and self.scaler_std is not None:
                x_num = ((x_num - self.scaler_mean) / self.scaler_std).astype(np.float32)
            inputs: dict[str, np.ndarray] = {"x_num": x_num}
            if "x_cat" in self.input_names:
                x_cat = np.zeros((1, len(CATEGORICAL_FEATURES)), dtype=np.int64)
                # sorted() matches the ml lane embedding order.
                for j, name in enumerate(sorted(CATEGORICAL_FEATURES)):
                    x_cat[0, j] = self.vocab.get(name, {}).get(str(categoricals.get(name, "")), 0)
                inputs["x_cat"] = x_cat
            return inputs
        # Generic single-input model: flat feature vector.
        input_meta = self.session.get_inputs()[0]
        shape = input_meta.shape
        dim = shape[1] if len(shape) >= 2 and isinstance(shape[1], int) and shape[1] > 0 else len(FEATURE_NAMES)
        vec = np.zeros(dim, dtype=np.float32)
        for i, name in enumerate(FEATURE_NAMES[:dim]):
            vec[i] = float(features.get(name, 0.0))
        return {input_meta.name: vec.reshape(1, -1)}

    def predict_proba(self, features: dict[str, float], categoricals: dict[str, str] | None = None) -> float:
        """Return fraud probability in [0, 1]."""
        if self.session is None:
            return rule_based_score(features)
        outputs = self.session.run(None, self.encode(features, categoricals or {}))
        value = float(np.asarray(outputs[0]).reshape(-1)[0])
        # Raw logits -> sigmoid; probabilities pass through unchanged.
        if value < 0.0 or value > 1.0:
            value = 1.0 / (1.0 + math.exp(-value))
        return value


# ---------------------------------------------------------------------------
# Rule-based fallback (transparent, deterministic)
# ---------------------------------------------------------------------------
def rule_based_score(features: dict[str, float]) -> float:
    score = 0.05
    log_amount = features.get("log_amount", 0.0)
    if log_amount >= math.log1p(1_000_000):
        score += 0.35
    elif log_amount >= math.log1p(100_000):
        score += 0.20
    elif log_amount >= math.log1p(10_000):
        score += 0.08
    if features.get("cross_state", 0.0) >= 1.0:
        score += 0.05
    if features.get("cross_bank", 0.0) >= 1.0:
        score += 0.05
    if features.get("sender_txns_24h", 0.0) >= 10:
        score += 0.15
    elif features.get("sender_txns_24h", 0.0) >= 5:
        score += 0.08
    if features.get("amount_vs_sender_avg", 0.0) >= 10:
        score += 0.20
    elif features.get("amount_vs_sender_avg", 0.0) >= 5:
        score += 0.10
    if features.get("new_device", 0.0) >= 1.0:
        score += 0.05
    if features.get("device_emulator", 0.0) >= 1.0:
        score += 0.15
    if features.get("sim_swap_7d", 0.0) >= 1.0:
        score += 0.15
    if features.get("receiver_fanin_72h", 0.0) >= 20:
        score += 0.10
    if features.get("is_night", 0.0) >= 1.0:
        score += 0.05
    return min(score, 0.99)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------
class AMLScoreRequest(BaseModel):
    transaction_id: str = Field(min_length=1, max_length=128)
    user_id: str = Field(min_length=1, max_length=128)
    amount: float = Field(ge=0, le=1e12)
    currency: str = Field(default="NGN", min_length=3, max_length=3)
    transaction_type: str = Field(default="transfer", max_length=64)
    country_code: str = Field(default="NG", min_length=2, max_length=2)
    timestamp: int | None = None  # epoch seconds; defaults to now
    # Optional pre-computed numeric features (NUMERIC_FEATURES names) and
    # categorical attributes (CATEGORICAL_FEATURES names) from the caller.
    features: dict[str, float] = Field(default_factory=dict)
    categoricals: dict[str, str] = Field(default_factory=dict)

    @field_validator("currency", "country_code")
    @classmethod
    def upper(cls, value: str) -> str:
        return value.upper()


class AMLScoreResponse(BaseModel):
    transaction_id: str
    risk_score: float
    risk_level: str
    flagged: bool
    sar_required: bool
    recommendation: str
    model_mode: str
    model_name: str
    model_version: str
    latency_ms: float
    detailed_scores: dict[str, float]


def build_features(req: AMLScoreRequest) -> dict[str, float]:
    """Derive ml-contract numeric features from the transaction; caller
    overrides win (req.features)."""
    ts = req.timestamp or int(time.time())
    local = time.gmtime(ts)
    feats = dict(req.features)
    feats.setdefault("log_amount", math.log1p(req.amount))
    feats.setdefault("hour", float(local.tm_hour))
    feats.setdefault("dow", float(local.tm_wday))
    feats.setdefault("is_night", 1.0 if local.tm_hour < 6 else 0.0)
    feats.setdefault("cross_state", 0.0 if req.country_code == "NG" else 1.0)
    return feats


def risk_band(score: float) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "high"
    if score >= MEDIUM_RISK_THRESHOLD:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.model = FraudModel()
    app.state.requests_served = 0
    app.state.total_latency_ms = 0.0
    yield


app = FastAPI(title="AML ML Inference Service", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health(request: Request) -> dict[str, Any]:
    model: FraudModel = request.app.state.model
    avg_latency = (
        request.app.state.total_latency_ms / request.app.state.requests_served
        if request.app.state.requests_served
        else 0.0
    )
    payload: dict[str, Any] = {
        "status": "healthy",
        "service": SERVICE_NAME,
        "model_mode": model.model_mode,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "model_path": str(MODEL_PATH),
        "model_inputs": model.input_names,
        "requests_served": request.app.state.requests_served,
        "avg_latency_ms": round(avg_latency, 3),
    }
    if model.load_error:
        payload["model_load_error"] = model.load_error
    return payload


@app.get("/metrics")
async def metrics() -> Response:
    if not PROMETHEUS:
        raise HTTPException(status_code=501, detail="prometheus_client not installed")
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/v1/aml/score", response_model=AMLScoreResponse)
async def score(req: AMLScoreRequest, request: Request) -> AMLScoreResponse:
    start = time.perf_counter()
    model: FraudModel = request.app.state.model
    features = build_features(req)

    infer_start = time.perf_counter()
    risk = model.predict_proba(features, req.categoricals)
    infer_ms = (time.perf_counter() - infer_start) * 1000

    level = risk_band(risk)
    flagged = risk >= MEDIUM_RISK_THRESHOLD
    sar_required = risk >= HIGH_RISK_THRESHOLD
    recommendation = (
        "file_sar_and_block" if sar_required
        else "step_up_verification" if flagged
        else "allow"
    )
    latency_ms = (time.perf_counter() - start) * 1000

    request.app.state.requests_served += 1
    request.app.state.total_latency_ms += latency_ms
    if PROMETHEUS:
        REQUEST_COUNT.labels(model_mode=model.model_mode, risk_level=level).inc()
        REQUEST_LATENCY.observe(latency_ms / 1000)
        INFER_LATENCY.observe(infer_ms / 1000)
        if model.model_mode == "rule_fallback":
            FALLBACK_COUNT.inc()

    return AMLScoreResponse(
        transaction_id=req.transaction_id,
        risk_score=round(risk, 6),
        risk_level=level,
        flagged=flagged,
        sar_required=sar_required,
        recommendation=recommendation,
        model_mode=model.model_mode,
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        latency_ms=round(latency_ms, 3),
        detailed_scores={"fraud_probability": round(risk, 6), "inference_ms": round(infer_ms, 3)},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8100")))
