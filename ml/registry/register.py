"""MLflow model-registry helper with graceful local fallback.

Logs params/metrics/artifacts to an MLflow tracking server
(env MLFLOW_TRACKING_URI, default http://localhost:5000). When the server is
unreachable, falls back to a local file registry at
ml/registry/local_registry.json so registration ALWAYS works.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

LOCAL_REGISTRY = Path(__file__).resolve().parent / "local_registry.json"


def _mlflow_available(uri: str, timeout: float = 3.0) -> bool:
    import socket
    from urllib.parse import urlparse
    u = urlparse(uri)
    try:
        with socket.create_connection((u.hostname or "localhost",
                                       u.port or 5000), timeout=timeout):
            return True
    except OSError:
        return False


def _local_log(entry: dict) -> str:
    reg = json.loads(LOCAL_REGISTRY.read_text()) if LOCAL_REGISTRY.exists() else {"runs": []}
    entry = dict(entry)
    entry["run_id"] = f"local-{int(time.time() * 1000)}"
    entry["registered_at"] = datetime.now(timezone.utc).isoformat()
    entry["backend"] = "local_file"
    reg["runs"].append(entry)
    LOCAL_REGISTRY.write_text(json.dumps(reg, indent=2))
    return entry["run_id"]


def register(model_name: str, artifact_dir: str, params: dict | None = None,
             metrics: dict | None = None, tags: dict | None = None,
             tracking_uri: str | None = None) -> str:
    """Register a model run; returns run_id. Falls back to local registry."""
    uri = tracking_uri or os.environ.get("MLFLOW_TRACKING_URI",
                                         "http://localhost:5000")
    metrics = metrics or {}
    params = params or {}
    artifact_dir = str(artifact_dir)

    mpath = Path(artifact_dir) / "metrics.json"
    if not metrics and mpath.exists():
        metrics = json.loads(mpath.read_text())

    if _mlflow_available(uri):
        try:
            import mlflow
            mlflow.set_tracking_uri(uri)
            mlflow.set_experiment("fraudfusion")
            with mlflow.start_run(run_name=model_name) as run:
                mlflow.log_params({k: str(v) for k, v in params.items()})
                mlflow.log_metrics({k: float(v) for k, v in metrics.items()
                                    if isinstance(v, (int, float))})
                mlflow.log_artifacts(artifact_dir)
                mlflow.set_tags({"provenance": "synthetic", **(tags or {})})
                mlflow.register_model(
                    f"runs:/{run.info.run_id}/artifacts", model_name)
                print(f"mlflow run_id={run.info.run_id} registered as {model_name}")
                return run.info.run_id
        except Exception as e:  # noqa: BLE001 - degrade gracefully
            print(f"mlflow failed ({e}); falling back to local registry")

    rid = _local_log(dict(model_name=model_name, artifact_dir=artifact_dir,
                          params=params, metrics=metrics, tags=tags or {}))
    print(f"local registry run_id={rid} ({LOCAL_REGISTRY})")
    return rid


def list_runs() -> list[dict]:
    if LOCAL_REGISTRY.exists():
        return json.loads(LOCAL_REGISTRY.read_text())["runs"]
    return []


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--artifact-dir", required=True)
    ap.add_argument("--params", default="{}")
    a = ap.parse_args()
    register(a.model, a.artifact_dir, params=json.loads(a.params))
