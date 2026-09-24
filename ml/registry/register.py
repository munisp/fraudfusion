"""MLflow model-registry helper with graceful local fallback.

Logs params/metrics/artifacts to an MLflow tracking server
(env MLFLOW_TRACKING_URI, default http://localhost:5000). When the server is
unreachable, falls back to a local file registry at
ml/registry/local_registry.json so registration ALWAYS works.
"""
from __future__ import annotations

import json
import os
import sys
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


def _local_promote(model_name: str, version: str, stage: str,
                   alias: str | None = None) -> dict:
    """Stage promotion in the local file registry.

    Marks the matching run with the stage and, if `alias` is given, moves the
    alias pointer (champion/challenger) to this model+version. Returns the
    promotion record.
    """
    reg = json.loads(LOCAL_REGISTRY.read_text()) if LOCAL_REGISTRY.exists() \
        else {"runs": []}
    matches = [r for r in reg.get("runs", [])
               if r.get("model_name") == model_name and
               (r.get("params", {}).get("version") == version or
                r.get("artifact_dir", "").rstrip("/").endswith(f"/{version}"))]
    if not matches:
        raise KeyError(
            f"no local registry run for {model_name} version {version}")
    target = matches[-1]
    target["stage"] = stage
    target["promoted_at"] = datetime.now(timezone.utc).isoformat()
    reg.setdefault("aliases", {})
    if alias:
        reg["aliases"][alias] = {"model_name": model_name, "version": version,
                                 "set_at": target["promoted_at"]}
    reg.setdefault("promotions", []).append(dict(
        model_name=model_name, version=version, stage=stage, alias=alias,
        at=target["promoted_at"], backend="local_file"))
    LOCAL_REGISTRY.write_text(json.dumps(reg, indent=2))
    return reg["promotions"][-1]


def promote(model_name: str, version: str, stage: str = "Production",
            alias: str | None = None, tracking_uri: str | None = None) -> dict:
    """Promote a registered model version to a stage (and optional alias).

    Server mode (MLFLOW_TRACKING_URI reachable): uses
    MlflowClient.transition_model_version_stage and, when `alias` is set,
    MlflowClient.set_registered_model_alias (e.g. alias="champion" — the
    pointer consumed by mlops/serving/model_router.py and retrain.sh).
    Local mode: updates local_registry.json (stage field + aliases map).

    Example: python -m ml.registry.register promote --model fraud_net \\
        --version v3 --stage Production --alias champion
    """
    uri = tracking_uri or os.environ.get("MLFLOW_TRACKING_URI",
                                         "http://localhost:5000")
    if _mlflow_available(uri):
        try:
            import mlflow
            client = mlflow.tracking.MlflowClient(uri)
            mv = None
            for v in client.search_model_versions(f"name='{model_name}'"):
                if str(v.version) == str(version) or \
                        v.tags.get("version") == str(version):
                    mv = v
                    break
            if mv is None:
                raise KeyError(
                    f"no registered model version {version} for {model_name}")
            client.transition_model_version_stage(
                name=model_name, version=mv.version, stage=stage,
                archive_existing_versions=False)
            if alias:
                client.set_registered_model_alias(model_name, alias, mv.version)
            rec = dict(model_name=model_name, version=str(mv.version),
                       stage=stage, alias=alias, backend="mlflow")
            print(f"promoted {model_name} v{mv.version} -> {stage}"
                  + (f" (alias={alias})" if alias else ""))
            return rec
        except Exception as e:  # noqa: BLE001 - degrade gracefully
            print(f"mlflow promotion failed ({e}); using local registry")
    rec = _local_promote(model_name, version, stage, alias)
    print(f"local promotion: {model_name} {version} -> {stage}"
          + (f" (alias={alias})" if alias else ""))
    return rec


def list_runs() -> list[dict]:
    if LOCAL_REGISTRY.exists():
        return json.loads(LOCAL_REGISTRY.read_text())["runs"]
    return []


if __name__ == "__main__":
    import argparse
    if len(sys.argv) > 1 and sys.argv[1] in ("register", "promote"):
        ap = argparse.ArgumentParser()
        sub = ap.add_subparsers(dest="cmd", required=True)
        rp = sub.add_parser("register", help="log + register a model run")
        rp.add_argument("--model", required=True)
        rp.add_argument("--artifact-dir", required=True)
        rp.add_argument("--params", default="{}")
        pp = sub.add_parser("promote", help="promote a version to stage/alias")
        pp.add_argument("--model", required=True)
        pp.add_argument("--version", required=True)
        pp.add_argument("--stage", default="Production")
        pp.add_argument("--alias", default=None,
                        help="e.g. champion / challenger")
        a = ap.parse_args()
        if a.cmd == "promote":
            promote(a.model, a.version, a.stage, a.alias)
        else:
            register(a.model, a.artifact_dir, params=json.loads(a.params))
    else:  # legacy invocation: --model X --artifact-dir Y
        ap = argparse.ArgumentParser()
        ap.add_argument("--model", required=True)
        ap.add_argument("--artifact-dir", required=True)
        ap.add_argument("--params", default="{}")
        a = ap.parse_args()
        register(a.model, a.artifact_dir, params=json.loads(a.params))
