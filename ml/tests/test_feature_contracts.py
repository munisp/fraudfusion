"""Static feature-contract tests: detector-side feature construction must
match the model artifact's declared schema (names, order, dims).

Pairs covered:
  * aml-monitor (mlops/serving/aml_service.py) <-> fraud_net artifacts
    (vocab.json categorical keys + order, preprocess.npz scaler dims,
    ONNX x_num/x_cat input dims) and the ml-lane source of truth
    (ml/data/synthetic_nigeria.py).
  * account-takeover-detector (services/python/account-takeover-detector)
    hybrid blend <-> fraud_net artifacts (same contract; blend consumes the
    same x_num/x_cat encoding).
  * gnn_mule: ml/inference/predict.score_gnn consumes preprocess.npz scaler
    dims == NODE_FEATURE_NAMES == MuleGNN input width (weights.pt).

Service feature lists are extracted by AST (static parse, no import of
service dependencies). A swapped or missing feature must fail these tests;
``test_contract_check_catches_swap_and_missing`` is a meta-test proving it.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parents[2]
AML_SERVICE = REPO / "mlops" / "serving" / "aml_service.py"
ATO_SERVICE = REPO / "services" / "python" / "account-takeover-detector" / "main.py"
ML_SOURCE = REPO / "ml" / "data" / "synthetic_nigeria.py"
FRAUD_NET_ART = REPO / "ml" / "artifacts" / "fraud_net"
GNN_ART = REPO / "ml" / "artifacts" / "gnn_mule" / "v2"


# ---------------------------------------------------------------------------
# AST helpers: extract top-level list-of-strings assignments from a module
# ---------------------------------------------------------------------------
def extract_str_list(path: Path, name: str) -> list[str]:
    tree = ast.parse(path.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return [elt.value for elt in node.value.elts]
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.target.id == name:
            return [elt.value for elt in node.value.elts]
    raise AssertionError(f"{name} not found in {path}")


def check_contract(service_num: list[str], service_cat: list[str],
                   ref_num: list[str], ref_cat: list[str]) -> list[str]:
    """Return list of contract violations (empty == OK). Order matters for
    numerics (positional x_num) and sorted-categoricals (positional x_cat)."""
    errors = []
    if service_num != ref_num:
        if sorted(service_num) == sorted(ref_num):
            errors.append("numeric feature ORDER differs (same names, "
                          "swapped positions)")
        else:
            missing = set(ref_num) - set(service_num)
            extra = set(service_num) - set(ref_num)
            errors.append(f"numeric feature mismatch: missing={missing} "
                          f"extra={extra}")
    if service_cat != ref_cat:
        if sorted(service_cat) == sorted(ref_cat):
            errors.append("categorical feature ORDER differs")
        else:
            errors.append(f"categorical mismatch: "
                          f"missing={set(ref_cat) - set(service_cat)} "
                          f"extra={set(service_cat) - set(ref_cat)}")
    return errors


# ---------------------------------------------------------------------------
# Reference schema (ml lane source of truth) + artifact declarations
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def ref_schema():
    return {
        "num": extract_str_list(ML_SOURCE, "NUMERIC_FEATURES"),
        "cat": extract_str_list(ML_SOURCE, "CATEGORICAL_FEATURES"),
        "gnn_node": extract_str_list(ML_SOURCE, "NODE_FEATURE_NAMES"),
    }


@pytest.fixture(scope="module", params=["v1", "v2", "v3", "v4"])
def fraud_net_artifact(request):
    d = FRAUD_NET_ART / request.param
    if not d.exists():
        pytest.skip(f"artifact {d} missing")
    prep = np.load(d / "preprocess.npz")
    vocab = json.loads((d / "vocab.json").read_text())
    return {"dir": d, "version": request.param,
            "scaler_dim": int(prep["scaler_mean"].shape[0]),
            "vocab": vocab}


# ---------------------------------------------------------------------------
# aml-monitor <-> fraud_net
# ---------------------------------------------------------------------------
def test_aml_service_matches_ml_reference(ref_schema):
    svc_num = extract_str_list(AML_SERVICE, "NUMERIC_FEATURES")
    svc_cat = extract_str_list(AML_SERVICE, "CATEGORICAL_FEATURES")
    errors = check_contract(svc_num, svc_cat,
                            ref_schema["num"], ref_schema["cat"])
    assert errors == [], f"aml_service contract violations: {errors}"


def test_aml_service_matches_fraud_net_artifacts(ref_schema,
                                                 fraud_net_artifact):
    svc_num = extract_str_list(AML_SERVICE, "NUMERIC_FEATURES")
    svc_cat = extract_str_list(AML_SERVICE, "CATEGORICAL_FEATURES")
    art = fraud_net_artifact
    # scaler dims must equal numeric feature count
    assert art["scaler_dim"] == len(svc_num) == len(ref_schema["num"]), (
        f"{art['version']}: scaler dim {art['scaler_dim']} vs "
        f"{len(svc_num)} service numerics")
    # vocab keys must be exactly the categorical features (sorted order is
    # what the model consumes — vocab.json dict order is the artifact's
    # declared embedding order)
    assert sorted(art["vocab"].keys()) == sorted(svc_cat), (
        f"{art['version']}: vocab keys {sorted(art['vocab'])} vs service "
        f"categoricals {sorted(svc_cat)}")
    assert list(art["vocab"].keys()) == sorted(ref_schema["cat"]), (
        f"{art['version']}: vocab.json key order is not the sorted order "
        "the encoders assume")


def test_fraud_net_onnx_input_dims(ref_schema, fraud_net_artifact):
    ort = pytest.importorskip("onnxruntime")
    onnx_path = fraud_net_artifact["dir"] / "model.onnx"
    if not onnx_path.exists():
        pytest.skip(f"no ONNX export for {fraud_net_artifact['version']}")
    sess = ort.InferenceSession(str(onnx_path),
                                providers=["CPUExecutionProvider"])
    inputs = {i.name: i.shape for i in sess.get_inputs()}
    assert inputs["x_num"][1] == len(ref_schema["num"])
    assert inputs["x_cat"][1] == len(ref_schema["cat"])


# ---------------------------------------------------------------------------
# account-takeover-detector blend <-> fraud_net
# ---------------------------------------------------------------------------
def test_ato_service_matches_ml_reference(ref_schema):
    if not ATO_SERVICE.exists():
        pytest.skip("account-takeover-detector not present")
    svc_num = extract_str_list(ATO_SERVICE, "NUMERIC_FEATURES")
    svc_cat = extract_str_list(ATO_SERVICE, "CATEGORICAL_FEATURES")
    errors = check_contract(svc_num, svc_cat,
                            ref_schema["num"], ref_schema["cat"])
    assert errors == [], f"ATO detector contract violations: {errors}"


def test_ato_login_features_are_contract_subset(ref_schema):
    """login_features() must only emit names declared in the numeric
    contract (a typo'd feature name silently scores 0 otherwise)."""
    if not ATO_SERVICE.exists():
        pytest.skip("account-takeover-detector not present")
    tree = ast.parse(ATO_SERVICE.read_text())
    emitted = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "login_features":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    for k in sub.keys:
                        if isinstance(k, ast.Constant):
                            emitted.add(k.value)
    assert emitted, "login_features dict not found"
    unknown = emitted - set(ref_schema["num"])
    assert not unknown, f"login_features emits non-contract features: {unknown}"


# ---------------------------------------------------------------------------
# gnn_mule <-> preprocess.npz dims
# ---------------------------------------------------------------------------
def test_gnn_preprocess_dims_match_model_and_schema(ref_schema):
    import torch
    from ml.models.gnn_mule import load_state_dict_portable, MuleGNN

    prep = np.load(GNN_ART / "preprocess.npz")
    dim = int(prep["scaler_mean"].shape[0])
    assert dim == int(prep["scaler_std"].shape[0])
    assert dim == len(ref_schema["gnn_node"]), (
        f"gnn scaler dim {dim} vs NODE_FEATURE_NAMES "
        f"{len(ref_schema['gnn_node'])}")
    model = MuleGNN(dim, use_pyg=False)
    load_state_dict_portable(model, GNN_ART / "weights.pt")  # raises on mismatch


def test_gnn_node_scores_csv_matches_graph_dims(ref_schema):
    """If node_scores.csv ships beside the artifact, its row count must equal
    the graph snapshot node count and its scores must be probabilities."""
    csv_path = GNN_ART / "node_scores.csv"
    if not csv_path.exists():
        pytest.skip("node_scores.csv not generated yet")
    import csv as csv_mod
    rows = list(csv_mod.reader(csv_path.open()))
    header, data = rows[0], rows[1:]
    assert header == ["account_ref", "mule_score", "node_id",
                      "artifact_version"]
    g = np.load(REPO / "ml" / "data" / "generated" / "graph.npz")
    key = "X_test" if "X_test" in g else "X"
    assert len(data) == g[key].shape[0]
    scores = np.array([float(r[1]) for r in data])
    assert np.all((scores >= 0.0) & (scores <= 1.0))
    node_ids = [int(r[2]) for r in data]
    assert node_ids == list(range(len(data)))


# ---------------------------------------------------------------------------
# Meta-test: the contract check itself must catch swap / missing / extra
# ---------------------------------------------------------------------------
def test_contract_check_catches_swap_and_missing(ref_schema):
    num, cat = ref_schema["num"], ref_schema["cat"]
    swapped = num.copy()
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert check_contract(swapped, cat, num, cat), "swap not caught"
    missing = num[:-1]
    assert check_contract(missing, cat, num, cat), "missing not caught"
    extra = num + ["bogus_feature"]
    assert check_contract(extra, cat, num, cat), "extra not caught"
    cat_swapped = list(reversed(cat))
    assert check_contract(num, cat_swapped, num, cat), "cat swap not caught"
    assert check_contract(num, cat, num, cat) == [], "clean check must pass"
