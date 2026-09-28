"""Tests for the Cultural Intelligence layer (ml/bayesian/cultural_intelligence.py).

Covers: MCMC convergence diagnostics (quick-mode fits), Christmas uplift vs
a random week, ajo-vs-structuring discrimination (AUC reported honestly),
the explicit uncertain zone, adjustment-factor math, calendar mask
precedence, ethics meta-tests (NO religion/ethnicity/tribe/language
attributes anywhere in feature schemas or the generator's cultural
columns), zone-parity fairness checks, the weighted cultural-fraud score,
and the service constant-mirroring contract.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.bayesian import cultural_intelligence as ci  # noqa: E402
from ml.data import synthetic_nigeria as syn  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SERVICE_CULTURAL = (REPO / "services" / "python" / "intel-service"
                    / "app" / "cultural.py")

SENSITIVE_RE = ci.FORBIDDEN_ATTRIBUTE_RE


@pytest.fixture(scope="module")
def fitted(tmp_path_factory):
    """Quick-mode end-to-end fit (thin chains; honest diagnostics)."""
    out = tmp_path_factory.mktemp("cultural") / "v1"
    metrics = ci.fit_all(version="v1", seed=42, quick=True, out_dir=out)
    return {"out": out, "metrics": metrics,
            "summaries": json.loads((out / "summaries.json").read_text())}


# ---------------- convergence -------------------------------------------------

def test_convergence_all_models(fitted):
    m = fitted["metrics"]
    for name in ("ajo_model", "market_model", "calendar_model",
                 "giving_model", "affinity_model"):
        assert m[name]["rhat_max"] < 1.1, f"{name} R-hat {m[name]['rhat_max']}"
        assert m[name]["ess_min"] > 50, f"{name} ESS {m[name]['ess_min']}"


def test_calibration_truth_in_ci95(fitted):
    """Honest intervals: >=80% of event×zone cells contain the
    absorbed-overlap truth (nominal 95%, synthetic check)."""
    share = fitted["metrics"]["calendar_model"]["truth_in_ci95_share"]
    assert 0.80 <= share <= 1.0


# ---------------- calendar ----------------------------------------------------

def test_christmas_uplift_beats_random_week(fitted):
    s = fitted["summaries"]
    ev = {e["id"]: e for e in s["events"]}
    xmas = ev["christmas"]["national"]
    assert xmas["uplift_mean"] > 1.3
    assert xmas["ci95"][0] > 1.05          # entire CI above baseline
    # a day with no event has no uplift entry at all
    masks = ci.event_masks(ci._date_range())
    any_event = np.zeros(ci.DAYS, dtype=bool)
    for m in masks.values():
        any_event |= m
    assert (~any_event).sum() > 200        # most days are baseline (factor 1.0)


def test_event_mask_precedence_exclusive():
    masks = ci.event_masks(ci._date_range())
    taken = np.zeros(ci.DAYS, dtype=int)
    for m in masks.values():
        taken += m.astype(int)
    assert taken.max() == 1                # exclusive assignment
    raw = ci.event_masks(ci._date_range(), exclusive=False)
    # Jan 1-2: both new_year and salary_week raw-active (overlap absorbed)
    jan1 = 0
    assert raw["new_year"][jan1] and raw["salary_week"][jan1]
    assert masks["new_year"][jan1] and not masks["salary_week"][jan1]
    # Christmas beats Detty December on Dec 25
    dec25 = 358  # 2026-12-25
    assert raw["detty_december"][dec25] and raw["christmas"][dec25]
    assert masks["christmas"][dec25] and not masks["detty_december"][dec25]


# ---------------- ajo legitimacy ----------------------------------------------

def test_ajo_discrimination_auc_honest(fitted):
    auc = fitted["metrics"]["ajo_model"]["test_auc"]
    assert 0.85 <= auc <= 1.0              # synthetic separation, honestly reported
    assert fitted["metrics"]["ajo_model"]["test_n"] >= 100


def test_ajo_uncertain_zone_and_extremes(fitted):
    out = fitted["out"]
    z = np.load(out / "serving.npz")
    beta, mu, sd = z["ajo_beta_draws"], z["ajo_feature_mu"], z["ajo_feature_sd"]
    clear_legit = {"log_n_members": np.log(10), "contribution_cv": 0.03,
                   "cadence_cv": 0.08, "rotation_coverage": 0.98,
                   "payout_ratio": 0.95, "log_tenure_days": np.log(400)}
    r = ci.ajo_predict(beta, mu, sd, clear_legit)
    assert r["assessment"] == "likely_legitimate_ajo" and not r["uncertain"]
    assert r["p_legitimate_mean"] > 0.9
    clear_fraud = {"log_n_members": np.log(9), "contribution_cv": 0.04,
                   "cadence_cv": 0.55, "rotation_coverage": 0.05,
                   "payout_ratio": 0.12, "log_tenure_days": np.log(30)}
    r2 = ci.ajo_predict(beta, mu, sd, clear_fraud)
    assert r2["assessment"] == "likely_fraud" and r2["p_legitimate_mean"] < 0.2
    # ambiguous: high-ish rotation but payout/cadence slightly off -> the
    # posterior honestly cannot call it (CI straddles 0.5)
    ambiguous = {"log_n_members": np.log(8), "contribution_cv": 0.07,
                 "cadence_cv": 0.15, "rotation_coverage": 0.72,
                 "payout_ratio": 0.9, "log_tenure_days": np.log(150)}
    r3 = ci.ajo_predict(beta, mu, sd, ambiguous)
    assert r3["assessment"] == "uncertain" and r3["uncertain"]
    assert r3["ci95"][0] < 0.5 < r3["ci95"][1]
    for r_ in (r, r2, r3):
        assert len(r_["top_discriminating_features"]) == 3


def test_ajo_rotation_is_top_discriminator(fitted):
    s = fitted["summaries"]
    coefs = {c["name"]: c["posterior_mean"] for c in s["ajo"]["coefficients"]}
    # rotation reciprocity is the honest discriminator vs fan-out
    assert coefs["rotation_coverage"] > 1.5
    assert coefs["rotation_coverage"] == max(
        (v for k, v in coefs.items() if k != "intercept"), key=abs)


# ---------------- market + giving ---------------------------------------------

def test_market_cycle_recovery(fitted):
    s = fitted["summaries"]
    se = s["market_cycles"]["south_east"]
    assert se["cycle_days"] == 4
    assert se["day_names"] == ["Eke", "Orie", "Afo", "Nkwo"]
    peak = int(np.argmax(se["uplift_mean"]))
    assert peak == 0                        # market day (Eke) is the peak
    assert se["uplift_mean"][0] > 1.3
    sw = s["market_cycles"]["south_west"]
    assert sw["cycle_days"] == 5
    nw = s["market_cycles"]["north_west"]
    assert nw["cycle_days"] == 7
    for z, c in s["market_cycles"].items():
        for lo, m_, hi in zip(c["ci95_lo"], c["uplift_mean"], c["ci95_hi"]):
            assert lo <= m_ <= hi


def test_giving_rhythm_peaks(fitted):
    s = fitted["summaries"]["giving_rhythm"]
    assert s["north_west"]["peak_day"] == "friday"    # Jumu'ah
    assert s["north_east"]["peak_day"] == "friday"
    assert s["south_west"]["peak_day"] == "sunday"    # services/tithes
    assert s["south_east"]["peak_day"] == "sunday"
    nc = s["north_central"]["uplift_mean"]            # mixed Fri + Sun
    assert nc[4] > nc[2] and nc[6] > nc[2]            # both peaks > midweek


# ---------------- typology base rates ------------------------------------------

def test_affinity_base_rates_ci_cover_truth(fitted):
    data = ci.synth_cultural(42)
    s = fitted["summaries"]["affinity_base_rates"]
    covered_obs = 0
    recovered = 0
    total = 0
    for zi, z in enumerate(ci.ZONES):
        for ki, k in enumerate(ci.CULTURAL_FRAUD_TYPOLOGIES):
            row = s[z][k]
            assert row["ci95"][0] <= row["posterior_mean"] <= row["ci95"][1]
            total += 1
            # the observed proportion is the truth the model actually saw
            # (generator perturbs documented shares by ~8% before counting)
            obs = data["y_aff"][zi, ki] / max(data["n_aff"][zi], 1)
            if row["ci95"][0] <= obs <= row["ci95"][1]:
                covered_obs += 1
            # posterior mean recovers the documented share within 40% rel.
            true_share = data["true_affinity_share"][k][z]
            if abs(row["posterior_mean"] - true_share) <= 0.4 * true_share:
                recovered += 1
    assert covered_obs / total >= 0.9      # honest interval calibration
    assert recovered / total >= 0.8        # recovery of documented shares


# ---------------- cultural fraud score -----------------------------------------

def test_cultural_fraud_score_weights_and_bands():
    assert abs(sum(ci.CULTURAL_FRAUD_WEIGHTS.values()) - 1.0) < 1e-9
    clean = ci.cultural_fraud_score({k: 0.0 for k in ci.CULTURAL_FRAUD_WEIGHTS})
    assert clean["cultural_fraud_score"] == 0.0
    assert clean["risk_band"] == "low"
    hot = ci.cultural_fraud_score({k: 1.0 for k in ci.CULTURAL_FRAUD_WEIGHTS})
    assert hot["cultural_fraud_score"] == 1.0
    assert hot["risk_band"] == "critical"
    mid = ci.cultural_fraud_score({"network_anomaly": 0.8, "urgency": 0.5})
    # 0.25*0.8 + 0.10*0.5 = 0.25 -> low band boundary
    assert 0.2 <= mid["cultural_fraud_score"] <= 0.3
    high = ci.cultural_fraud_score({"temporal_anomaly": 1.0, "network_anomaly": 1.0,
                                    "cultural_inconsistency": 1.0})
    assert high["risk_band"] in ("high", "critical")     # 0.65 raw
    # authenticity discount: matching calendar + consistent network
    auth = ci.cultural_fraud_score(
        {"temporal_anomaly": 1.0, "network_anomaly": 1.0,
         "cultural_inconsistency": 1.0},
        authenticity={"event_matches_calendar": True,
                      "network_consistent_with_claimed_norm": True})
    assert auth["cultural_fraud_score"] < high["cultural_fraud_score"]
    assert auth["authenticity_discount"] == 0.10
    with pytest.raises(ValueError):
        ci.cultural_fraud_score({"unknown_indicator": 0.5})


# ---------------- ETHICS meta-tests ---------------------------------------------

def _ast_str_list(path: Path, name: str):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {path}")


def test_no_sensitive_attributes_anywhere(fitted):
    """ETHICS GUARDRAIL meta-test: no religion/ethnicity/tribe/language
    fields in ANY feature schema of the cultural layer."""
    assert not any(SENSITIVE_RE.search(f) for f in ci.AJO_FEATURES)
    assert not any(SENSITIVE_RE.search(k) for k in ci.CULTURAL_FRAUD_WEIGHTS)
    # service schemas (pydantic models + mirrored constants)
    tree = ast.parse(SERVICE_CULTURAL.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assert not SENSITIVE_RE.search(node.target.id), node.target.id
    # generator cultural columns
    src = (REPO / "ml" / "data" / "synthetic_nigeria.py").read_text()
    for col in ("cultural_event", "ajo_group_id", "is_local_market_day"):
        assert col in src
        assert not SENSITIVE_RE.search(col)
    # served summaries keys — EXEMPT exactly the five fraud-scheme typology
    # labels (domain-document category names, not person attributes)
    exempt = set(ci.CULTURAL_FRAUD_TYPOLOGIES)
    for key in _walk_keys(fitted["summaries"]):
        if key in exempt:
            continue
        assert not SENSITIVE_RE.search(key), key


def _walk_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v)


def test_service_constant_mirror_contract():
    """app/cultural.py is torch-free and mirrors the ml constants; this AST
    contract test keeps them in sync."""
    svc_weights = _ast_str_list(SERVICE_CULTURAL, "CULTURAL_FRAUD_WEIGHTS")
    assert svc_weights == ci.CULTURAL_FRAUD_WEIGHTS
    svc_features = _ast_str_list(SERVICE_CULTURAL, "AJO_FEATURES")
    assert svc_features == ci.AJO_FEATURES
    svc_prec = _ast_str_list(SERVICE_CULTURAL, "EVENT_PRECEDENCE")
    assert svc_prec == ci.EVENT_PRECEDENCE
    svc_zone = _ast_str_list(SERVICE_CULTURAL, "STATE_TO_ZONE")
    assert svc_zone == ci.STATE_TO_ZONE


# ---------------- fairness (zone parity) ---------------------------------------

def test_fairness_zone_parity(fitted):
    """Zone-level priors must not drive materially divergent treatment:
      * zone-uniform events (independence day, salary week) recover
        near-equal zone uplifts (max/min mean ratio bounded AND every zone
        within 15% of the national mean — tight intervals legitimately need
        not overlap the pooled mean after partial pooling, so the criterion
        is MATERIAL divergence, not interval overlap);
      * the ajo model has no zone/geography input at all (schema check).
    """
    s = fitted["summaries"]
    ev = {e["id"]: e for e in s["events"]}
    for eid in ("independence_day", "salary_week"):
        means = [ev[eid]["zone_uplift"][z]["uplift_mean"] for z in ci.ZONES]
        assert max(means) / min(means) < 1.6, (eid, means)
        nat_mean = ev[eid]["national"]["uplift_mean"]
        for z in ci.ZONES:
            zm = ev[eid]["zone_uplift"][z]["uplift_mean"]
            assert abs(zm - nat_mean) / nat_mean < 0.15, (eid, z, zm, nat_mean)
    # ajo feature schema carries no geography
    assert not any("zone" in f or "state" in f or "geo" in f
                   for f in ci.AJO_FEATURES)


# ---------------- synthetic generator -------------------------------------------

def test_generator_cultural_layer_additive_and_honest(tmp_path):
    meta = syn.main(str(tmp_path), n_customers=600, n_txns=6000, seed=7)
    assert meta["dataset_version"] == 2                # v2 contract preserved
    assert meta["cultural_patterns_version"] == 1
    import pandas as pd
    tx = pd.read_parquet(tmp_path / "transactions.parquet")
    assert {"cultural_event", "ajo_group_id", "is_local_market_day"} <= set(tx.columns)
    # honest labels: legit cultural flows never fraud, masquerades always fraud
    legit = tx[tx["fraud_typology"].isin(
        ["ajo_contribution", "religious_giving", "family_support"])]
    assert len(legit) > 0 and (legit["is_fraud"] == 0).all()
    masq = tx[tx["fraud_typology"].isin(syn.CULTURAL_MASQUERADE_TYPOLOGIES)]
    assert len(masq) > 0 and (masq["is_fraud"] == 1).all()
    # the generator's masquerade typologies == the model's five typologies
    assert set(syn.CULTURAL_MASQUERADE_TYPOLOGIES) == set(ci.CULTURAL_FRAUD_TYPOLOGIES)
    for t in syn.CULTURAL_MASQUERADE_TYPOLOGIES:
        assert (masq["fraud_typology"] == t).any(), t
    fake = tx[tx["fraud_typology"] == "fake_ajo_ponzi"]
    assert len(fake) > 0 and (fake["is_fraud"] == 1).all()
    # giving rows peak on Friday/Sunday
    gv = tx[tx["fraud_typology"] == "religious_giving"]
    assert set(gv["dow"].unique()) <= {4, 6}
