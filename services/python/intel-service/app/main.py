"""intel-service — National + Cultural Fraud Intelligence serving API
(FastAPI, :8500).

Serves the hierarchical Bayesian posteriors fit by
``ml/bayesian/national_intelligence.py`` and shipped under
``ml/artifacts/national_intelligence/<version>/``:

    GET /v1/intel/national/summary     national rate posterior + trend + top typologies
    GET /v1/intel/states               37 states ranked, credible intervals, P(above national)
    GET /v1/intel/states/{code}        state detail incl. LGA table for pilot states
    GET /v1/intel/hotspots?k=10        posterior-ranked hotspots, P(exceeds threshold)
    GET /v1/intel/typology-mix         per-zone Dirichlet-multinomial mix with intervals
    GET /v1/intel/brief                markdown National Fraud Intelligence Brief
    GET /health                        loud fail-closed health (503 when artifact missing)

plus the Cultural Intelligence layer (``app/cultural.py``,
``ml/bayesian/cultural_intelligence.py``) mounted under
/v1/intel/cultural/: calendar uplift, ajo/esusu legitimacy posterior,
audited anomaly-score adjustment, culturally-specific typology base rates,
weekly giving rhythm, and weighted cultural-fraud indicator scoring.

NDPA-safe by construction: the model only ever sees aggregate weekly
counts; the artifact contains no PII; and any aggregate cell with
fewer than ``SUPPRESS_MIN_N`` weekly transactions is suppressed
(k-anonymity-style) as ``{"suppressed": true}``.

AUTH: every /v1/intel/* data-plane route requires EITHER a staff Keycloak
JWT (app/auth.py, fail-closed, mirrors kyc-api) OR a tenant API key
(X-API-Key: ffk_*) validated via billing-service introspection with the
fraud_score scope (app/api_keys.py; fail-closed, <=60s TTL cache).
/health stays unauthenticated for orchestrators.

FAIL-CLOSED: if the artifact is missing/unloadable the service still
boots (so orchestrators can see it), but /health returns 503 and every
/v1/intel/* endpoint returns 503 with a loud reason. There is NO silent
fallback to heuristics — intelligence consumers must never unknowingly
read stale or fabricated numbers.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse

from app.api_keys import require_scope

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("intel-service")

SERVICE_NAME = "intel-service"
SUPPRESS_MIN_N = int(os.getenv("INTEL_SUPPRESS_MIN_N", "30"))  # k-anonymity floor

DEFAULT_ARTIFACT_DIR = (Path(__file__).resolve().parents[4]
                        / "ml" / "artifacts" / "national_intelligence" / "v1")
DEFAULT_CULTURAL_ARTIFACT_DIR = (Path(__file__).resolve().parents[4]
                                 / "ml" / "artifacts" / "cultural_intelligence" / "v1")


class IntelStore:
    """Loaded artifact: summaries.json aggregates + state posterior draws."""

    def __init__(self, artifact_dir: Path):
        self.artifact_dir = Path(artifact_dir)
        self.summaries: dict[str, Any] = json.loads(
            (self.artifact_dir / "summaries.json").read_text())
        self.metrics: dict[str, Any] = json.loads(
            (self.artifact_dir / "metrics.json").read_text())
        z = np.load(self.artifact_dir / "posterior.npz")
        samples = z["samples"]                       # (chains, draws, 2+S)
        flat = samples.reshape(-1, samples.shape[-1])
        self.mu_rate = 1.0 / (1.0 + np.exp(-flat[:, 0]))
        self.theta = 1.0 / (1.0 + np.exp(-flat[:, 2:]))
        codes = [str(p).split("[")[1].rstrip("]") for p in z["param_names"][2:]]
        self.state_index = {c: i for i, c in enumerate(codes)}
        logger.info("intel artifact loaded from %s (%d posterior draws, period=%s weeks)",
                    self.artifact_dir, len(flat),
                    self.summaries.get("data_period_weeks"))

    # -- helpers ---------------------------------------------------------
    def p_exceeds(self, code: str, threshold: float) -> float:
        j = self.state_index[code]
        return float((self.theta[:, j] > threshold).mean())

    def suppress_row(self, row: dict, weekly_n: float) -> dict:
        """k-anonymity: cells below SUPPRESS_MIN_N weekly transactions are
        suppressed — return only the identity fields and the flag."""
        if weekly_n < SUPPRESS_MIN_N:
            return {"suppressed": True,
                    "reason": f"cell below k-anonymity floor (n<{SUPPRESS_MIN_N}/wk)"}
        return row


def create_app(artifact_dir: str | Path | None = None,
               cultural_artifact_dir: str | Path | None = None) -> FastAPI:
    artifact_dir = Path(os.getenv("INTEL_ARTIFACT_DIR", "") or
                        (artifact_dir or DEFAULT_ARTIFACT_DIR))
    cultural_dir = Path(os.getenv("INTEL_CULTURAL_ARTIFACT_DIR", "") or
                        (cultural_artifact_dir or DEFAULT_CULTURAL_ARTIFACT_DIR))
    app = FastAPI(title="intel-service",
                  version="1.1.0",
                  description="National + Cultural Fraud Intelligence "
                              "(hierarchical Bayesian / MCMC)")

    store: IntelStore | None = None
    load_error: str | None = None
    try:
        store = IntelStore(artifact_dir)
    except Exception as exc:  # fail-closed, loudly
        load_error = f"artifact missing/unloadable at {artifact_dir}: {exc}"
        logger.error("INTEL ARTIFACT UNAVAILABLE — %s. /health will report 503 "
                     "and all /v1/intel/* endpoints are disabled (fail-closed).",
                     load_error)

    # All /v1/intel/* data-plane routes require EITHER a staff Keycloak JWT
    # OR a tenant API key (X-API-Key: ffk_*) with the fraud_score scope,
    # validated via billing-service introspection (fail-closed). /health
    # stays unauthenticated for orchestrators.
    _intel_auth = [Depends(require_scope("fraud_score"))]

    # Cultural intelligence router (independently fail-closed: a missing
    # cultural artifact 503s /v1/intel/cultural/* only, never the national
    # endpoints — and vice versa).
    from app.cultural import create_cultural_router
    cultural_router = create_cultural_router(cultural_dir)
    app.include_router(cultural_router, dependencies=_intel_auth)
    app.state.cultural_router = cultural_router

    # Request-legitimacy router (stateless heuristic scoring — no artifact,
    # so it is never fail-closed; see app/request_legitimacy.py).
    from app.request_legitimacy import create_request_legitimacy_router
    legitimacy_router = create_request_legitimacy_router()
    app.include_router(legitimacy_router, dependencies=_intel_auth)
    app.state.request_legitimacy_router = legitimacy_router

    def require_store() -> IntelStore:
        if store is None:
            raise HTTPException(status_code=503,
                                detail=f"intel artifact unavailable ({load_error}); "
                                       "service is fail-closed")
        return store

    @app.get("/health")
    def health():
        if store is None:
            raise HTTPException(status_code=503,
                                detail={"status": "unhealthy",
                                        "reason": load_error,
                                        "mode": "fail-closed"})
        return {"status": "ok", "service": SERVICE_NAME,
                "artifact_dir": str(store.artifact_dir),
                "model_version": store.metrics.get("version"),
                "cultural_layer": ("ok" if cultural_router.cultural_store is not None  # type: ignore[attr-defined]
                                   else f"unavailable: {cultural_router.cultural_load_error}"),  # type: ignore[attr-defined]
                "request_legitimacy_layer": "ok (stateless, no artifact required)",
                "provenance": store.summaries.get("provenance")}

    # ------------------------------------------------------------------
    @app.get("/v1/intel/national/summary", dependencies=_intel_auth)
    def national_summary():
        s = require_store().summaries
        nat = s["national"]
        return {
            "data_period_weeks": s["data_period_weeks"],
            "provenance": s["provenance"],
            "national_fraud_rate": {
                "posterior_mean": nat["posterior_mean"],
                "ci95": nat["ci95"],
            },
            "week_trend": {"direction": nat["trend_direction"],
                           "delta_last4_vs_prior4": nat["week_trend_delta"]},
            "top_typologies": nat["top_typologies"],
            "totals": {"txn_year": nat["total_txn_year"],
                       "fraud_year": nat["total_fraud_year"]},
            "forecast_4wk": s["forecast"],
            "model_version": require_store().metrics.get("version"),
        }

    @app.get("/v1/intel/states", dependencies=_intel_auth)
    def states():
        st = require_store()
        nat_mean = st.summaries["national"]["posterior_mean"]
        out = []
        for r in st.summaries["states"]:
            weekly_n = r["txn_count"] / st.summaries["data_period_weeks"]
            if weekly_n < SUPPRESS_MIN_N:
                out.append({"code": r["code"], "name": r["name"],
                            "suppressed": True,
                            "reason": f"cell below k-anonymity floor "
                                      f"(n<{SUPPRESS_MIN_N}/wk)"})
                continue
            out.append({**r, "weekly_txn_mean": weekly_n,
                        "reference_national_mean": nat_mean,
                        "suppressed": False})
        return {"states": out, "national_posterior_mean": nat_mean,
                "suppression_min_weekly_n": SUPPRESS_MIN_N,
                "provenance": st.summaries["provenance"]}

    @app.get("/v1/intel/states/{code}", dependencies=_intel_auth)
    def state_detail(code: str):
        st = require_store()
        code = code.lower()
        row = next((r for r in st.summaries["states"] if r["code"] == code), None)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown state code '{code}'")
        out: dict[str, Any] = {**row,
                               "weekly_txn_mean": row["txn_count"]
                               / st.summaries["data_period_weeks"]}
        lgas = st.summaries["lgas"].get(code)
        if lgas is not None:
            table = []
            for lg in lgas:
                if lg["weekly_txn_mean"] < SUPPRESS_MIN_N:
                    table.append({"lga": lg["lga"], "suppressed": True,
                                  "reason": f"cell below k-anonymity floor "
                                            f"(n<{SUPPRESS_MIN_N}/wk)"})
                else:
                    table.append({**lg, "suppressed": False})
            out["lgas"] = table
            out["lga_model"] = "hierarchical partial pooling toward state mean"
        else:
            out["lgas"] = None
            out["lga_model"] = ("not a pilot state — LGA pooling currently only "
                                "for lagos, kano, abuja_fct")
        return out

    @app.get("/v1/intel/hotspots", dependencies=_intel_auth)
    def hotspots(k: int = Query(10, ge=1, le=37),
                 threshold: float | None = Query(None, gt=0, lt=1)):
        st = require_store()
        thr = threshold if threshold is not None else \
            st.summaries["national"]["posterior_mean"]
        rows = []
        for r in st.summaries["states"]:
            weekly_n = r["txn_count"] / st.summaries["data_period_weeks"]
            if weekly_n < SUPPRESS_MIN_N:
                continue                      # suppressed cells never rank
            rows.append({
                "code": r["code"], "name": r["name"], "zone": r["zone"],
                "posterior_mean": r["posterior_mean"], "ci95": r["ci95"],
                "p_exceeds_threshold": st.p_exceeds(r["code"], thr),
            })
        rows.sort(key=lambda r: (-r["p_exceeds_threshold"], -r["posterior_mean"]))
        return {"k": k, "threshold": thr, "hotspots": rows[:k],
                "provenance": st.summaries["provenance"]}

    @app.get("/v1/intel/typology-mix", dependencies=_intel_auth)
    def typology_mix():
        st = require_store()
        return {"zones": st.summaries["typology_mix"],
                "model": "Dirichlet-multinomial per geopolitical zone",
                "provenance": st.summaries["provenance"]}

    @app.get("/v1/intel/brief", response_class=PlainTextResponse, dependencies=_intel_auth)
    def brief():
        return render_brief(require_store())

    return app


def render_brief(store: IntelStore) -> str:
    """Markdown 'National Fraud Intelligence Brief' from posterior aggregates."""
    s = store.summaries
    nat = s["national"]
    m = store.metrics
    top5 = s["states"][:5]
    fc = s["forecast"]

    lines = [
        "# National Fraud Intelligence Brief — Nigeria",
        "",
        f"**Data period:** last {s['data_period_weeks']} weeks | "
        f"**Model version:** {m.get('version')} | "
        f"**Provenance:** {s['provenance']}",
        "",
        "## National estimate",
        "",
        f"- Annual-average weekly fraud rate: **{nat['posterior_mean']:.4f}** "
        f"(95% credible interval [{nat['ci95'][0]:.4f}, {nat['ci95'][1]:.4f}])",
        f"- Latest week rate: **{nat['weekly_rate_mean'][-1]:.4f}** "
        f"(temporal model; forecast below continues from here)",
        f"- Trend: **{nat['trend_direction']}** "
        f"(last-4-week mean minus prior-4-week mean: {nat['week_trend_delta']:+.5f})",
        f"- Volume: {nat['total_txn_year']:,} transactions, "
        f"{nat['total_fraud_year']:,} fraud events (reported)",
        "- Top typologies nationally: "
        + ", ".join(f"{t['typology']} ({t['share']:.0%})"
                    for t in nat["top_typologies"]),
        "",
        "## Hotspots (top 5 states by posterior mean fraud rate)",
        "",
        "| State | Posterior mean | 95% CI | P(above national) |",
        "|---|---|---|---|",
    ]
    for r in top5:
        lines.append(f"| {r['name']} | {r['posterior_mean']:.4f} | "
                     f"[{r['ci95'][0]:.4f}, {r['ci95'][1]:.4f}] | "
                     f"{r['p_above_national']:.2f} |")
    lines += ["", "## Zone typology shifts", ""]
    nat_shares = {t["typology"]: t["share"] for t in nat["top_typologies"]}
    for z, blk in s["typology_mix"].items():
        mix = {r["typology"]: r["posterior_mean"] for r in blk["mix"]}
        nat_mix_all = nat_mix(s)
        shifts = sorted(((t, mix[t] - nat_mix_all[t]) for t in mix),
                        key=lambda kv: -abs(kv[1]))[:2]
        shift_txt = ", ".join(f"{t} {d:+.1%} vs national" for t, d in shifts)
        top = max(mix, key=mix.get)
        lines.append(f"- **{z}**: dominant {top} ({mix[top]:.0%}); {shift_txt}")
    lines += [
        "",
        "## Forecast (next 4 weeks, national weekly fraud rate)",
        "",
        "| Week | Posterior predictive mean | 95% interval |",
        "|---|---|---|",
    ]
    for k_ in range(fc["weeks_ahead"]):
        lines.append(f"| +{k_ + 1} | {fc['rate_mean'][k_]:.4f} | "
                     f"[{fc['rate_ci95'][k_][0]:.4f}, {fc['rate_ci95'][k_][1]:.4f}] |")
    lines += [
        "",
        "## Methodology",
        "",
        "Hierarchical Bayesian models fit with MCMC (NUTS-lite, dual-averaging "
        "HMC; split R-hat and ESS in metrics.json). State fraud rates use "
        "logit-normal partial pooling toward the national mean; LGA rates in "
        "pilot states pool toward their state mean; zone typology mixes are "
        "Dirichlet-multinomial; the national intensity is a 52-week random "
        "walk with a posterior-predictive forecast.",
        "",
        "## Caveats (read before acting)",
        "",
        f"- Training data is **{s['provenance']}** — absolute levels are NOT "
        "observed Nigerian fraud rates until real feeds replace the generator.",
        "- Estimates reflect *reported/detected* fraud; states with weaker "
        "detection look safer than they are (reporting bias).",
        "- Aggregates describe regions, not individuals — do not use state or "
        "zone rates to score a person (ecological fallacy).",
        f"- Cells with fewer than {SUPPRESS_MIN_N} weekly transactions are "
        "suppressed (k-anonymity); no PII exists anywhere in this pipeline.",
        "",
    ]
    return "\n".join(lines)


def nat_mix(summaries: dict) -> dict[str, float]:
    """Reconstruct national mix from zone mixes weighted by zone fraud volume."""
    zones = summaries["typology_mix"]
    tot = sum(b["fraud_count_year"] for b in zones.values()) or 1
    out: dict[str, float] = {}
    for blk in zones.values():
        w = blk["fraud_count_year"] / tot
        for r in blk["mix"]:
            out[r["typology"]] = out.get(r["typology"], 0.0) + w * r["posterior_mean"]
    return out


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8500")))
