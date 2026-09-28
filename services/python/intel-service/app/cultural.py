"""Cultural Intelligence router for intel-service (mounted under
/v1/intel/cultural/).

Serves the MCMC posteriors fit by ``ml/bayesian/cultural_intelligence.py``
and shipped under ``ml/artifacts/cultural_intelligence/<version>/``:

    GET  /v1/intel/cultural/calendar?date=YYYY-MM-DD&state=lagos
    POST /v1/intel/cultural/ajo/assess
    GET  /v1/intel/cultural/adjustment?date=&state=&channel=
    GET  /v1/intel/cultural/typologies?zone=south_west
    GET  /v1/intel/cultural/giving-rhythm?zone=north_west
    POST /v1/intel/cultural/score

ETHICS GUARDRAIL (enforced by meta-test): these models adjust for
transaction PATTERNS in cultural context — never the person. No
per-individual ethnicity/religion/tribe/language fields exist in any
schema here; geography enters only as zone-level aggregate priors.

AUDIT: every /adjustment call is recorded (Postgres
``cultural_adjustment_audit`` when INTEL_AUDIT_DSN is configured, else the
in-memory ring buffer exposed on the store for tests/dev). There is no
silent path.

This module is deliberately torch-free (the service image has no torch);
the small constant tables mirror ml/bayesian/cultural_intelligence.py and
are kept in sync by an AST contract test in
ml/tests/test_cultural_intelligence.py.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("intel-service.cultural")

# --- mirrored constants (sync-tested against ml.bayesian.cultural_intelligence)
STATE_TO_ZONE = {
    "lagos": "south_west", "ogun": "south_west", "oyo": "south_west",
    "osun": "south_west", "ondo": "south_west", "ekiti": "south_west",
    "rivers": "south_south", "delta": "south_south", "edo": "south_south",
    "akwa_ibom": "south_south", "cross_river": "south_south",
    "bayelsa": "south_south",
    "anambra": "south_east", "enugu": "south_east", "imo": "south_east",
    "abia": "south_east", "ebonyi": "south_east",
    "abuja_fct": "north_central", "kwara": "north_central",
    "plateau": "north_central", "kogi": "north_central",
    "niger": "north_central", "benue": "north_central",
    "nasarawa": "north_central",
    "kano": "north_west", "kaduna": "north_west", "katsina": "north_west",
    "sokoto": "north_west", "jigawa": "north_west", "kebbi": "north_west",
    "zamfara": "north_west",
    "borno": "north_east", "bauchi": "north_east", "adamawa": "north_east",
    "gombe": "north_east", "yobe": "north_east", "taraba": "north_east",
}

CULTURAL_FRAUD_WEIGHTS = {
    "temporal_anomaly": 0.20,
    "network_anomaly": 0.25,
    "cultural_inconsistency": 0.20,
    "amount_anomaly": 0.15,
    "communication_anomaly": 0.10,
    "urgency": 0.10,
}
RISK_BANDS = [(0.8, "critical"), (0.6, "high"), (0.4, "medium"), (0.0, "low")]
EVENT_PRECEDENCE = ["christmas", "new_year", "independence_day", "easter",
                    "eid_al_fitr", "eid_al_adha", "detty_december",
                    "salary_week"]
AJO_FEATURES = ["log_n_members", "contribution_cv", "cadence_cv",
                "rotation_coverage", "payout_ratio", "log_tenure_days"]
MARKET_CYCLE_REFERENCE = date(2025, 12, 31)


def risk_band(score: float) -> str:
    for thr, band in RISK_BANDS:
        if score >= thr:
            return band
    return "low"


class AjoAssessRequest(BaseModel):
    """Ajo/esusu group transfer-pattern summary. PATTERN-LEVEL ONLY."""
    n_members: int = Field(ge=2, le=500)
    contribution_cv: float = Field(ge=0.0, le=10.0,
                                   description="CV of member contribution amounts")
    cadence_cv: float = Field(ge=0.0, le=10.0,
                              description="CV of inter-transfer intervals")
    rotation_coverage: float = Field(ge=0.0, le=1.0,
                                     description="fraction of members receiving "
                                                 "exactly once per cycle")
    payout_ratio: float = Field(ge=0.0, le=100.0,
                                description="mean payout / (n_members x contribution)")
    tenure_days: float = Field(ge=0.0, le=100000.0)


class CulturalScoreRequest(BaseModel):
    """Weighted cultural-fraud indicator scoring (document weights)."""
    model_config = {"populate_by_name": True}
    indicators: dict[str, float] = Field(default_factory=dict)
    claimed_event: str | None = None
    date_: date | None = Field(None, alias="date")
    state: str | None = None
    network_consistent_with_claimed_norm: bool = False
    ajo_pattern: AjoAssessRequest | None = None


class CulturalStore:
    """Loaded cultural artifact: summaries + derived serving draws."""

    def __init__(self, artifact_dir: Path):
        self.artifact_dir = Path(artifact_dir)
        self.summaries: dict[str, Any] = json.loads(
            (self.artifact_dir / "summaries.json").read_text())
        self.metrics: dict[str, Any] = json.loads(
            (self.artifact_dir / "metrics.json").read_text())
        z = np.load(self.artifact_dir / "serving.npz", allow_pickle=False)
        self.event_uplift = z["event_uplift_draws"]     # (n, E, Z)
        self.market_uplift = z["market_uplift_draws"]   # (n, Z, maxL) NaN-padded
        self.giving_uplift = z["giving_uplift_draws"]   # (n, Z, 7)
        self.ajo_beta = z["ajo_beta_draws"]             # (n, 7)
        self.ajo_mu = z["ajo_feature_mu"]
        self.ajo_sd = z["ajo_feature_sd"]
        self.event_ids = [str(e) for e in z["event_ids"]]
        self.zones = [str(zn) for zn in z["zones"]]
        self.audit_log: list[dict] = []                 # in-memory audit fallback
        self._pg = None
        dsn = os.getenv("INTEL_AUDIT_DSN", "")
        if dsn:
            try:
                import psycopg
                self._pg = psycopg.connect(dsn)
                logger.info("cultural adjustment audit -> Postgres")
            except Exception as exc:
                logger.error("INTEL_AUDIT_DSN set but Postgres unreachable (%s) "
                             "— audit falls back to in-memory buffer", exc)
        logger.info("cultural artifact loaded from %s (%d draws)",
                    self.artifact_dir, len(self.event_uplift))

    # -- calendar helpers ---------------------------------------------------
    def events_on(self, d: date) -> tuple[list[dict], dict | None]:
        """All culturally-active events on ``d`` (raw windows) and the single
        APPLIED event after precedence (exclusive-mask semantics: the applied
        event's fitted uplift already absorbs any lower-precedence overlap)."""
        active = []
        import calendar as _cal
        for e in self.summaries["events"]:
            if e["id"] == "salary_week":
                # month-end ±3d: last 3 days of the month or first 3
                last = _cal.monthrange(d.year, d.month)[1]
                if d.day >= last - 2 or d.day <= 3:
                    active.append(e)
                continue
            s = datetime.strptime(e["start"], "%Y-%m-%d").date()
            t = datetime.strptime(e["end"], "%Y-%m-%d").date()
            if s <= d <= t:
                active.append(e)
        applied = None
        for eid in EVENT_PRECEDENCE:
            hit = next((e for e in active if e["id"] == eid), None)
            if hit is not None:
                applied = hit
                break
        return active, applied

    def zone_of(self, state: str) -> str:
        z = STATE_TO_ZONE.get(state.lower())
        if z is None:
            raise HTTPException(status_code=404,
                                detail=f"unknown state code '{state}'")
        return z

    def event_factor(self, event_id: str, zone: str) -> dict:
        ei = self.event_ids.index(event_id)
        zi = self.zones.index(zone)
        draws = self.event_uplift[:, ei, zi]
        return {"mean": float(draws.mean()),
                "ci95": [float(np.quantile(draws, 0.025)),
                         float(np.quantile(draws, 0.975))],
                "draws": draws}

    def market_factor(self, d: date, zone: str) -> dict:
        zi = self.zones.index(zone)
        L = int(self.summaries["market_cycles"][zone]["cycle_days"])
        k = (d - MARKET_CYCLE_REFERENCE).days % L
        draws = self.market_uplift[:, zi, k]
        day_name = self.summaries["market_cycles"][zone]["day_names"][k]
        return {"mean": float(draws.mean()),
                "ci95": [float(np.quantile(draws, 0.025)),
                         float(np.quantile(draws, 0.975))],
                "draws": draws, "cycle_day": k, "day_name": day_name,
                "is_market_day": k == 0}

    # -- audit ----------------------------------------------------------------
    def audit(self, record: dict) -> dict:
        record = {**record, "request_id": str(uuid.uuid4()),
                  "recorded_at": datetime.utcnow().isoformat() + "Z"}
        if self._pg is not None:
            try:
                with self._pg.cursor() as cur:
                    cur.execute(
                        "INSERT INTO cultural_adjustment_audit "
                        "(request_id, on_date, state, channel, factor, "
                        " components, reason, model_version) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (record["request_id"], record["date"], record["state"],
                         record.get("channel"), record["factor"],
                         json.dumps(record["components"]), record["reason"],
                         record.get("model_version")))
                self._pg.commit()
                record["backend"] = "postgres"
                return record
            except Exception as exc:  # loud fallback, still audited
                logger.error("Postgres audit insert failed (%s); falling back "
                             "to in-memory audit buffer", exc)
        self.audit_log.append(record)
        record["backend"] = "memory"
        return record


def create_cultural_router(artifact_dir: Path) -> APIRouter:
    router = APIRouter(prefix="/v1/intel/cultural", tags=["cultural"])
    store: CulturalStore | None = None
    load_error: str | None = None
    try:
        store = CulturalStore(artifact_dir)
    except Exception as exc:  # fail-closed, loudly (cultural endpoints only)
        load_error = f"cultural artifact missing/unloadable at {artifact_dir}: {exc}"
        logger.error("CULTURAL ARTIFACT UNAVAILABLE — %s. Cultural endpoints "
                     "503 (fail-closed); national endpoints unaffected.",
                     load_error)

    def require_store() -> CulturalStore:
        if store is None:
            raise HTTPException(status_code=503,
                                detail=f"cultural artifact unavailable ({load_error}); "
                                       "cultural endpoints are fail-closed")
        return store

    @router.get("/calendar")
    def calendar(date_: date = Query(..., alias="date"),
                 state: str = Query("lagos")):
        st = require_store()
        zone = st.zone_of(state)
        active, applied = st.events_on(date_)
        out_events = []
        for e in active:
            f = st.event_factor(e["id"], zone)
            out_events.append({
                "id": e["id"], "name": e["name"],
                "lunar_approx": e["lunar_approx"],
                "uplift_mean": f["mean"], "ci95": f["ci95"],
                "applied": applied is not None and e["id"] == applied["id"],
            })
        return {"date": str(date_), "state": state.lower(), "zone": zone,
                "active_events": out_events,
                "applied_event": applied["id"] if applied else None,
                "precedence_note": ("overlapping windows resolve by precedence; "
                                    "the applied event's uplift already absorbs "
                                    "lower-precedence overlaps (never double-counted)"),
                "provenance": st.summaries["provenance"]}

    @router.post("/ajo/assess")
    def ajo_assess(req: AjoAssessRequest):
        st = require_store()
        import math
        feats = {
            "log_n_members": math.log(req.n_members),
            "contribution_cv": req.contribution_cv,
            "cadence_cv": req.cadence_cv,
            "rotation_coverage": req.rotation_coverage,
            "payout_ratio": req.payout_ratio,
            "log_tenure_days": math.log(max(req.tenure_days, 1.0)),
        }
        x = np.array([feats[f] for f in AJO_FEATURES])
        xs = np.concatenate([[1.0], (x - st.ajo_mu) / st.ajo_sd])
        p = 1.0 / (1.0 + np.exp(-(st.ajo_beta @ xs)))
        lo, hi = float(np.quantile(p, 0.025)), float(np.quantile(p, 0.975))
        mean = float(p.mean())
        uncertain = bool(lo < 0.5 < hi)
        assessment = ("uncertain" if uncertain else
                      "likely_legitimate_ajo" if mean >= 0.5 else "likely_fraud")
        contrib = st.ajo_beta.mean(axis=0) * xs
        order = np.argsort(-np.abs(contrib[1:]))
        top = [{"feature": AJO_FEATURES[j],
                "coefficient_mean": float(st.ajo_beta.mean(axis=0)[1 + j]),
                "contribution": float(contrib[1 + j]),
                "direction": ("toward_legitimate" if contrib[1 + j] > 0
                              else "toward_fraud")}
               for j in order[:3]]
        return {"p_legitimate_mean": mean, "ci95": [lo, hi],
                "assessment": assessment, "uncertain": uncertain,
                "uncertain_rule": st.summaries["ajo"]["uncertain_rule"],
                "top_discriminating_features": top,
                "model_auc_test": st.summaries["ajo"]["test_auc"],
                "note": ("declared/registered ajo groups (ajo_groups table) get "
                         "monitored-not-whitelisted treatment: this posterior "
                         "adjusts anomaly context, it never exempts from "
                         "monitoring"),
                "provenance": st.summaries["provenance"]}

    @router.get("/adjustment")
    def adjustment(date_: date = Query(..., alias="date"),
                   state: str = Query(...),
                   channel: str | None = Query(None)):
        st = require_store()
        zone = st.zone_of(state)
        active, applied = st.events_on(date_)
        components: list[dict] = []
        draw_list: list[np.ndarray] = []
        if applied is not None:
            f = st.event_factor(applied["id"], zone)
            components.append({"component": f"calendar:{applied['id']}",
                               "factor_mean": f["mean"], "ci95": f["ci95"],
                               "reason": f"{applied['name']} uplift window"
                                         + (" (lunar approximation)"
                                            if applied["lunar_approx"] else "")})
            draw_list.append(f["draws"])
        mf = st.market_factor(date_, zone)
        if mf["is_market_day"] or mf["mean"] > 1.05:
            components.append({"component": "market_week",
                               "factor_mean": mf["mean"], "ci95": mf["ci95"],
                               "reason": (f"{zone} market-week day "
                                          f"{mf['cycle_day']} ({mf['day_name']})")})
            draw_list.append(mf["draws"])
        if channel == "giving":
            zi = st.zones.index(zone)
            gd = st.giving_uplift[:, zi, date_.weekday()]
            components.append({"component": "giving_rhythm",
                               "factor_mean": float(gd.mean()),
                               "ci95": [float(np.quantile(gd, 0.025)),
                                        float(np.quantile(gd, 0.975))],
                               "reason": f"{zone} weekly giving rhythm "
                                         f"({date_.strftime('%A')})"})
            draw_list.append(gd)
        if draw_list:
            n = min(len(d) for d in draw_list)
            prod = np.prod(np.stack([d[:n] for d in draw_list]), axis=0)
            factor = {"mean": float(prod.mean()),
                      "ci95": [float(np.quantile(prod, 0.025)),
                               float(np.quantile(prod, 0.975))]}
        else:
            factor = {"mean": 1.0, "ci95": [1.0, 1.0]}
        reason = ("; ".join(c["reason"] for c in components)
                  or "no active cultural uplift — factor 1.0")
        record = st.audit({"date": str(date_), "state": state.lower(),
                           "channel": channel, "factor": factor["mean"],
                           "components": [{k: v for k, v in c.items()}
                                          for c in components],
                           "reason": reason,
                           "model_version": st.metrics.get("version")})
        return {"date": str(date_), "state": state.lower(), "zone": zone,
                "channel": channel,
                "adjustment_factor": factor,
                "usage": ("divide the raw anomaly z-score by adjustment_factor.mean "
                          "before thresholding; intervals let analysts keep or "
                          "override the adjustment"),
                "independence_note": ("component posteriors are from separate "
                                      "sub-models and multiplied as if independent "
                                      "(documented approximation)"),
                "components": components,
                "reason": reason,
                "audit": {"recorded": True, "backend": record["backend"],
                          "request_id": record["request_id"]},
                "provenance": st.summaries["provenance"]}

    @router.get("/typologies")
    def typologies(zone: str | None = Query(None)):
        st = require_store()
        rates = st.summaries["affinity_base_rates"]
        if zone is not None:
            if zone not in rates:
                raise HTTPException(status_code=404,
                                    detail=f"unknown zone '{zone}'")
            rates = {zone: rates[zone]}
        return {"typologies": st.summaries["affinity_typologies"],
                "zones": rates,
                "domain_source": ("NIGERIAN_CULTURAL_FRAUD_PATTERNS_* documents "
                                  "(five masquerade typologies)"),
                "note": ("base rates are zone-level aggregates with credible "
                         "intervals — prior context for detectors, never a "
                         "score of any person"),
                "provenance": st.summaries["provenance"]}

    @router.get("/giving-rhythm")
    def giving_rhythm(zone: str | None = Query(None)):
        st = require_store()
        curves = st.summaries["giving_rhythm"]
        if zone is not None:
            if zone not in curves:
                raise HTTPException(status_code=404,
                                    detail=f"unknown zone '{zone}'")
            curves = {zone: curves[zone]}
        return {"zones": curves,
                "note": ("weekly giving rhythm (zone aggregate): Friday Jumu'ah "
                         "/ Sunday service-and-tithe peaks; zone-level only"),
                "provenance": st.summaries["provenance"]}

    @router.post("/score")
    def score(req: CulturalScoreRequest):
        st = require_store()
        indicators = {k: float(np.clip(v, 0.0, 1.0))
                      for k, v in req.indicators.items()}
        unknown = sorted(set(indicators) - set(CULTURAL_FRAUD_WEIGHTS))
        if unknown:
            raise HTTPException(status_code=422,
                                detail=f"unknown indicators: {unknown}")
        raw = sum(CULTURAL_FRAUD_WEIGHTS[k] * v for k, v in indicators.items())
        discount = 0.0
        notes: list[str] = []
        if req.claimed_event and req.date_ is not None:
            active, applied = st.events_on(req.date_)
            active_ids = {e["id"] for e in active}
            # map loose claims onto calendar ids
            claim = req.claimed_event.lower()
            matched = any(claim in eid or eid in claim for eid in active_ids)
            if matched:
                discount += 0.05
                notes.append("claimed event window matches the cultural calendar")
            else:
                raw = min(1.0, raw + 0.10)
                notes.append("CLAIMED EVENT IS OUT OF ITS CULTURAL WINDOW "
                             "(calendar inconsistency)")
        if req.network_consistent_with_claimed_norm:
            discount += 0.05
            notes.append("network structure consistent with the claimed norm")
        if req.ajo_pattern is not None and req.claimed_event and \
                req.claimed_event.lower() in ("ajo", "esusu", "adashe", "cooperative"):
            import math
            rp = req.ajo_pattern
            feats = [math.log(rp.n_members), rp.contribution_cv, rp.cadence_cv,
                     rp.rotation_coverage, rp.payout_ratio,
                     math.log(max(rp.tenure_days, 1.0))]
            xs = np.concatenate([[1.0], (np.array(feats) - st.ajo_mu) / st.ajo_sd])
            p_ajo = float((1.0 / (1.0 + np.exp(-(st.ajo_beta @ xs)))).mean())
            if p_ajo >= 0.8:
                discount += 0.05
                notes.append(f"rotation pattern consistent with legitimate ajo "
                             f"(posterior {p_ajo:.2f})")
            elif p_ajo <= 0.3:
                notes.append(f"rotation pattern INCONSISTENT with legitimate ajo "
                             f"(posterior {p_ajo:.2f})")
        discount = min(discount, 0.15)
        final = float(np.clip(raw - discount, 0.0, 1.0))
        return {"cultural_fraud_score": round(final, 4),
                "risk_band": risk_band(final),
                "indicator_breakdown": {
                    k: {"severity": indicators.get(k, 0.0),
                        "weight": CULTURAL_FRAUD_WEIGHTS[k],
                        "contribution": round(indicators.get(k, 0.0)
                                              * CULTURAL_FRAUD_WEIGHTS[k], 4)}
                    for k in CULTURAL_FRAUD_WEIGHTS},
                "authenticity_discount": round(discount, 4),
                "authenticity_notes": notes,
                "weights_source": ("canonical normalisation of the domain "
                                   "documents' indicator weights "
                                   "(NIGERIAN_CULTURAL_FRAUD_PATTERNS_*)"),
                "provenance": st.summaries["provenance"]}

    router.cultural_store = store  # type: ignore[attr-defined]  (test hook)
    router.cultural_load_error = load_error  # type: ignore[attr-defined]
    return router
