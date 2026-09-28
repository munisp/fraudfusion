"""Cultural Intelligence for Nigeria: MCMC posteriors over the culturally
patterned rhythms of legitimate Nigerian financial life, so the fraud
platform neither false-flags communal finance nor misses fraud hidden
inside cultural patterns.

Five coupled Bayesian models, all fit with the dependency-light MCMC
toolkit in ``ml.bayesian.mcmc`` (NUTS / NUTS-lite, torch autograd) and all
reporting split R-hat / ESS diagnostics:

1. **Ajo/esusu legitimacy posterior** — Bayesian logistic regression for
   P(legitimate rotating-savings club | transfer-pattern summary). Ajo /
   esusu / adashe clubs (equal periodic contributions rotating a lump sum
   so every member receives exactly once) look EXACTLY like
   structuring/smurfing to a naive detector. The honest discriminators are
   rotation reciprocity (coverage ~1.0, payout ratio ~1) vs fan-out /
   ponzi payout asymmetry. Trained on synthetic ajo cycles vs synthetic
   fake-ajo ponzi rings and structuring rings; held-out AUC reported
   honestly. Output includes an explicit ``uncertain`` zone — patterns the
   posterior cannot separate are declared uncertain, never forced.

2. **Cultural calendar uplift model** — per-event posterior log-uplift
   multipliers on transaction volume, hierarchical partial pooling across
   the 6 geopolitical zones. Priors carry DOCUMENTED zone-composition
   assumptions (aggregate level, wide) — e.g. Eid events are prior-centred
   higher in northern zones, Christmas/Easter/Detty December in southern
   zones — and the likelihood (window-vs-baseline log volume ratios) is
   strong enough to dominate. Lunar events (Eid al-Fitr, Eid al-Adha) use
   2026 Gregorian approximations and are flagged ``lunar_approx``.

3. **Market-week cycle posteriors** — cyclic harmonic Bayesian regression
   per zone on daily volume: 4-day South-East market week
   (Eke/Orie/Afo/Nkwo), 5-day South-West cycle, 7-day northern weekly
   markets. Closes the "no per-town 4/8-day market calendars" gap at zone
   resolution.

4. **Religious giving rhythm** — weekly harmonic posterior on giving-type
   transfers (Friday Jumu'ah / Sunday service-and-tithe peaks), partial
   pooling across zones. Zone-level aggregate only.

5. **Affinity-fraud base rates** — per-zone partial-pooling posteriors for
   culturally-specific fraud typologies (community/religious-network
   affinity ponzi, romance scams, festive-season impersonation); feeds the
   investment-fraud detector's priors.

ETHICS GUARDRAIL (enforced, tested in ml/tests/test_cultural_intelligence.py):
these models adjust for transaction PATTERNS in cultural context — never
the person. There are NO per-individual ethnicity/religion/tribe/language
features anywhere in this module, in the served schemas, or in the
synthetic generator's cultural layer. Geography enters only as the
state/zone the account already carries, and only as zone-level AGGREGATE
priors. Posteriors are statistical descriptions with honestly wide
uncertainty, not judgments of any group (stereotype-risk caveat in
docs/CULTURAL_INTELLIGENCE.md).

TRAINING DATA IS SYNTHETIC (seeded ``synth_cultural`` below; assumptions
documented in code and MODEL_CARD.md). No real NIBSS/NFIU feed exists in
this repo and none is faked.

Run:
    python -m ml.bayesian.cultural_intelligence [--version v1] [--quick]
or the thin wrapper:
    python -m ml.train.train_cultural_intel [--version v1]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.bayesian import mcmc  # noqa: E402
from ml.bayesian.national_intelligence import (  # noqa: E402
    STATES, ZONES, _fit_whitened, _logit, _sigmoid)
from ml.train.common import ARTIFACT_ROOT, set_seed  # noqa: E402

MODEL_NAME = "cultural_intelligence"
REFERENCE_YEAR = 2026

# ---------------------------------------------------------------------------
# ETHICS GUARDRAIL: per-individual sensitive-attribute terms that must never
# appear in any feature schema, request/response field, or generated column
# of the cultural layer. The meta-test asserts this list matches nothing.
# NOTE: the five CULTURAL_FRAUD_TYPOLOGIES labels (e.g.
# "religious_manipulation") are FRAUD-SCHEME category names from the domain
# documents, not person attributes — the meta-test exempts exactly those
# label strings and nothing else.
# ---------------------------------------------------------------------------
FORBIDDEN_ATTRIBUTE_RE = re.compile(
    r"religion|ethnic|tribe|tribal|language|yoruba|igbo|hausa|"
    r"fulani|muslim|christian", re.IGNORECASE)

STATE_TO_ZONE = {code: zone for code, _, zone, _ in STATES}

# ---------------------------------------------------------------------------
# Cultural calendar 2026. Lunar events use 2026 Gregorian approximations
# (Umm al-Qura-style estimates) and are flagged; they drift ±1-2 days.
# ``window`` is (start, end) inclusive; Detty December and Christmas are
# modelled as nested events (season uplift x day uplift) — see
# ``event_masks``: the Detty December mask excludes Christmas days so the
# two effects are identified separately, and the API multiplies them.
# ---------------------------------------------------------------------------
CULTURAL_EVENTS_2026 = [
    {"id": "new_year", "name": "New Year", "start": "2026-01-01",
     "end": "2026-01-02", "lunar_approx": False},
    {"id": "eid_al_fitr", "name": "Eid al-Fitr (Sallah)", "start": "2026-03-20",
     "end": "2026-03-22", "lunar_approx": True},
    {"id": "easter", "name": "Easter (Good Friday–Easter Monday)",
     "start": "2026-04-03", "end": "2026-04-06", "lunar_approx": False},
    {"id": "eid_al_adha", "name": "Eid al-Adha (Big Sallah)",
     "start": "2026-05-27", "end": "2026-05-29", "lunar_approx": True},
    {"id": "independence_day", "name": "Independence Day",
     "start": "2026-10-01", "end": "2026-10-02", "lunar_approx": False},
    {"id": "detty_december", "name": "Detty December season",
     "start": "2026-12-15", "end": "2026-12-31", "lunar_approx": False},
    {"id": "christmas", "name": "Christmas", "start": "2026-12-24",
     "end": "2026-12-26", "lunar_approx": False},
    {"id": "salary_week", "name": "Salary week (month-end ±3d, recurring)",
     "start": None, "end": None, "lunar_approx": False},
]
EVENT_IDS = [e["id"] for e in CULTURAL_EVENTS_2026]

# DOCUMENTED zone-composition prior offsets (aggregate, wide priors): the
# prior MEAN of each event's zone uplift is shifted by these constants
# before partial pooling; the likelihood dominates where windows carry
# volume. These describe where each festival is more widely observed at
# zone level — never attributes of any individual.
EVENT_ZONE_PRIOR_OFFSET = {
    "eid_al_fitr": {"north_west": 0.30, "north_east": 0.30, "north_central": 0.15},
    "eid_al_adha": {"north_west": 0.30, "north_east": 0.30, "north_central": 0.15},
    "christmas": {"south_west": 0.20, "south_east": 0.25, "south_south": 0.20,
                  "north_central": 0.10},
    "easter": {"south_west": 0.15, "south_east": 0.20, "south_south": 0.15,
               "north_central": 0.05},
    "detty_december": {"south_west": 0.25, "south_south": 0.15,
                       "south_east": 0.15, "north_central": 0.10},
    "independence_day": {},
    "new_year": {"south_west": 0.10, "north_central": 0.05},
    "salary_week": {},
}

# ---------------------------------------------------------------------------
# Market-week cycles (zone aggregate): 4-day SE market week
# (Eke/Orie/Afo/Nkwo), 5-day SW cycle, 7-day northern weekly markets.
# ---------------------------------------------------------------------------
MARKET_CYCLE = {
    "south_east": {"days": 4, "names": ["Eke", "Orie", "Afo", "Nkwo"]},
    "south_south": {"days": 4, "names": ["Eke", "Orie", "Afo", "Nkwo"]},
    "south_west": {"days": 5, "names": ["Aje", "Asegun", "Itolo", "Ojo", "Ife"]},
    "north_central": {"days": 7, "names": ["market_day"] + [f"day_{i}" for i in range(1, 7)]},
    "north_west": {"days": 7, "names": ["market_day"] + [f"day_{i}" for i in range(1, 7)]},
    "north_east": {"days": 7, "names": ["market_day"] + [f"day_{i}" for i in range(1, 7)]},
}
MARKET_CYCLE_REFERENCE = np.datetime64("2025-12-31")  # day-0 = market day

# Ajo legitimacy model features (pattern-level ONLY — no person attributes).
AJO_FEATURES = [
    "log_n_members",        # log group size
    "contribution_cv",      # CV of contribution amounts (equal in real ajo)
    "cadence_cv",           # CV of inter-transfer gaps (regular in real ajo)
    "rotation_coverage",    # fraction of members receiving exactly once/cycle
    "payout_ratio",         # mean payout / (n_members x contribution); ~1 legit
    "log_tenure_days",      # log group tenure
]
AJO_UNCERTAIN_CI_LEVEL = 0.95   # CI straddling 0.5 -> "uncertain"

# The five culturally-specific fraud typologies (domain source: uploaded
# NIGERIAN_CULTURAL_FRAUD_PATTERNS_* documents) — fraud masquerading as
# cultural norms. Model 5 estimates per-zone posterior base rates.
CULTURAL_FRAUD_TYPOLOGIES = [
    "ceremony_exploitation", "religious_manipulation",
    "family_obligation_abuse", "business_practice_abuse",
    "authority_status_abuse",
]

# Weighted indicator scoring (canonical set distilled from the domain
# documents' per-pattern indicator weights — they vary 0.15-0.4 across
# documents; this is the documented canonical normalisation used here).
CULTURAL_FRAUD_WEIGHTS = {
    "temporal_anomaly": 0.20,         # off-season / odd-hour vs cultural calendar
    "network_anomaly": 0.25,          # no prior relationship / broadcast fan-in
    "cultural_inconsistency": 0.20,   # contradicts the claimed cultural norm
    "amount_anomaly": 0.15,           # above cultural-norm amount ranges
    "communication_anomaly": 0.10,    # social-engineering script signals
    "urgency": 0.10,                  # artificial urgency pressure
}
RISK_BANDS = [(0.8, "critical"), (0.6, "high"), (0.4, "medium"), (0.0, "low")]

DAYS = 365  # reference year length (2026)


def risk_band(score: float) -> str:
    for thr, band in RISK_BANDS:
        if score >= thr:
            return band
    return "low"


def cultural_fraud_score(indicators: dict[str, float],
                         authenticity: dict | None = None) -> dict:
    """Weighted cultural-fraud indicator score (0..1) + risk band.

    ``indicators`` maps the six CULTURAL_FRAUD_WEIGHTS indicator names to
    severities in [0, 1] (pattern-level signals only — NO person
    attributes). ``authenticity`` optionally carries the cultural
    authenticity check: {"event_matches_calendar": bool,
    "claimed_event": str|None, "ajo_p_legitimate": float|None,
    "network_consistent_with_claimed_norm": bool}. Consistent authenticity
    evidence DISCOUNTS the score (max -0.15), documented: legitimate
    cultural context is evidence against, never for, fraud.
    """
    unknown = sorted(set(indicators) - set(CULTURAL_FRAUD_WEIGHTS))
    if unknown:
        raise ValueError(f"unknown indicators: {unknown}")
    parts = {k: float(np.clip(indicators.get(k, 0.0), 0.0, 1.0))
             for k in CULTURAL_FRAUD_WEIGHTS}
    raw = sum(CULTURAL_FRAUD_WEIGHTS[k] * v for k, v in parts.items())
    discount = 0.0
    notes = []
    if authenticity:
        if authenticity.get("event_matches_calendar"):
            discount += 0.05
            notes.append("claimed event window matches the cultural calendar")
        elif authenticity.get("claimed_event"):
            notes.append("CLAIMED EVENT IS OUT OF ITS CULTURAL WINDOW "
                         "(calendar inconsistency)")
            raw = min(1.0, raw + 0.10)
        if authenticity.get("network_consistent_with_claimed_norm"):
            discount += 0.05
            notes.append("network structure consistent with the claimed norm")
        p_ajo = authenticity.get("ajo_p_legitimate")
        if p_ajo is not None and authenticity.get("claimed_event") in (
                "ajo", "esusu", "adashe", "cooperative"):
            if p_ajo >= 0.8:
                discount += 0.05
                notes.append(f"rotation pattern consistent with legitimate ajo "
                             f"(posterior {p_ajo:.2f})")
            elif p_ajo <= 0.3:
                notes.append(f"rotation pattern INCONSISTENT with legitimate ajo "
                             f"(posterior {p_ajo:.2f})")
    discount = min(discount, 0.15)
    score = float(np.clip(raw - discount, 0.0, 1.0))
    return {"cultural_fraud_score": round(score, 4),
            "risk_band": risk_band(score),
            "indicator_breakdown": {k: {"severity": v,
                                        "weight": CULTURAL_FRAUD_WEIGHTS[k],
                                        "contribution": round(v * CULTURAL_FRAUD_WEIGHTS[k], 4)}
                                    for k, v in parts.items()},
            "authenticity_discount": round(discount, 4),
            "authenticity_notes": notes,
            "weights_source": ("canonical normalisation of the domain "
                               "documents' indicator weights "
                               "(NIGERIAN_CULTURAL_FRAUD_PATTERNS_*)")}


# ---------------------------------------------------------------------------
# Synthetic training data (seeded; assumptions documented inline)
# ---------------------------------------------------------------------------
def _date_range(year: int = REFERENCE_YEAR) -> np.ndarray:
    return np.arange(np.datetime64(f"{year}-01-01"),
                     np.datetime64(f"{year}-01-01") + DAYS)


def event_masks(dates: np.ndarray, exclusive: bool = True
                ) -> dict[str, np.ndarray]:
    """Boolean (DAYS,) masks per event. salary_week = last 3 / first 3 days
    of every month.

    Overlapping windows (documented): with ``exclusive=True`` each day is
    assigned to at most ONE event by EVENT_PRECEDENCE (specific events beat
    the recurring salary week; Christmas beats Detty December). The
    higher-precedence event's fitted uplift then ABSORBS the overlapped
    effect (e.g. New Year Jan 1-2 sits inside salary week, so the fitted
    New Year uplift includes the salary component) — the serving API
    applies only the assigned event's factor, never both, so served
    factors stay unbiased. The synthetic TRUTH applies all effects
    multiplicatively (``exclusive=False``); the calibration metric compares
    against the absorbed-overlap expectation, not the bare event truth.
    """
    month = dates.astype("datetime64[M]")
    m0 = month.astype("datetime64[D]")
    dom = (dates - m0).astype(int) + 1
    month_len = ((month + 1).astype("datetime64[D]") - m0).astype(int)
    masks: dict[str, np.ndarray] = {}
    for e in CULTURAL_EVENTS_2026:
        if e["id"] == "salary_week":
            masks[e["id"]] = (dom >= month_len - 2) | (dom <= 3)
            continue
        s, t = np.datetime64(e["start"]), np.datetime64(e["end"])
        masks[e["id"]] = (dates >= s) & (dates <= t)
    if not exclusive:
        return masks
    taken = np.zeros(len(dates), dtype=bool)
    for eid in EVENT_PRECEDENCE:
        masks[eid] = masks[eid] & ~taken
        taken |= masks[eid]
    return masks


# Specific cultural events take precedence over the recurring salary week;
# Christmas/New Year inside Detty December take precedence over the season.
EVENT_PRECEDENCE = ["christmas", "new_year", "independence_day", "easter",
                    "eid_al_fitr", "eid_al_adha", "detty_december",
                    "salary_week"]


def synth_cultural(seed: int = 42) -> dict:
    """One synthetic reference year (2026) of cultural-pattern training data.

    Assumptions (all synthetic, deterministic given ``seed``):
      * Daily platform-observable volume per zone ~ Poisson(base_z x
        market-cycle uplift x event uplift x weekly seasonality x noise),
        base_z proportional to national_intelligence volume weights.
      * True market-cycle uplift: exp(rho_z cos(2 pi k / L_z)), peak on the
        zone's market day (k=0), rho_z in [0.25, 0.5] — strongest in the
        South East 4-day cycle.
      * True event uplifts: zone means documented in code (Eid higher in
        northern zones, Christmas/Easter/Detty December higher in southern
        zones, Independence Day / salary week uniform) + N(0, 0.05) noise.
      * Giving-type transfers: Poisson with a weekly harmonic peaking
        Friday (northern zones, Jumu'ah) or Sunday (southern zones,
        services/tithes); North Central mixes both. Zone-level only.
      * Culturally-specific fraud: per zone weekly fraud incidents split
        into the five documented masquerade typologies
        (CULTURAL_FRAUD_TYPOLOGIES) with documented zone-level true shares.
      * Ajo groups: 400 synthetic group summaries — 200 legit rotating
        clubs, 100 fake-ajo ponzi rings, 100 structuring/smurfing rings —
        with the six AJO_FEATURES and honest labels.
    """
    rng = np.random.default_rng(seed)
    dates = _date_range()
    masks_raw = event_masks(dates, exclusive=False)   # truth: all apply
    masks = event_masks(dates, exclusive=True)        # model: precedence
    Z = len(ZONES)

    zone_weight = np.zeros(Z)
    for code, _, zone, w in STATES:
        zone_weight[ZONES.index(zone)] += w
    base_daily = 430_000 * zone_weight / zone_weight.sum()   # ~3M/week

    # --- true market-cycle harmonics ---------------------------------------
    rho_true = {"south_east": 0.50, "south_south": 0.35, "south_west": 0.40,
                "north_central": 0.25, "north_west": 0.30, "north_east": 0.30}
    cyc_day = (dates - MARKET_CYCLE_REFERENCE).astype(int)
    market_true = np.ones((Z, DAYS))
    for zi, z in enumerate(ZONES):
        L = MARKET_CYCLE[z]["days"]
        market_true[zi] = np.exp(rho_true[z] * np.cos(2 * np.pi * (cyc_day % L) / L))

    # --- true event uplifts (log space) -------------------------------------
    true_event_mean = {
        "eid_al_fitr": {"north_west": 0.65, "north_east": 0.65, "north_central": 0.50,
                        "south_west": 0.25, "south_south": 0.15, "south_east": 0.15},
        "eid_al_adha": {"north_west": 0.60, "north_east": 0.60, "north_central": 0.45,
                        "south_west": 0.20, "south_south": 0.12, "south_east": 0.12},
        "christmas": {"south_west": 0.55, "south_east": 0.60, "south_south": 0.55,
                      "north_central": 0.40, "north_west": 0.25, "north_east": 0.20},
        "easter": {"south_west": 0.40, "south_east": 0.45, "south_south": 0.40,
                   "north_central": 0.30, "north_west": 0.15, "north_east": 0.12},
        "detty_december": {"south_west": 0.70, "south_south": 0.50, "south_east": 0.50,
                           "north_central": 0.45, "north_west": 0.25, "north_east": 0.20},
        "independence_day": {z: 0.25 for z in ZONES},
        "new_year": {z: 0.30 for z in ZONES},
        "salary_week": {z: 0.35 for z in ZONES},
    }
    event_true = {eid: np.array([true_event_mean[eid][z] + rng.normal(0, 0.05)
                                 for z in ZONES]) for eid in EVENT_IDS}

    # --- daily volumes -------------------------------------------------------
    dow = (dates.astype("datetime64[D]").astype(int) + 3) % 7  # 2026-01-01 = Thu(3)
    weekly = np.exp(0.08 * np.cos(2 * np.pi * (dow - 4) / 7))   # mild Friday peak
    y_vol = np.empty((Z, DAYS), dtype=np.int64)
    total_event_uplift = np.zeros((Z, DAYS))
    for zi in range(Z):
        lam = base_daily[zi] * market_true[zi] * weekly
        for eid in EVENT_IDS:
            lam = lam * np.where(masks_raw[eid], np.exp(event_true[eid][zi]), 1.0)
            total_event_uplift[zi] += np.where(masks_raw[eid],
                                               event_true[eid][zi], 0.0)
        lam = lam * np.exp(rng.normal(0, 0.05, DAYS))
        y_vol[zi] = rng.poisson(lam)

    # --- giving-type transfers (weekly rhythm) -------------------------------
    # True phase: Friday (dow=4) peak in northern zones; Sunday (dow=6) peak
    # in southern zones; north_central mixes both at half amplitude each.
    give_base = base_daily * 0.02
    rho_g, phase1, phase2 = {}, {}, {}
    for z in ZONES:
        if z in ("north_west", "north_east"):
            rho_g[z], phase1[z], phase2[z] = 0.65, 4.0, None
        elif z == "north_central":
            rho_g[z], phase1[z], phase2[z] = 0.45, 4.0, 6.0
        else:
            rho_g[z], phase1[z], phase2[z] = 0.70, 6.0, None
    y_give = np.empty((Z, DAYS), dtype=np.int64)
    for zi, z in enumerate(ZONES):
        if phase2[z] is not None:
            # mixed zone (north_central): genuine Friday AND Sunday peaks
            # with a Saturday lull — a direct day table, NOT a single
            # cosine (a Fri+Sun cosine average peaks on Saturday, which is
            # not the real rhythm).
            u = np.where(dow == 4, rho_g[z],
                  np.where(dow == 6, 0.9 * rho_g[z],
                           np.where(dow == 5, 0.1 * rho_g[z],
                                    -0.15 * rho_g[z])))
        else:
            u = rho_g[z] * np.cos(2 * np.pi * (dow - phase1[z]) / 7)
        lam = give_base[zi] * np.exp(u) * np.exp(rng.normal(0, 0.06, DAYS))
        y_give[zi] = rng.poisson(lam)

    # --- culturally-specific fraud weekly incidents -------------------------
    # Documented zone-level true shares (synthetic assumptions; wide
    # posterior intervals carry the uncertainty). Basis: ceremony/title
    # exploitation and diaspora family-obligation appeals skew southern
    # (diaspora corridors), igba-boi apprenticeship abuse concentrates in
    # the South East, cooperative/ajo investment fraud in the South West,
    # authority impersonation slightly higher where traditional-ruler and
    # political structures intermediates payments.
    true_affinity_share = {
        "ceremony_exploitation": {"south_west": 0.10, "south_east": 0.09,
                                  "south_south": 0.08, "north_central": 0.06,
                                  "north_west": 0.04, "north_east": 0.04},
        "religious_manipulation": {"south_west": 0.08, "south_east": 0.09,
                                   "south_south": 0.07, "north_central": 0.07,
                                   "north_west": 0.08, "north_east": 0.07},
        "family_obligation_abuse": {"south_west": 0.09, "south_east": 0.10,
                                    "south_south": 0.08, "north_central": 0.07,
                                    "north_west": 0.05, "north_east": 0.05},
        "business_practice_abuse": {"south_east": 0.12, "south_west": 0.10,
                                    "south_south": 0.09, "north_central": 0.07,
                                    "north_west": 0.06, "north_east": 0.05},
        "authority_status_abuse": {"north_central": 0.09, "north_west": 0.08,
                                   "north_east": 0.08, "south_west": 0.07,
                                   "south_south": 0.06, "south_east": 0.06},
    }
    n_fraud_week = np.empty((Z, 52), dtype=np.int64)
    y_aff = np.empty((Z, len(CULTURAL_FRAUD_TYPOLOGIES)), dtype=np.int64)
    n_aff = np.empty(Z, dtype=np.int64)
    for zi, z in enumerate(ZONES):
        lam = base_daily[zi] * 7 * 0.01          # ~1% of volume flagged fraud
        n_fraud_week[zi] = rng.poisson(lam)
        n_aff[zi] = n_fraud_week[zi].sum()
        for ki, k in enumerate(CULTURAL_FRAUD_TYPOLOGIES):
            share = true_affinity_share[k][z] * np.exp(rng.normal(0, 0.08))
            y_aff[zi, ki] = rng.binomial(n_aff[zi], min(share, 0.9))

    # --- ajo groups ------------------------------------------------------------
    ajo = synth_ajo_groups(rng)
    return {
        "seed": seed, "year": REFERENCE_YEAR, "zones": ZONES,
        "dates": dates, "event_masks": masks, "dow": dow,
        "cycle_day": cyc_day,
        "y_vol": y_vol, "base_daily": base_daily,
        "market_true": market_true, "event_true": event_true,
        "total_event_uplift_true": total_event_uplift,
        "y_give": y_give, "rho_give_true": rho_g,
        "n_aff": n_aff, "y_aff": y_aff,
        "true_affinity_share": true_affinity_share,
        "ajo": ajo,
    }


def synth_ajo_groups(rng: np.random.Generator, n_legit: int = 200,
                     n_ponzi: int = 100, n_struct: int = 100) -> dict:
    """Synthetic group-level transfer-pattern summaries with honest labels.

    y=1 legitimate rotating savings club; y=0 fraud (fake-ajo ponzi or
    structuring/smurfing ring). Feature conventions in AJO_FEATURES.
    """
    n = n_legit + n_ponzi + n_struct
    X = np.empty((n, len(AJO_FEATURES)))
    y = np.zeros(n, dtype=np.int64)
    kind = np.array(["legit"] * n_legit + ["fake_ajo_ponzi"] * n_ponzi
                    + ["structuring_ring"] * n_struct)

    # legit ajo: equal contributions, regular cadence, full rotation,
    # payout ~= n x contribution, long tenure. ~15% are young clubs still
    # mid-cycle (rotation incomplete) — honest overlap with fraud.
    n_mem = rng.integers(5, 21, n_legit)
    young = rng.random(n_legit) < 0.15
    cov_legit = np.where(young, rng.normal(0.70, 0.10, n_legit),
                         rng.normal(0.97, 0.04, n_legit))
    cad_legit = np.where(young, rng.normal(0.15, 0.07, n_legit),
                         rng.normal(0.08, 0.05, n_legit))
    X[:n_legit] = np.column_stack([
        np.log(n_mem),
        np.clip(rng.normal(0.03, 0.02, n_legit), 0.005, None),
        np.clip(cad_legit, 0.01, None),
        np.clip(cov_legit, 0, 1),
        np.clip(rng.normal(0.95, 0.06, n_legit), 0.5, 1.2),
        np.log(rng.uniform(60, 720, n_legit)),
    ])
    y[:n_legit] = 1
    # fake-ajo ponzi: escalating contributions, partial rotation, inflated
    # early payouts, short tenure before collapse. ~20% fake the rotation
    # with wash transfers among members, so coverage alone cannot separate.
    s = slice(n_legit, n_legit + n_ponzi)
    n_mem = rng.integers(6, 18, n_ponzi)
    washed = rng.random(n_ponzi) < 0.20
    cov_ponzi = np.where(washed, rng.normal(0.70, 0.10, n_ponzi),
                         np.clip(rng.normal(0.22, 0.10, n_ponzi), 0, 0.6))
    pay_ponzi = np.where(washed, rng.normal(1.15, 0.30, n_ponzi),
                         rng.normal(1.7, 0.45, n_ponzi))
    # washed rings keep contributions steady (no escalation) to look calm
    cv_ponzi = np.where(washed, rng.normal(0.08, 0.05, n_ponzi),
                        rng.normal(0.28, 0.12, n_ponzi))
    X[s] = np.column_stack([
        np.log(n_mem),
        np.clip(cv_ponzi, 0.01, None),
        np.clip(rng.normal(0.15, 0.08, n_ponzi), 0.02, None),
        np.clip(cov_ponzi, 0, 1),
        np.clip(pay_ponzi, 0.9, None),
        np.log(rng.uniform(21, 180, n_ponzi)),
    ])
    # structuring/smurfing ring: equal sub-threshold amounts (LOW
    # contribution_cv like ajo); most are bursty, but ~30% are automated
    # regular-interval smurfing (cadence_cv overlapping legit ajo). NO
    # rotation (fan-out to one collector), payout never returns, very short
    # tenure.
    s = slice(n_legit + n_ponzi, n)
    n_mem = rng.integers(4, 15, n_struct)
    automated = rng.random(n_struct) < 0.30
    cad_struct = np.where(automated, rng.normal(0.20, 0.08, n_struct),
                          rng.normal(0.55, 0.20, n_struct))
    # ~15% round-trip funds back through the ring (layering), faking partial
    # rotation and near-parity payouts — the genuine confusion region.
    roundtrip = rng.random(n_struct) < 0.15
    cov_struct = np.where(roundtrip, np.clip(rng.normal(0.68, 0.08, n_struct), 0, 1),
                          np.clip(rng.normal(0.05, 0.05, n_struct), 0, 0.3))
    pay_struct = np.where(roundtrip, rng.normal(0.95, 0.15, n_struct),
                          np.clip(rng.normal(0.12, 0.10, n_struct), 0.0, 0.5))
    cad_struct = np.where(roundtrip, rng.normal(0.15, 0.06, n_struct),
                          cad_struct)
    X[s] = np.column_stack([
        np.log(n_mem),
        np.clip(np.where(roundtrip, rng.normal(0.06, 0.04, n_struct),
                         rng.normal(0.04, 0.03, n_struct)), 0.005, None),
        np.clip(cad_struct, 0.05, None),
        np.clip(cov_struct, 0, 1),
        np.clip(pay_struct, 0.0, None),
        np.log(rng.uniform(7, 200, n_struct)),
    ])
    return {"X": X, "y": y, "kind": kind, "features": list(AJO_FEATURES)}


def ajo_design(X_raw: np.ndarray) -> np.ndarray:
    """Standardised design matrix with intercept column prepended."""
    X = np.asarray(X_raw, dtype=np.float64)
    mu = X.mean(axis=0)
    sd = X.std(axis=0)
    sd = np.where(sd <= 0, 1.0, sd)
    Xs = (X - mu) / sd
    return np.column_stack([np.ones(len(X)), Xs]), mu, sd


# ---------------------------------------------------------------------------
# Model 1: ajo/esusu legitimacy posterior (Bayesian logistic regression)
# ---------------------------------------------------------------------------
def fit_ajo_model(ajo: dict, n_samples: int = 800, burn: int = 1000,
                  n_chains: int = 4, seed: int = 42) -> dict:
    """y ~ Bernoulli(sigmoid(X beta)); beta ~ N(0, 2^2) (weakly informative).

    70/30 stratified split: fit on train, held-out AUC reported honestly.
    NUTS-lite without whitening (dim=7, benign geometry). Needs a real
    warmup (burn >= ~600): with honest class overlap the posterior has
    enough curvature that short-burn chains do not mix (verified
    empirically: burn=300 -> max R-hat 1.8; burn=600 -> ~1.01).
    """
    import torch
    X, y = ajo["X"], ajo["y"]
    rng = np.random.default_rng(seed + 1)
    idx = rng.permutation(len(y))
    n_tr = int(0.7 * len(y))
    tr, te = idx[:n_tr], idx[n_tr:]
    Xd, mu, sd = ajo_design(X[tr])
    Xte = np.column_stack([np.ones(len(te)), (X[te] - mu) / sd])
    ytr, yte = y[tr], y[te]
    D = torch.as_tensor(Xd)
    yv = torch.as_tensor(ytr.astype(np.float64))

    def logpost_torch(beta):
        eta = D @ beta
        ll = torch.sum(yv * eta - torch.logaddexp(torch.zeros_like(eta), eta))
        lp = -0.5 * torch.sum((beta / 2.0) ** 2)
        return ll + lp

    t0 = time.time()
    res = mcmc.nuts_lite(mcmc._torch_logpost_and_grad(logpost_torch),
                         np.zeros(Xd.shape[1]), n_samples=n_samples,
                         n_chains=n_chains, burn=burn, step_size=0.15,
                         max_leapfrog=8, seed=seed)
    fit_s = time.time() - t0
    summ = mcmc.summarize(res["samples"])
    flat = res["samples"].reshape(-1, Xd.shape[1])
    # held-out scoring: posterior-mean probability per test group
    p_te = _sigmoid(Xte @ flat.T)                      # (n_te, draws)
    p_mean = p_te.mean(axis=1)
    auc = _roc_auc(yte, p_mean)
    acc = float(((p_mean > 0.5).astype(int) == yte).mean())
    return {"res": res, "summ": summ, "flat": flat, "feature_mu": mu,
            "feature_sd": sd, "fit_seconds": fit_s,
            "test": {"y": yte, "p_mean": p_mean, "p_draws": p_te,
                     "kind": ajo["kind"][te], "auc": auc, "accuracy": acc},
            "names": ["intercept"] + AJO_FEATURES}


def _roc_auc(y: np.ndarray, score: np.ndarray) -> float:
    """Rank-based AUC (no sklearn dependency at fit time)."""
    y = np.asarray(y)
    pos, neg = score[y == 1], score[y == 0]
    order = np.argsort(np.concatenate([pos, neg]), kind="mergesort")
    ranks = np.empty(len(order))
    ranks[order] = np.arange(1, len(order) + 1)
    # average ranks for ties
    vals = np.concatenate([pos, neg])
    _, inv, cnt = np.unique(vals, return_inverse=True, return_counts=True)
    sums = np.bincount(inv, ranks)
    avg = sums / cnt
    r = avg[inv]
    rp = r[:len(pos)].sum()
    return float((rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def ajo_predict(beta_draws: np.ndarray, feature_mu: np.ndarray,
                feature_sd: np.ndarray, features: dict) -> dict:
    """Posterior P(legitimate ajo | pattern summary) with CI + uncertain zone.

    ``features`` maps AJO_FEATURES names to values. Uncertain when the 95%
    credible interval of the probability straddles 0.5.
    """
    x = np.array([float(features[f]) for f in AJO_FEATURES])
    xs = np.concatenate([[1.0], (x - feature_mu) / feature_sd])
    p = _sigmoid(beta_draws @ xs)
    lo_a, hi_a = mcmc.credible_interval(p.reshape(-1, 1))
    lo, hi = float(lo_a[0]), float(hi_a[0])
    mean = float(p.mean())
    uncertain = bool(lo < 0.5 < hi)
    label = "uncertain" if uncertain else ("likely_legitimate_ajo"
                                           if mean >= 0.5 else "likely_fraud")
    # top discriminating features: |beta_j * x_j| contribution to the logit
    flat = beta_draws.mean(axis=0)
    contrib = flat * xs
    order = np.argsort(-np.abs(contrib[1:]))
    top = [{"feature": AJO_FEATURES[j],
            "coefficient_mean": float(flat[1 + j]),
            "contribution": float(contrib[1 + j]),
            "direction": ("toward_legitimate" if contrib[1 + j] > 0
                          else "toward_fraud")}
           for j in order[:3]]
    return {"p_legitimate_mean": mean, "ci95": [float(lo), float(hi)],
            "assessment": label, "uncertain": uncertain,
            "top_discriminating_features": top}


# ---------------------------------------------------------------------------
# Model 3 (fit before 2): market-week cyclic harmonic regression per zone
# ---------------------------------------------------------------------------
def fit_market_model(data: dict, n_samples: int = 800, burn: int = 800,
                     n_chains: int = 4, seed: int = 42) -> dict:
    """y_zt ~ Poisson(exp(a_z + b_z cos(2 pi k_t/L_z) + c_z sin(2 pi k_t/L_z)))
    with k_t the day of the zone's market cycle. Harmonic coefficients are
    partially pooled across all six zones (one shared hierarchy: with only
    1-2 zones per cycle length, per-length group variances are unidentified
    funnels — verified empirically, R-hat > 2.9; a single hierarchy mixes).

    Priors: a_z ~ N(log base_z, 0.5); b_z ~ N(mu_b, sigma),
    c_z ~ N(mu_c, sigma); mu_b, mu_c ~ N(0, 0.3); log sigma ~ N(-1, 0.5).
    NOTE (documented): for 7-day zones the market cycle and the Gregorian
    weekly seasonality share period 7 and partially alias — the zone curve
    is the honest combined rhythm there.
    """
    import torch
    Z = len(ZONES)
    dim = 3 + 3 * Z          # mu_b, mu_c, log_sigma + (a, b, c) x Z
    y = torch.as_tensor(data["y_vol"].astype(np.float64))     # (Z, DAYS)
    L_z = np.array([MARKET_CYCLE[z]["days"] for z in ZONES], dtype=np.float64)
    k = (data["cycle_day"] % L_z[:, None]).astype(np.float64)  # (Z, DAYS)
    cosk = torch.as_tensor(np.cos(2 * np.pi * k / L_z[:, None]))
    sink = torch.as_tensor(np.sin(2 * np.pi * k / L_z[:, None]))
    a0 = torch.as_tensor(np.log(data["base_daily"]))

    def logpost_torch(par):
        mu_b, mu_c, log_sig = par[0], par[1], par[2]
        abc = par[3:].reshape(Z, 3)
        a, b, c = abc[:, 0], abc[:, 1], abc[:, 2]
        eta = a[:, None] + b[:, None] * cosk + c[:, None] * sink
        ll = torch.sum(y * eta - torch.exp(eta))
        sig = torch.exp(log_sig)
        lp_h = (-0.5 * torch.sum((b - mu_b) ** 2) / sig ** 2
                - 0.5 * torch.sum((c - mu_c) ** 2) / sig ** 2
                - 2 * Z * log_sig)
        lp = (-0.5 * torch.sum(((a - a0) / 0.5) ** 2)
              - 0.5 * (mu_b / 0.3) ** 2 - 0.5 * (mu_c / 0.3) ** 2
              - 0.5 * ((log_sig + 1.0) / 0.5) ** 2)
        return ll + lp_h + lp

    x0 = np.concatenate([[0.2, 0.0, -1.0],
                         np.column_stack([np.log(data["base_daily"]),
                                          np.full(Z, 0.2), np.zeros(Z)]).ravel()])
    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    summ = mcmc.summarize(res["samples_white"])
    flat = res["samples"].reshape(-1, dim)
    abc = flat[:, 3:].reshape(-1, Z, 3)
    # posterior uplift curve per zone over its cycle days
    curves = {}
    for zi, z in enumerate(ZONES):
        L = MARKET_CYCLE[z]["days"]
        kk = np.arange(L)
        cosv, sinv = np.cos(2 * np.pi * kk / L), np.sin(2 * np.pi * kk / L)
        u = np.exp(abc[:, zi, 1][:, None] * cosv[None, :]
                   + abc[:, zi, 2][:, None] * sinv[None, :])   # (draws, L)
        lo, hi = mcmc.credible_interval(u.reshape(len(u), L))
        curves[z] = {"cycle_days": L, "day_names": MARKET_CYCLE[z]["names"],
                     "uplift_mean": [float(v) for v in u.mean(axis=0)],
                     "ci95_lo": [float(v) for v in lo],
                     "ci95_hi": [float(v) for v in hi],
                     "draws": u}
    names = (["mu_b", "mu_c", "log_sigma"]
             + [f"{p}[{z}]" for z in ZONES for p in ("a", "b", "c")])
    return {"res": res, "summ": summ, "flat": flat, "curves": curves,
            "names": names, "fit_seconds": fit_s}


# ---------------------------------------------------------------------------
# Model 2: cultural calendar uplift, hierarchical across zones
# ---------------------------------------------------------------------------
def fit_calendar_model(data: dict, market: dict, n_samples: int = 800,
                       burn: int = 800, n_chains: int = 4, seed: int = 42) -> dict:
    """Two-stage honest design (documented): the market-cycle posterior mean
    is plugged in as a divisor, then per event e x zone z the observed
    window-vs-baseline log volume ratio
        r_ez ~ N(u_ez, s_ez)     (s_ez: day-level residual dispersion after
                                  dow-profile decomposition + market plug-in
                                  uncertainty propagation)
        u_ez ~ N(mu_e + offset_ez, tau_e)   partial pooling across zones
        mu_e ~ N(0.3, 0.4),  log tau_e ~ N(-1, 0.5)
    ``offset_ez`` are the DOCUMENTED zone-composition prior assumptions
    (EVENT_ZONE_PRIOR_OFFSET). Market plug-in uncertainty IS propagated
    (r_ez recomputed over market posterior draws; across-draw variance
    added to the observation noise).
    """
    import torch
    Z, E = len(ZONES), len(EVENT_IDS)
    y = data["y_vol"].astype(np.float64)
    # market-corrected volumes (per-zone cycle day -> posterior-mean uplift)
    mcorr = np.ones_like(y)
    for zi, z in enumerate(ZONES):
        L = MARKET_CYCLE[z]["days"]
        curve_mean = market["curves"][z]["draws"].mean(axis=0)   # (L,)
        mcorr[zi] = curve_mean[data["cycle_day"] % L]
    any_event = np.zeros(DAYS, dtype=bool)
    for eid in EVENT_IDS:
        any_event |= data["event_masks"][eid]
    base_mask = ~any_event

    # Honest observation model, three components (all documented):
    #  (a) DAY-OF-WEEK DECOMPOSITION: event windows sample specific weekdays
    #      (e.g. Christmas 2026 = Thu–Sat) while the weekly seasonality is
    #      only absorbed by the market model in 7-day zones — without this
    #      correction r_ez is biased by up to ~±8% log (verified: truth-in-
    #      CI95 collapsed to ~2-23%). The dow profile is estimated on
    #      baseline days and subtracted.
    #  (b) day-level residuals of corrected log volume on baseline days
    #      (Poisson noise + remaining unmodelled structure);
    #  (c) PLUG-IN UNCERTAINTY PROPAGATION: r_ez recomputed over market
    #      posterior draws; across-draw variance added.
    log_y = np.log(np.maximum(y, 1.0))
    dow_arr = data["dow"]

    def _ratios(mcorr_: np.ndarray) -> np.ndarray:
        log_yc = log_y - np.log(mcorr_)
        # dow profile from baseline days (per zone), centred
        prof = np.zeros((Z, 7))
        for zi in range(Z):
            for d in range(7):
                sel = base_mask & (dow_arr == d)
                if sel.any():
                    prof[zi, d] = log_yc[zi, sel].mean()
            prof[zi] -= log_yc[zi, base_mask].mean()
        adj = log_yc - prof[:, dow_arr]
        out = np.empty((E, Z))
        for ei, eid in enumerate(EVENT_IDS):
            m = data["event_masks"][eid]
            for zi in range(Z):
                out[ei, zi] = adj[zi, m].mean() - adj[zi, base_mask].mean()
        return out

    base_adj_var = np.empty(Z)
    _mc = np.log(mcorr)
    _prof = np.zeros((Z, 7))
    for zi in range(Z):
        for d in range(7):
            sel = base_mask & (dow_arr == d)
            if sel.any():
                _prof[zi, d] = (log_y[zi] - _mc[zi])[sel].mean()
        _prof[zi] -= (log_y[zi] - _mc[zi])[base_mask].mean()
    base_adj = (log_y - _mc) - _prof[:, dow_arr]
    for zi in range(Z):
        base_adj_var[zi] = float(np.var(base_adj[zi, base_mask], ddof=1))
    nb = int(base_mask.sum())

    # market-curve posterior draws per zone-day (subsampled)
    rng = np.random.default_rng(seed + 7)
    n_sub = 40
    mcorr_draws = np.empty((n_sub, Z, DAYS))
    for zi, z in enumerate(ZONES):
        L = MARKET_CYCLE[z]["days"]
        d = market["curves"][z]["draws"]
        sub = d[rng.integers(0, len(d), n_sub)]               # (n_sub, L)
        day_idx = data["cycle_day"] % L
        mcorr_draws[:, zi, :] = sub[:, day_idx]
    r_draws = np.stack([_ratios(mcorr_draws[j]) for j in range(n_sub)])
    plug_var = r_draws.var(axis=0, ddof=1)                    # (E, Z)

    r = _ratios(mcorr)
    s = np.empty((E, Z))
    for ei, eid in enumerate(EVENT_IDS):
        nw = int(data["event_masks"][eid].sum())
        for zi in range(Z):
            s[ei, zi] = np.sqrt(base_adj_var[zi] * (1.0 / nw + 1.0 / nb)
                                + plug_var[ei, zi])
    off = np.array([[EVENT_ZONE_PRIOR_OFFSET[eid].get(z, 0.0) for z in ZONES]
                    for eid in EVENT_IDS])
    dim = E + E + E * Z                          # mu_e, log_tau_e, u_ez
    r_t = torch.as_tensor(r)
    s_t = torch.as_tensor(s)
    off_t = torch.as_tensor(off)

    def logpost_torch(par):
        mu, log_tau = par[:E], par[E:2 * E]
        u = par[2 * E:].reshape(E, Z)
        tau = torch.exp(log_tau)[:, None]
        ll = -0.5 * torch.sum(((r_t - u) / s_t) ** 2)
        lp_h = (-0.5 * torch.sum(((u - mu[:, None] - off_t) / tau) ** 2)
                - Z * torch.sum(log_tau))
        lp = (-0.5 * torch.sum(((mu - 0.3) / 0.4) ** 2)
              - 0.5 * torch.sum(((log_tau + 1.0) / 0.5) ** 2))
        return ll + lp_h + lp

    x0 = np.concatenate([np.full(E, 0.3), np.full(E, -1.0), r.reshape(-1)])
    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    summ = mcmc.summarize(res["samples_white"])
    flat = res["samples"].reshape(-1, dim)
    u_post = flat[:, 2 * E:].reshape(-1, E, Z)       # log-uplift draws
    names = ([f"mu_event[{e}]" for e in EVENT_IDS]
             + [f"log_tau[{e}]" for e in EVENT_IDS]
             + [f"u[{e}:{z}]" for e in EVENT_IDS for z in ZONES])
    return {"res": res, "summ": summ, "flat": flat, "u_post": u_post,
            "r_obs": r, "s_obs": s, "names": names, "fit_seconds": fit_s}


# ---------------------------------------------------------------------------
# Model 4: religious giving rhythm (weekly harmonic, hierarchical by zone)
# ---------------------------------------------------------------------------
def fit_giving_model(data: dict, n_samples: int = 800, burn: int = 800,
                     n_chains: int = 4, seed: int = 42) -> dict:
    """g_zt ~ Poisson(exp(d_z[dow_t])): SATURATED day-of-week rhythm model
    with partial pooling, d_zw ~ N(mu_w, sigma), mu_w ~ N(0, 0.7),
    log sigma ~ N(-1, 0.5).

    Why saturated rather than harmonic (documented deviation from a pure
    "weekly harmonic" fit): a Friday+Sunday double peak with a Saturday
    lull (north_central's mixed rhythm) is not representable by one or two
    weekly cosines — verified empirically, the harmonic fit flattens the
    mixed zone toward the pooled mean (Fri/Sun ~1.19 vs true ~1.5). The
    saturated model represents any weekly rhythm exactly and still pools
    strength across zones. Zone-level aggregate only — no individual
    religious attribute exists.
    """
    import torch
    Z = len(ZONES)
    dim = 7 + 1 + 7 * Z        # mu_w (7), log_sigma, d_zw (Z x 7)
    y = torch.as_tensor(data["y_give"].astype(np.float64))
    dow = torch.as_tensor(data["dow"].astype(np.int64))       # (DAYS,)

    def logpost_torch(par):
        mu, log_sig = par[:7], par[7]
        d = par[8:].reshape(Z, 7)
        eta = d[:, dow]                                       # (Z, DAYS)
        ll = torch.sum(y * eta - torch.exp(eta))
        sig = torch.exp(log_sig)
        lp_h = -0.5 * torch.sum(((d - mu[None, :]) / sig) ** 2) - 7 * Z * log_sig
        lp = (-0.5 * torch.sum((mu / 0.7) ** 2)
              - 0.5 * ((log_sig + 1.0) / 0.5) ** 2)
        return ll + lp_h + lp

    dow_cnt = np.bincount(data["dow"], minlength=7)
    x0_d = np.log(np.stack([
        np.bincount(data["dow"], weights=data["y_give"][zi], minlength=7)
        / dow_cnt for zi in range(Z)]))
    x0 = np.concatenate([np.zeros(7), [-1.0], x0_d.ravel()])
    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    summ = mcmc.summarize(res["samples_white"])
    flat = res["samples"].reshape(-1, dim)
    d_post = flat[:, 8:].reshape(-1, Z, 7)
    curves = {}
    day_names = ["monday", "tuesday", "wednesday", "thursday", "friday",
                 "saturday", "sunday"]
    for zi, z in enumerate(ZONES):
        u = np.exp(d_post[:, zi, :])
        # express as uplift relative to the zone's own geometric-mean day
        u = u / np.exp(d_post[:, zi, :].mean(axis=1, keepdims=True))
        lo, hi = mcmc.credible_interval(u.reshape(len(u), 7))
        peak = int(np.argmax(u.mean(axis=0)))
        curves[z] = {"day_names": day_names,
                     "uplift_mean": [float(v) for v in u.mean(axis=0)],
                     "ci95_lo": [float(v) for v in lo],
                     "ci95_hi": [float(v) for v in hi],
                     "peak_day": day_names[peak], "draws": u}
    names = ([f"mu_dow[{d}]" for d in day_names] + ["log_sigma"]
             + [f"d[{z}:{d}]" for z in ZONES for d in day_names])
    return {"res": res, "summ": summ, "flat": flat, "curves": curves,
            "names": names, "fit_seconds": fit_s}


# ---------------------------------------------------------------------------
# Model 5: affinity-fraud base rates (per-zone partial pooling per typology)
# ---------------------------------------------------------------------------
def fit_affinity_model(data: dict, n_samples: int = 800, burn: int = 800,
                       n_chains: int = 4, seed: int = 42) -> dict:
    """y_zk ~ Binomial(n_z, theta_zk); logit(theta_zk) = l_zk ~ N(mu_k, sigma_k)
    — centered logit-normal partial pooling per culturally-specific typology.
    Priors: mu_k ~ N(logit(0.08), 1.0), log sigma_k ~ N(-0.5, 0.75).
    """
    import torch
    Z, K = len(ZONES), len(CULTURAL_FRAUD_TYPOLOGIES)
    dim = 2 * K + Z * K
    y = torch.as_tensor(data["y_aff"].astype(np.float64))     # (Z, K)
    n = torch.as_tensor(np.repeat(data["n_aff"], K).reshape(Z, K).astype(np.float64))

    def logpost_torch(par):
        mu, log_sig = par[:K], par[K:2 * K]
        l = par[2 * K:].reshape(Z, K)
        theta = torch.sigmoid(l)
        ll = torch.sum(y * torch.log(theta) + (n - y) * torch.log1p(-theta))
        sig = torch.exp(log_sig)
        lp_h = -0.5 * torch.sum(((l - mu[None, :]) / sig[None, :]) ** 2) \
            - Z * torch.sum(log_sig)
        lp = (-0.5 * torch.sum(((mu - _logit(0.08)) / 1.0) ** 2)
              - 0.5 * torch.sum(((log_sig + 0.5) / 0.75) ** 2))
        return ll + lp_h + lp

    raw = np.clip(data["y_aff"] / np.maximum(data["n_aff"][:, None], 1),
                  1e-6, 1 - 1e-6)
    x0 = np.concatenate([_logit(raw.mean(axis=0)), np.full(K, -0.3),
                         _logit(raw).reshape(-1)])
    t0 = time.time()
    res = _fit_whitened(logpost_torch, x0, n_samples=n_samples,
                        n_chains=n_chains, burn=burn, seed=seed)
    fit_s = time.time() - t0
    summ = mcmc.summarize(res["samples_white"])
    flat = res["samples"].reshape(-1, dim)
    theta_post = _sigmoid(flat[:, 2 * K:].reshape(-1, Z, K))
    names = ([f"mu[{k}]" for k in CULTURAL_FRAUD_TYPOLOGIES]
             + [f"log_sigma[{k}]" for k in CULTURAL_FRAUD_TYPOLOGIES]
             + [f"logit_theta[{z}:{k}]" for z in ZONES for k in CULTURAL_FRAUD_TYPOLOGIES])
    return {"res": res, "summ": summ, "flat": flat, "theta_post": theta_post,
            "names": names, "fit_seconds": fit_s}


# ---------------------------------------------------------------------------
# Serving summaries
# ---------------------------------------------------------------------------
def _ci(x, prob=0.95):
    lo = np.quantile(x, (1 - prob) / 2, axis=0)
    hi = np.quantile(x, 1 - (1 - prob) / 2, axis=0)
    return lo, hi


def build_summaries(data: dict, ajo: dict, cal: dict, mkt: dict,
                    giv: dict, aff: dict) -> dict:
    events = []
    u = cal["u_post"]                                # (draws, E, Z)
    for ei, e in enumerate(CULTURAL_EVENTS_2026):
        zone_uplift = {}
        for zi, z in enumerate(ZONES):
            mult = np.exp(u[:, ei, zi])
            lo, hi = _ci(mult)
            zone_uplift[z] = {"uplift_mean": float(mult.mean()),
                              "ci95": [float(lo), float(hi)]}
        nat = np.exp(u[:, ei, :].mean(axis=1))
        lo, hi = _ci(nat)
        events.append({**{k: e[k] for k in ("id", "name", "start", "end",
                                            "lunar_approx")},
                       "zone_uplift": zone_uplift,
                       "national": {"uplift_mean": float(nat.mean()),
                                    "ci95": [float(lo), float(hi)]}})

    coef_rows = []
    for j, name in enumerate(ajo["names"]):
        lo, hi = _ci(ajo["flat"][:, j])
        coef_rows.append({"name": name, "posterior_mean": float(ajo["flat"][:, j].mean()),
                          "ci95": [float(lo), float(hi)]})

    market_cycles = {}
    for z in ZONES:
        c = dict(mkt["curves"][z])
        c.pop("draws")
        market_cycles[z] = c
    giving = {}
    for z in ZONES:
        c = dict(giv["curves"][z])
        c.pop("draws")
        giving[z] = c

    affinity = {}
    for zi, z in enumerate(ZONES):
        affinity[z] = {}
        for ki, k in enumerate(CULTURAL_FRAUD_TYPOLOGIES):
            tp = aff["theta_post"][:, zi, ki]
            lo, hi = _ci(tp)
            affinity[z][k] = {"posterior_mean": float(tp.mean()),
                              "ci95": [float(lo), float(hi)],
                              "n_fraud_observed": int(data["n_aff"][zi]),
                              "count_observed": int(data["y_aff"][zi, ki])}

    return {
        "provenance": "synthetic (seeded generator; no real transaction feeds)",
        "reference_year": data["year"], "seed": data["seed"],
        "ethics": ("pattern-level features only; no per-individual "
                   "ethnicity/religion/tribe/language attributes anywhere; "
                   "zone-level aggregate priors only"),
        "events": events,
        "ajo": {
            "features": AJO_FEATURES,
            "coefficients": coef_rows,
            "uncertain_rule": ("assessment='uncertain' when the 95% credible "
                               "interval of P(legitimate) straddles 0.5"),
            "test_auc": ajo["test"]["auc"],
            "test_accuracy_at_0.5": ajo["test"]["accuracy"],
            "test_n": int(len(ajo["test"]["y"])),
        },
        "market_cycles": market_cycles,
        "giving_rhythm": giving,
        "affinity_typologies": CULTURAL_FRAUD_TYPOLOGIES,
        "affinity_base_rates": affinity,
    }


# ---------------------------------------------------------------------------
# Orchestration: fit all five models, ship artifacts
# ---------------------------------------------------------------------------
def fit_all(version: str = "v1", seed: int = 42, quick: bool = False,
            out_dir: Path | None = None, data: dict | None = None) -> dict:
    set_seed(seed)
    data = data or synth_cultural(seed)
    if quick:  # CI/test mode: thin chains, still honest diagnostics
        kw = dict(n_samples=300, burn=300, n_chains=3, seed=seed)
    else:
        kw = dict(n_samples=1000, burn=1000, n_chains=4, seed=seed)

    t_start = time.time()

    def _fit_checked(name, fn, *args, **kw):
        """Fit with honest convergence enforcement: if max R-hat >= 1.2,
        double the warmup and refit (up to 2 retries). Diagnostics are
        reported regardless — never hidden."""
        burn = kw["burn"]
        fit = fn(*args, **{**kw, "burn": burn})
        for _ in range(2):
            rhat = float(np.nanmax(fit["summ"]["rhat"]))
            if rhat < 1.2:
                break
            burn *= 2
            print(f"[cultural] {name} max R-hat {rhat:.2f} — "
                  f"refit with burn={burn}")
            fit = fn(*args, **{**kw, "burn": burn})
        return fit

    # ajo logistic needs burn >= ~600 to mix (see fit_ajo_model docstring)
    ajo = _fit_checked("ajo", fit_ajo_model, data["ajo"],
                       **{**kw, "burn": kw["burn"] + 300})
    # market hierarchy hyperparameters (mu_b/mu_c/log_sigma) need warmup
    # too (verified: burn=300 -> max R-hat 2.4; burn=800 -> ~1.01)
    mkt = _fit_checked("market", fit_market_model, data,
                       **{**kw, "burn": kw["burn"] + 500, "seed": seed + 11})
    cal = _fit_checked("calendar", fit_calendar_model, data, mkt,
                       **{**kw, "seed": seed + 23})
    giv = _fit_checked("giving", fit_giving_model, data,
                       **{**kw, "seed": seed + 37})
    # affinity hierarchy needs a much longer warmup (weakly-identified
    # sigma_k with only 6 zones per typology — verified empirically)
    aff = _fit_checked("affinity", fit_affinity_model, data,
                       **{**kw, "burn": kw["burn"] + 1200, "seed": seed + 53})
    total_s = time.time() - t_start

    summaries = build_summaries(data, ajo, cal, mkt, giv, aff)

    def diag(fit):
        return {
            "rhat_max": float(np.nanmax(fit["summ"]["rhat"])),
            "ess_min": float(np.min(fit["summ"]["ess"])),
            "rhat": [float(v) for v in fit["summ"]["rhat"]],
            "ess": [float(v) for v in fit["summ"]["ess"]],
            "fit_seconds": round(fit["fit_seconds"], 1),
        }

    # truth-recovery check vs the ABSORBED-OVERLAP expectation: under
    # exclusive masks the fitted uplift targets the mean TOTAL uplift over
    # the assigned days (e.g. New Year includes the salary-week component
    # of Jan 1-2), not the bare event truth.
    E, Z = len(EVENT_IDS), len(ZONES)
    u_post = cal["u_post"]
    tot = data["total_event_uplift_true"]
    rec = {}
    for ei, eid in enumerate(EVENT_IDS):
        m = data["event_masks"][eid]
        for zi, z in enumerate(ZONES):
            lo, hi = _ci(u_post[:, ei, zi])
            expected = float(tot[zi, m].mean()) if m.any() else 0.0
            rec[f"{eid}:{z}"] = bool(lo <= expected <= hi)
    calib = float(np.mean(list(rec.values())))

    metrics = {
        "model": MODEL_NAME, "version": version,
        "data": (f"synthetic seeded cultural generator (seed={data['seed']}, "
                 f"reference year {data['year']}, 6 zones, 365 days, "
                 f"{len(data['ajo']['y'])} ajo/fraud group summaries)"),
        "seed": seed, "quick_mode": quick,
        "sampler": "nuts_lite (Laplace-whitened where dim>=12)",
        "n_chains": kw["n_chains"], "n_samples_per_chain": kw["n_samples"],
        "burn": kw["burn"], "total_fit_seconds": round(total_s, 1),
        "ajo_model": {**diag(ajo),
                      "test_auc": ajo["test"]["auc"],
                      "test_accuracy_at_0.5": ajo["test"]["accuracy"],
                      "test_n": int(len(ajo["test"]["y"])),
                      "accept_rate": [float(v) for v in ajo["res"]["accept_rate"]]},
        "market_model": diag(mkt),
        "calendar_model": {**diag(cal),
                           "truth_in_ci95_share": calib},
        "giving_model": diag(giv),
        "affinity_model": diag(aff),
        "christmas_national_uplift":
            summaries["events"][EVENT_IDS.index("christmas")]["national"],
        "ethics_guardrail": summaries["ethics"],
    }
    print(json.dumps({k: v for k, v in metrics.items()
                      if not k.endswith("_model")}, indent=2))

    out_dir = Path(out_dir or ARTIFACT_ROOT / MODEL_NAME / version)
    out_dir.mkdir(parents=True, exist_ok=True)
    mcmc.save_posterior(out_dir / "ajo_posterior.npz", ajo["res"]["samples"],
                        ajo["names"],
                        meta={"model": MODEL_NAME, "submodel": "ajo_logistic",
                              "features": AJO_FEATURES, "priors": "beta ~ N(0, 2^2)",
                              "provenance": "synthetic", "seed": seed})
    mcmc.save_posterior(out_dir / "calendar_posterior.npz", cal["res"]["samples"],
                        cal["names"],
                        meta={"model": MODEL_NAME, "submodel": "calendar_uplift",
                              "events": EVENT_IDS, "zones": ZONES,
                              "note": ("two-stage: fit AFTER the market model "
                                       "with market-corrected volumes; plug-in "
                                       "uncertainty propagated by recomputing "
                                       "window ratios over market posterior draws"),
                              "seed": seed})
    mcmc.save_posterior(out_dir / "market_posterior.npz", mkt["res"]["samples"],
                        mkt["names"],
                        meta={"model": MODEL_NAME, "submodel": "market_week_harmonic",
                              "cycles": {z: MARKET_CYCLE[z]["days"] for z in ZONES},
                              "seed": seed})
    mcmc.save_posterior(out_dir / "giving_posterior.npz", giv["res"]["samples"],
                        giv["names"],
                        meta={"model": MODEL_NAME, "submodel": "giving_weekly_harmonic",
                              "seed": seed})
    mcmc.save_posterior(out_dir / "affinity_posterior.npz", aff["res"]["samples"],
                        aff["names"],
                        meta={"model": MODEL_NAME, "submodel": "affinity_base_rates",
                              "typologies": CULTURAL_FRAUD_TYPOLOGIES, "zones": ZONES,
                              "seed": seed})

    # compact serving draws (derived quantities, unit-friendly for the API)
    maxL = max(MARKET_CYCLE[z]["days"] for z in ZONES)
    n_draws = min(cal["u_post"].shape[0],
                  min(mkt["curves"][z]["draws"].shape[0] for z in ZONES),
                  min(giv["curves"][z]["draws"].shape[0] for z in ZONES))
    event_uplift = np.exp(cal["u_post"][:n_draws])               # (n, E, Z)
    market_uplift = np.full((n_draws, Z, maxL), np.nan)
    giving_uplift = np.empty((n_draws, Z, 7))
    for zi, z in enumerate(ZONES):
        d = mkt["curves"][z]["draws"][:n_draws]
        market_uplift[:, zi, :d.shape[1]] = d
        giving_uplift[:, zi, :] = giv["curves"][z]["draws"][:n_draws]
    np.savez_compressed(
        out_dir / "serving.npz",
        event_uplift_draws=event_uplift,
        market_uplift_draws=market_uplift,
        giving_uplift_draws=giving_uplift,
        ajo_beta_draws=ajo["flat"][:n_draws],
        ajo_feature_mu=ajo["feature_mu"], ajo_feature_sd=ajo["feature_sd"],
        event_ids=np.array(EVENT_IDS), zones=np.array(ZONES),
        meta_json=np.array(json.dumps({
            "model": MODEL_NAME, "version": version,
            "note": "derived posterior draws for serving; independence across "
                    "sub-models assumed when multiplying components"})))
    (out_dir / "summaries.json").write_text(json.dumps(summaries, indent=2))
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (out_dir / "MODEL_CARD.md").write_text(_model_card(version, metrics, summaries))
    print(f"saved -> {out_dir} (total fit {total_s:.1f}s)")
    return metrics


def _model_card(version: str, m: dict, s: dict) -> str:
    diag_rows = "\n".join(
        f"| {name} | {m[name]['rhat_max']:.4f} | {m[name]['ess_min']:.0f} | "
        f"{m[name]['fit_seconds']:.0f}s |"
        for name in ("ajo_model", "calendar_model", "market_model",
                     "giving_model", "affinity_model"))
    ev_rows = "\n".join(
        f"| {e['name']} | {e['start'] or 'monthly'} → {e['end'] or ''} | "
        f"{'yes (approx)' if e['lunar_approx'] else 'no'} | "
        f"{e['national']['uplift_mean']:.2f}× | "
        f"[{e['national']['ci95'][0]:.2f}, {e['national']['ci95'][1]:.2f}] |"
        for e in s["events"])
    coef_rows = "\n".join(
        f"| {c['name']} | {c['posterior_mean']:+.2f} | "
        f"[{c['ci95'][0]:+.2f}, {c['ci95'][1]:+.2f}] |"
        for c in s["ajo"]["coefficients"])
    return f"""# Model Card: cultural_intelligence ({version})

MCMC posteriors over Nigeria's culturally-patterned legitimate financial
rhythms — ajo/esusu rotating savings, festive spending calendar, market-week
cycles, weekly religious-giving rhythm — plus per-zone base rates of
culturally-specific fraud typologies. Purpose: stop false-flagging communal
finance as structuring, and stop missing fraud hidden inside cultural
patterns. Companion to `national_intelligence`.

- **Data**: {m['data']} — provenance: **synthetic** (no real feeds).
- **Inference**: {m['sampler']}, {m['n_chains']} chains x
  {m['n_samples_per_chain']} kept samples per model. Total fit {m['total_fit_seconds']:.0f}s.
- **Ethics guardrail**: {s['ethics']}. Enforced by a meta-test
  (`test_no_sensitive_attributes_anywhere`) that scans every feature schema
  in this pipeline for religion/ethnicity/tribe/language terms.

## Convergence diagnostics

| Sub-model | max R-hat | min ESS | fit time |
|---|---|---|---|
{diag_rows}

## Ajo/esusu legitimacy posterior

Held-out discrimination (synthetic): **AUC {s['ajo']['test_auc']:.3f}**
(n={s['ajo']['test_n']}; legit rotating clubs vs fake-ajo ponzi rings and
structuring rings). Assessment is three-way: `likely_legitimate_ajo` /
`likely_fraud` / **`uncertain`** — the uncertain zone is explicit (95% CI
straddling 0.5), never forced into a binary call.

| Coefficient | Posterior mean | 95% CI |
|---|---|---|
{coef_rows}

## Cultural calendar uplift (national posterior)

| Event | 2026 window | Lunar approx | Uplift mean | 95% CI |
|---|---|---|---|---|
{ev_rows}

## Market-week cycles

Per-zone cyclic harmonic posteriors: South East / South South 4-day
(Eke/Orie/Afo/Nkwo), South West 5-day, northern zones 7-day. NOTE: for
7-day zones the market rhythm and Gregorian weekly seasonality share
period 7 and partially alias — the served curve is the honest combined
rhythm.

## Limitations

- Trained on synthetic data with documented assumptions; absolute levels
  are NOT measured Nigerian cultural patterns until real feeds land.
- Calendar model is two-stage (fit after the market model on
  market-corrected volumes); the market plug-in's uncertainty is propagated
  by recomputing window ratios over market posterior draws, and residual
  day-level dispersion (incl. unmodelled weekly seasonality) enters the
  observation noise. Residual *bias* of the market fit is not fully
  captured — treat intervals as honest-but-not-conservative.
- Lunar dates (Eid al-Fitr ~2026-03-20, Eid al-Adha ~2026-05-27) are
  approximations, flagged `lunar_approx`; re-seed when official dates are
  announced.
- Culture varies WITHIN zones; intervals carry that uncertainty honestly —
  a wide interval is a statement of ignorance, not of uniformity.
- Statistical descriptions of aggregates must never be read as judgments
  of groups or applied to individuals (stereotype risk; see
  docs/CULTURAL_INTELLIGENCE.md).
"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--quick", action="store_true",
                    help="thin chains for CI smoke runs")
    a = ap.parse_args()
    fit_all(version=a.version, seed=a.seed, quick=a.quick)
