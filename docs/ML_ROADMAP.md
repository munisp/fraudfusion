# Rule → ML Migration Roadmap (Go detectors)

**Why this document exists.** Round-3 audit finding: "the six rule-only Go
detectors have **no migration roadmap anywhere** — no shared `mlclient`, no
`docs/ML_ROADMAP.md`, zero roadmap hooks." This file is that roadmap. It does
not claim ML is always better — it defines the honest graduation path from
transparent rules to measured models, with the gates a challenger must pass
before it replaces a rule.

**Status key:** ✅ shipped · 🔄 in progress · ⬜ planned

---

## 1. Current rule inventories (ground truth at HEAD)

| Detector | Rules today (increments) | Persistence of decisions | Feature data available |
|---|---|---|---|
| advance-fee | 419/inheritance/lottery/business-proposal pattern packs, fee-request, urgency, `language_anomaly` heuristic (misspelling density / caps ratio / urgent-payment keywords), sender reputation, webmail corroboration | `advance_fee_messages` | labeled message rows |
| chargeback | history counts, high-value, cross-border, abuse-pattern thresholds (4) — window now unified at `HISTORY_WINDOW_DAYS=90` | `chargeback_*`, `chargeback_abuse_patterns` | dispute outcomes (ground truth on resolution) |
| crypto | wallet reputation (excluded-self median baseline, n≥5), amount, platform allowlist, P2P deviation, velocity, scam patterns | crypto tables | labeled scam-wallet outcomes |
| insider | after-hours (Africa/Lagos, weekend-aware), privileged-resource access, velocity, collusion (≥2 shared resources), exfiltration + Round-4 SoD/ghost-vendor/payroll/expense endpoints | insider tables | investigation outcomes |
| investment | returns>20%, pyramid structure, SEC registry (file-importable), promoter history, known-scam list | investment tables | scheme collapse outcomes |
| sim-swap | swap-recency × login correlation, new-device, fail-closed on telco outage | sim-swap tables | confirmed takeover outcomes |

## 2. Shared serving path (the missing `mlclient` — now exists)

`services/go/authcommon/` holds the consolidated auth stack; ML serving reuses
the pattern established by `aml-monitor/services/go/.../mlclient` (circuit
breaker from `authcommon/breaker.go`, model-router on **:8200** as default,
`model_mode` honesty label in every response: `onnx` | `rule_fallback`).

Every graduated detector MUST:
1. call the **model router** (:8200), never a model service directly;
2. keep its rule engine as the **loud fallback** (never silent);
3. emit `model_mode` + model version in every response;
4. log features + decision to its pattern/decision table (training data).

## 3. Target models and feature contracts

| Detector | Phase-1 model | Phase-2 model | Feature contract source | Training labels |
|---|---|---|---|---|
| advance-fee | logistic/GBDT on message features | small transformer embedding + GBDT | message feature extractor (to be pinned in `ml/features/`) | `advance_fee_messages.outcome` |
| chargeback | GBDT on 90-day window features | sequence model over dispute history | chargeback feature view | dispute win/loss + friendly-fraud labels |
| crypto | GBDT on wallet/velocity features | graph model (wallet cluster GNN) | crypto feature view | confirmed scam wallets |
| insider | hierarchical Bayesian (shipped, `insider_risk/v1`) → calibrated GBDT | GNN collusion (gnn_mule pattern) | insider feature view | confirmed insider cases |
| investment | GBDT on scheme features | text+structure hybrid | investment feature view | collapsed-scheme outcomes |
| sim-swap | GBDT on swap/login correlation | sequence model over session events | sim-swap feature view | confirmed takeovers |

## 4. Graduation gates (per detector, no exceptions)

1. **Shadow mode** ≥ 2 weeks: model scores logged, rules still decide.
2. **Champion/challenger A/B** via model router: 5% → 50% traffic, two-proportion
   z-test on flag rate and fraud-capture recall (machinery exists in
   `mlops/serving/model_router.py` + `mlops/experiments/analyze.py`).
3. **Quality gates**: AUC-PR ≥ rule-engine simulated AUC-PR on the same replay
   window; precision at fixed alert volume ≥ rules; calibrated probabilities
   (ECE ≤ 0.05 after Bayesian calibration layer).
4. **Adversarial gate**: constrained PGD evasion rate no worse than the rule
   engine's blind spots (harness exists: `ml/adversarial/evasion_eval.py`).
5. **Rollback runbook** pre-written before 50% step (see `mlops/README.md`).

## 5. Phasing

| Phase | Scope | Status |
|---|---|---|
| 0 | fraud_net/credit/GNN/embedder + Bayesian calibration + router + drift monitors | ✅ shipped (Rounds 1–4) |
| 1 | aml + ATO + identity-theft hybrid (rules + model blend) | ✅ shipped |
| 2 | insider Bayesian + GNN collusion, chargeback GBDT shadow | 🔄 models exist (Bayesian); Go wiring planned |
| 3 | investment + sim-swap shadow | ⬜ |
| 4 | advance-fee + crypto shadow | ⬜ |
| 5 | any rule→model promotion that passes §4 gates | ⬜ gated |

## 6. Honest constraints

- All current models are trained on **synthetic Nigerian data**; no detector
  graduates past shadow mode until real labeled outcomes accumulate in its
  decision tables (that is what the tables are for).
- Rule engines are never deleted: they remain the fallback and the
  audit-explainable baseline (regulators can inspect a rule; a GBDT needs
  SHAP-style explanation — planned, not built).
