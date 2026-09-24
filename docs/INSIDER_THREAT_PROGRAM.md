# Insider Threat Program

This document is the process + technology answer to insider risk at
FraudFusion. **Every process control below is mapped to the code that
enforces it** (`file:line`), so the program is auditable end-to-end.

Scope: employees, contractors, and service principals with privileged access
to customer data, the ledger, the watchlist/SAR pipeline, and the ML scoring
stack. Nigerian regulatory context: CBN/NFIU reporting duties (MLPPA 2022),
EFCC escalation for criminal referral.

---

## 1. Prevention

### 1.1 Segregation of duties (SoD), enforced in code

SoD is not a policy PDF — it is enforced at the database layer, fail-closed:

| Control | Enforcement |
|---|---|
| Incompatible-duty matrix (create_user+approve_user, initiate_payment+approve_payment, modify_watchlist+file_sar, export_data+delete_audit, modify_payroll+approve_payroll, modify_ledger+reconcile_ledger, and more) | `database/20260828_insider_sod.sql:17` (`sod_matrix`, seeded idempotently) |
| Current duty holdings per subject | `database/20260828_insider_sod.sql:51` (`sod_assignments`) |
| Violation audit trail (open/acknowledged/exempted/resolved lifecycle, deduped per open pair) | `database/20260828_insider_sod.sql:72` (`sod_violations`) |
| Conflict evaluation function (tenant overrides shadow global rules) | `database/20260828_insider_sod.sql:100` (`sod_check_assignment`) |
| **Fail-closed DB trigger**: conflicting assignments are never created; the attempt is recorded and a WARNING raised | `database/20260828_insider_sod.sql:131` (`sod_enforce_assignment`), trigger at `database/20260828_insider_sod.sql:165` |
| API gate `POST /v1/insider/sod-check` (mode `check` evaluates, mode `grant` persists; grant requires `admin`/`sod_manager` role; deny returns 409) | `services/go/insider-fraud-detector/insider_sod.go:73` (`sodCheck`), role gate `insider_sod.go:603` (`hasAnyRole`) |
| Grant re-verified against concurrent races (trigger RETURN NULL ⇒ rows-affected 0 ⇒ 409) | `services/go/insider-fraud-detector/insider_sod.go:108-129` |

### 1.2 Dual control (maker-checker) already in ledger/storage

| Control | Enforcement |
|---|---|
| Financial close requires request → review → approve with actor separation, ledger snapshot hash pinned at each transition | `services/go/ledger-command/financial_controls.go:431` (`moveCloseToReview`, requester-only), `financial_controls.go:466` (`approveClose`), event log `financial_controls.go:517` (`insertCloseEvent`) |
| Destructive storage operations require dual-control approval with a signed, single-use delete token (approver ≠ requester) | `implementations/storage/deletion_approval.py:39` (`DualControlViolation`), `deletion_approval.py:117` (`approve`, approver-must-differ check at 126-127), `deletion_approval.py:202` (`issue`) |
| Audit-log cleanup is dual-control gated | `implementations/security/audit/audit_logger.py:1011` (`cleanup_old_logs`, token check at ~1060) |

### 1.3 Least privilege

| Control | Enforcement |
|---|---|
| Token introspection on every insider-detector request; only configured roles pass | `services/go/insider-fraud-detector/main.go:420` (`authenticate`), role allow-list from `KEYCLOAK_REQUIRED_ROLES` (`main.go:446`) |
| Per-endpoint role gates from introspected claims (e.g. SoD grant = admin/sod_manager only) | `services/go/insider-fraud-detector/main.go:563` (`roleSet`), `insider_sod.go:603` (`hasAnyRole`) |
| Fine-grained relationship-based authorization (ReBAC) for resources | `orchestrator/go/internal/permify/client.go:117` (`CheckPermission`) |
| Tenant isolation on every endpoint (`X-Tenant-ID` must match body) | `services/go/insider-fraud-detector/main.go:634` (`tenantMatches`) |

### 1.4 Mandatory vacation + access-review campaigns

Privileged-duty holders must take an uninterrupted vacation block (access
suspended) and pass periodic access reviews — fraud that requires continuous
attendance (ghost vendors, skim schemes) surfaces while the insider is away.

| Control | Enforcement |
|---|---|
| Campaign tracking (type `mandatory_vacation` / `access_review`), days required/taken, access suspension flag, reviewer sign-off | `database/20260828_insider_sod.sql:202` (`access_review_campaigns`) |
| Compliance metric function | `database/20260828_insider_sod.sql:243` (`vacation_compliance_pct`) |

---

## 2. Detection

| Signal | Detection code |
|---|---|
| After-hours / high-velocity / privileged-resource access scoring | `services/go/insider-fraud-detector/main.go:136` (`monitorAccess`), `main.go:161` (`detectUnusualActivity`) |
| Data exfiltration (volume, external destination, repeat attempts) | `services/go/insider-fraud-detector/main.go:195` (`detectDataExfiltration`) |
| Authorization abuse on sensitive resources | `services/go/insider-fraud-detector/main.go:233` (`detectAuthorizationAbuse`) |
| Collusion via shared privileged resources (≥2 distinct resources = collusion, 1 = teamwork) | `services/go/insider-fraud-detector/main.go:299` (`detectCollusion`), decision at `main.go:287` (`collusionOutcome`) |
| **Collusion graph**: GNN mule-ring artifact scores (read-only probe of `ml/artifacts/gnn_mule/<version>`, optional `node_scores.csv`) combined with shared-resource signals; degrades gracefully when artifact absent | `services/go/insider-fraud-detector/insider_sod.go:299` (`collusionGraph`), probe at `insider_sod.go:213` (`probeGNNArtifact`), combination logic at `insider_sod.go:255` (`collusionGraphVerdict`) |
| GNN mule/collusion ring model (leakage-free, split-aware snapshots) | `ml/models/gnn_mule.py`, artifact + metrics at `ml/artifacts/gnn_mule/v2/metrics.json` |
| Ghost-vendor / ghost-employee overlap (shared bank account, device, address, tax ID; weighted score, alert ≥ 50) | `services/go/insider-fraud-detector/insider_sod.go:384` (`ghostVendor`), scoring at `insider_sod.go:358` (`ghostVendorScore`), persistence `database/20260828_insider_sod.sql:175` (`employee_vendor_overlap`) |
| Payroll padding (salary change > 15% [env `PAYROLL_PADDING_THRESHOLD_PCT`] without ≥ 2 distinct approver events; self-modification escalates) | `services/go/insider-fraud-detector/insider_sod.go:481` (`payrollPadding`), decision at `insider_sod.go:451` (`payrollPaddingOutcome`) |
| Expense-abuse velocity (claims/24h, amount/30d, duplicate merchant bursts, round amounts) | `services/go/insider-fraud-detector/insider_sod.go:546` (`expenseAbuse`), decision at `insider_sod.go:520` (`expenseAbuseOutcome`), feed table `database/20260828_insider_sod.sql:230` (`expense_claims`) |
| Bayesian insider-risk scoring: hierarchical logit-normal-binomial model of per-department insider-event rates with learned partial pooling (shrinks small-team rates toward the population mean); sampled with NUTS-lite, ships `posterior.npz` + `metrics.json` artifacts | `ml/bayesian/insider_risk.py:1-28` (model contract), `ml/bayesian/insider_risk.py:68` (`fit`), sampler `ml/bayesian/mcmc.py:117` (`nuts_lite`), artifacts at `ml/artifacts/insider_risk/v1/` |
| Tamper evidence: append-only audit log with HMAC-SHA256 keyed chaining and cross-segment seals | `implementations/security/audit/audit_logger.py:228` (`compute_hash`), `audit_logger.py:243` (`AuditLogger`), verification `audit_logger.py:712` (`verify_integrity`), `audit_logger.py:804` (`verify_chain`) |

All detection endpoints fail closed: storage errors return 500 and no
verdict (`internalError`, `services/go/insider-fraud-detector/main.go:705`),
and authenticated role gates deny by default.

---

## 3. Response

| Step | Enforcement |
|---|---|
| Case workflow / triage queue: insider alerts persisted with risk level; analysts pull the per-tenant queue | `services/go/insider-fraud-detector/main.go:327` (`getAlerts`), alert persistence `main.go:396` (`persistEventAndAlert`, threshold score ≥ 50) |
| SoD violation case lifecycle (open → acknowledged/exempted → resolved, with resolver and notes) | `database/20260828_insider_sod.sql:72` (`sod_violations.status`) |
| Ghost-vendor investigation states (open → investigating → confirmed_ghost/cleared) | `database/20260828_insider_sod.sql:175` (`employee_vendor_overlap.status`) |
| Evidence preservation under dual control: ledger snapshot hash pinned at close review/approve; reconciliation breaks retained | `services/go/ledger-command/financial_controls.go:388` (`ledgerSnapshotHash`), `financial_controls.go:244` (`insertReconciliationBreak`) |
| Regulator escalation: SAR generation + filing gate (only successful regulator receipt marks `filed`; 72h NFIU STR SLA tracked) | `services/go/aml-monitor/handlers/aml_handler.go:395` (`GenerateSAR`), `aml_handler.go:498` (`FileSAR`), SLA at `aml_handler.go:547` |
| EFCC criminal referral path | `services/go/aml-monitor/handlers/aml_handler.go:803-804` (`EFCC_ENDPOINT` / `EFCC_API_KEY`) |

---

## 4. Deterrence

| Control | Enforcement |
|---|---|
| Signed audit trail (HMAC-SHA256 keyed chain; key from `AUDIT_HMAC_KEY`/URI; fail-closed without key) | `implementations/security/audit/audit_logger.py:86` (`_load_hmac_key`), chain continuity `audit_logger.py:304` (`_restore_chain_state`) |
| Anti-wipe evidence vault: regulated tables are immutable — UPDATE/DELETE denied by trigger; soft-delete only | `database/20260825_antiwipe_soft_delete.sql:18` (immutable trigger function), `database/20260825_antiwipe_soft_delete.sql:22` (`antiwipe_attach_immutable`), `database/20260825_regulated_tables_immutable.sql` |
| Hard delete requires dual-control signed single-use tokens | `implementations/storage/deletion_approval.py:117`, `:202` |
| Every insider-detector alert records the acting principal (`actor_id`) in event metadata | `services/go/insider-fraud-detector/main.go:396-398` |

---

## 5. Metrics

| Metric | Source |
|---|---|
| **MTTD** (mean time to detect): `detected_at`/`created_at` of first alert vs. first anomalous event per employee | `insider_fraud_events.created_at` vs. `insider_fraud_alerts.created_at` (`database/20260827_service_base_tables.sql:138`, `:177`) |
| **SoD violation count** (open/denied attempts per tenant) | `sod_violations` (`database/20260828_insider_sod.sql:72`); denied attempts recorded by trigger (`:131`) and API (`insider_sod.go:159`) |
| **Vacation compliance %** | `vacation_compliance_pct(tenant)` (`database/20260828_insider_sod.sql:243`) |
| **Ghost-entity hit rate** (confirmed_ghost / cleared ratio) | `employee_vendor_overlap.status` (`database/20260828_insider_sod.sql:175`) |
| Access-review completion | `access_review_campaigns.status` (`database/20260828_insider_sod.sql:202`) |
| Audit-chain verification failures | `verify_chain` result (`implementations/security/audit/audit_logger.py:804`) |

---

## 6. Adversarial robustness of the detection stack (cross-reference)

Insiders who understand the ML scoring layer may try to evade it. The
evasion surface of `fraud_net` is quantified and defended in
`ml/adversarial/`:

- Evasion evaluation (FGSM/PGD with feature-space plausibility constraints;
  ART cross-check engine): `ml/adversarial/evasion_eval.py`, results in
  `ml/adversarial/reports/evasion_report.md`.
- Post-defense re-evaluation (clip/quantize, rule ensemble, smoothing-lite,
  adversarial-training note) and residual risk:
  `ml/adversarial/reports/defenses_report.md`.

Key finding: at eps=1.0 (one standard deviation per numeric feature), a
constrained PGD attack evades ~51–80% of fraud that clean scoring flags for
review — so **SoD, dual control, and the immutable audit trail (this
program) are the compensating controls when ML detection is degraded**, and
the non-differentiable rule ensemble exists precisely so that model evasion
does not imply program evasion.
