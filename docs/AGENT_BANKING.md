# Agent banking — stakeholder onboarding and operations

Operational guide for onboarding **agent-banking operators** (the CBN
agent-network stakeholder) onto FraudFusion. The endpoint surface is being
delivered by the services lane against the `agent_applications` table
(`database/20260901_python_services_caveats.sql`, §8); this document is the
operational contract those endpoints implement.

## Who agents are in the Nigerian ecosystem

Agent banking is the CBN-sanctioned channel in which a **principal** (a bank,
MFB, or licensed fintech/PSP such as the super-agent networks) deputizes
**agents** — corner shops, kiosks, petrol stations, market stalls — to perform
cash-in/cash-out, transfers, bill payments, BVN enrollment, and account
opening via POS terminals or mobile apps. Agents operate on a pre-funded
**float** account and earn commissions per transaction. In practice agents are
the last-mile cash interface for a large share of the underbanked population,
especially outside Lagos/Abuja/Port Harcourt.

Key actors:

- **Principal institution** — the licensed entity the agent represents;
  liable for the agent's conduct (`principal_fintech` / `principal_reference`
  on the application).
- **Agent operator** — the human/business being onboarded (identified by
  `agent_code` + BVN, captured by salted hash only — never plaintext).
- **FraudFusion tenant** — the principal's platform tenant that manages its
  agent network through this service.

## Why they were absent

FraudFusion's onboarding flows modeled tenants, merchants, and KYB businesses
but had no stakeholder record for agents: no agent identity (BVN-by-reference),
no principal linkage, no float-account capture, and no agent-tier risk
segmentation. That gap meant agent transactions scored by the fraud models had
no first-class subject to attach velocity, float, or geo signals to — the
synthetic training data already models agents (`ml/data/synthetic_nigeria.py`,
~1.5% of accounts), so scoring expected a population the platform could not
actually enroll.

## Onboarding flow (maps to the new endpoints)

All endpoints live under onboarding-service, `/api/v1/onboarding/agents/*`,
and follow the same dual-control pattern as KYB/merchant onboarding
(`docs/ONBOARDING.md`). State machine:
`submitted → screening → pending_approval → approved` (or `rejected`;
`approved → suspended` for post-approval action).

| Step | Operation | Endpoint | Notes |
|------|-----------|----------|-------|
| 1 | Submit agent application | `POST /api/v1/onboarding/agents` | Body: agent code, full name, principal fintech + reference, BVN (hashed at rest with per-agent salt; plaintext never persisted), float account (NUBAN + bank code), geo coordinates. Tenant-scoped; duplicate `agent_code` per tenant rejected (UNIQUE constraint). |
| 2 | Sanctions/watchlist screening | automatic on submit; `GET /api/v1/onboarding/agents/{id}` | `screening_status` moves `pending → clear | hit | unavailable`. A `hit` blocks approval. |
| 3 | Staff review | `POST /api/v1/onboarding/admin/agents/{id}/review` | Moves to `pending_approval`. Reviewer ≠ submitter. |
| 4 | Approve (dual control) | `POST /api/v1/onboarding/admin/agents/{id}/approve` | Approver must differ from both submitter and reviewer — enforced in the DB (`agent_applications_dual_control_guard`). |
| 5 | Reject | `POST /api/v1/onboarding/admin/agents/{id}/reject` | Reason required; lands in `rejection_reason`. |
| 6 | List/monitor | `GET /api/v1/onboarding/agents` | Keyset-paginated (`limit`/`cursor`, `next_cursor` in the response); scoped to the caller's tenant unless staff. |
| 7 | Suspend | `POST /api/v1/onboarding/admin/agents/{id}/suspend` | Post-approval risk action; suspension is the only way to stop an approved agent — rows are regulated evidence and cannot be deleted (DB trigger denies DELETE). |

Every transition writes an approval-events audit record, same as API-key and
merchant approvals, so regulator access (`/admin/regulator-access`) can
evidence who approved which agent and when.

## Float management notes

- The float account (`float_account_number` + `float_account_bank`) is the
  agent's pre-funded working-capital account at the principal. FraudFusion
  records it for monitoring; the principal remains responsible for funding,
  reconciliation, and settlement of that account.
- **Float exhaustion and unusual float top-ups are fraud signals.** Feed
  float balances into scoring context where available: agents running
  chronically near-zero float, or receiving large off-hours top-ups from
  unrelated accounts, match known cash-out / collusion patterns.
- **Geo-fencing:** the captured `latitude`/`longitude` is the agent's
  registered trading location. Transactions originating far from it (or
  "roaming" agents without a mobile-agent designation from the principal)
  should score as higher risk.
- **Tiering (`cbn_tier`):** align agent daily limits with the principal's
  mandate and the customer tiers they serve (`docs/KYC_TIERS.md`). Tier
  upgrades for agents follow the same evidence-based flow as customer tier
  upgrades.
- **Velocity:** per-agent velocity (transactions/hour, distinct customers/day)
  is the primary agent-level anomaly feature; shared-device and shared-float
  patterns across agents of the same principal indicate aggregator fraud.

## Regulatory references (plain text)

- Central Bank of Nigeria, "Guidelines for the Regulation of Agent Banking
  and Agent Banking Relationships in Nigeria" (2013) — defines the
  principal/agent relationship, permitted agent activities, principal
  liability, and consumer-protection duties.
- CBN, "Guidance Notes on Anti-Money Laundering and Combating the Financing
  of Terrorism (AML/CFT) Regulations" — agent KYC/screening obligations that
  step 2 above implements.
- CBN three-tiered KYC framework — the tier model in `docs/KYC_TIERS.md`
  applied to customers served at agent locations.
- NIBSS NUBAN standard — the 10-digit account-number validation applied to
  float accounts.

These are cited for orientation; the current published versions on the CBN
website prevail over this summary.
