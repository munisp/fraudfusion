# CBN KYC Tier Mapping

FraudFusion onboarding levels (`basic` / `enhanced` / `premium`) map onto the
Central Bank of Nigeria's three-tier KYC framework (CBN AML/CFT Regulations,
2022, and the Tiered KYC guidelines). This document is the canonical mapping;
the KYC *enforcement* service (transaction-limit enforcement) is owned by
another lane — this file documents the contract it must enforce.

## Tier mapping

| Onboarding level | CBN tier | Identity documentation | Verification calls |
|---|---|---|---|
| `basic` | **Tier 1** | BVN or NIN only | `POST /api/v1/kyc/verify/basic` |
| `enhanced` | **Tier 2** | BVN + NIN + proof of address + PEP/sanctions screening | `POST /api/v1/kyc/verify/enhanced`, `POST /api/v1/screening/pep`, `POST /api/v1/screening/sanctions` |
| `premium` | **Tier 3** | Tier 2 documents + credit-bureau check + enhanced due diligence | `POST /api/v1/kyc/verify/premium`, `POST /api/v1/credit-bureau/check` |

Tier selection during onboarding is recorded via
`POST /api/v1/onboarding/kyc-tier` (onboarding-service) with values
`basic` / `enhanced` / `premium` per tenant — see `docs/ONBOARDING.md`.

## Account limits (CBN tiered KYC)

Limits enforced by the enforcement service per CBN tiered-KYC guidance:

| Limit | Tier 1 (`basic`) | Tier 2 (`enhanced`) | Tier 3 (`premium`) |
|---|---:|---:|---:|
| Max single transaction | ₦50,000 | ₦200,000 | No CBN cap (institutional risk policy) |
| Max daily cumulative transaction | ₦300,000 | ₦500,000 | No CBN cap |
| Max account balance | ₦300,000 | ₦500,000 | Unlimited |
| Channels | USSD/agent/mobile | All channels | All channels |

Notes:

- AML obligations (CTR at ₦10,000,000 NGN, STR filing within 72h of
  detection) apply at **every** tier and are implemented by
  `services/go/aml-monitor` (see `CTR_THRESHOLD_NGN` / `STR_SLA_HOURS`).
- Sanctions screening uses the local watchlist
  (`services/go/aml-monitor/config/sanctions_watchlist.json`) with ML
  augmentation, at onboarding (Tier 2/3) and per-transaction for flagged
  counterparties.
- The values above are the CBN defaults; the enforcement service must treat
  them as configurable per tenant/institution policy.
