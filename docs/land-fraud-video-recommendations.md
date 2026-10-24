# Land Fraud Systems and Remedy — Video Analysis & Implementation Ledger

**Source**: Channels Television, *"Land Fraud Systems And Remedy, Efficacy CEO
Shares Insight Into Challenges In Real Estate Business"* — interview with
Dr. Oluremi Ajiboye (MD/CEO, Efficacy Development PLC), published
2026-10-23, 13:51. Full transcript: `output/fixes11/land-fraud-video-transcript.txt`
(+ `.srt` with timestamps).

## What the video says

Nigerian land fraud is *systematized*: land grabbing is "an industry" built on
poor implementation of systems government already created. The CEO's own
losses (Omonile extortion, family disputes, buying from 2 of 7 families) and
his near-miss with a **cloned Certificate of Occupancy at Badore** — caught
only by a last-minute CTC (Certified True Copy) registry re-check after
lawyers, agreements and deposits were already in — frame the core problem:
**even professionals cannot verify title**. Context data cited: ~97% of
Nigerian land lacks formal title; 4,000+ land-grabbing petitions with ~1,700
attended; a PwC estimate of $900B+ locked in Nigerian real estate.

### Recommendations made in the interview

1. 100% enforcement of the Land Grabbers Act (2016; 10-yr Lagos, 25-yr Ogun).
2. Three dedicated land courts in Lagos (one per senatorial district) with
   **90-day resolution**, meeting twice weekly.
3. Chieftaincy/Local-Government ministry accountability for royal fathers
   involved in grabbing (fear of dethronement).
4. **Compensation before revocation** under the Land Use Act 1978 — an
   independent body (PwC/KPMG, town planners, REDAN) collects documents and
   compensates *before* acquisitions like the Coastal Road proceed.
5. Police should stay out of land matters (they are used to criminalize
   civil disputes — "malicious damage", "forceful entry" — buying time for
   grabbers).
6. **One standard deed-of-assignment template** for every land transaction
   in the state ("It happens in America… that is the standard for this
   state") — uniform interpretation, known remedies, known penalties.

## Coverage ledger → what was built (Round 11)

| # | Recommendation / failure mode | Buildable as software? | Implementation |
|---|---|---|---|
| — | Cloned C of O; CTC re-check | Yes | **Composite due-diligence endpoint** `POST /api/v1/due-diligence`: registry owner cross-check (CTC equivalent) via the fail-closed lands-registry adapters + claimants + consents + disputes + revocations → `clear / caution / high_risk / unavailable` with reason codes (`owner_mismatch`, `registry_not_found`, `multiple_claimants`, `consent_incomplete`, `open_dispute`, `uncompensated_revocation`). Combines with the existing `/api/v1/verify` document forensics. |
| — | Multiple sales of the same parcel | Yes | **First-wins parcel registry** `POST /api/v1/parcels`: duplicate `parcel_ref` → `409` + recorded conflict; same certificate number or survey-plan hash under a new ref → conflict record + `disputed` status. The multiple-sale alarm fires at registration time, not in court years later. |
| — | "Bought from 2 of 7 families"; heirs deny signatures | Yes | **Consent-party tracking** `POST /api/v1/parcels/{ref}/consents`: every required party must confirm before a parcel goes `clear`; withdrawals recorded; conflicts block clearing regardless of consent. Deed checker requires each consent party's **signature block on the same line as their name** — a name in the recitals is not consent. |
| 6 | Standard deed template | Yes | **Deed conformance checker** `POST /api/v1/deeds/conformance` (`api/deed_conformance.py`): 9 standard clauses (parties, recitals/root of title, consideration, parcel description with survey/beacons, habendum, covenants, Governor's consent s.22, execution, attestation) → missing-clause report + conformance score. Until Lagos publishes an official template, this enforces the de-facto standard structure. |
| 2 | Dedicated land courts, 90-day resolution | Yes (the tracking half) | **Dispute cases** `POST /api/v1/parcels/{ref}/disputes` with a configurable SLA clock (`LAND_DISPUTE_SLA_DAYS`, default 90): overdue open cases flagged `sla_breached`; resolution restores parcel status. Gives investors the "this matter takes 3 months, not 3 years" predictability signal. |
| 4 | Compensation before revocation | Yes | **Revocation workflow** `POST /api/v1/parcels/{ref}/revocations` → `/documents` → `/compensate`: compensation is rejected before documents are collected, and `acquisition_lawful` is **only** true when compensated — the Land Use Act guardrail as a state machine. |
| — | "When you go to court…" evidence | Yes | **Hash-chained evidence packs** `GET /api/v1/parcels/{ref}/evidence`: every registration/consent/conflict/dispute/revocation event appended to a per-parcel tamper-evident chain (payloads hash-only, NDPA-aligned); export verifies offline. Court bundle for exactly the litigation the video describes. |
| — | 97% untitled land | Partially | Parcels can be registered without a certificate number (survey-plan hash / address identity), so customary-chain parcels enter the same first-wins + evidence system before formal titling. |
| 1, 3, 5 | Enforcement, chieftaincy accountability, police conduct | **No — policy** | Out of scope for software. The platform supplies enforcement-adjacent tooling (evidence packs, SLA breach flags) and documents the boundary honestly. |

### Supporting pieces

- **Sandbox lands-registry doubles** `/sandbox/registry/lands/owner|history`
  (magic: cert ending `9` → 404, ending `8` → owner mismatch `SANDBOX
  STRANGER`, else deterministic owner) — partners dry-run the full
  due-diligence flow before any state lands-bureau contract exists; adapter
  conformance verified against a real uvicorn round trip.
- **Canonical PG migration** `database/20261025_land_due_diligence.sql`
  mirroring the SQLite schema (dual-driver store pattern).
- `.env.example`: `LAND_DISPUTE_SLA_DAYS`, per-state `*_LANDS_URL`.

### Known follow-ups (not in this round)

- Live state lands-bureau data contracts (procurement; adapters are plug-ready).
- Webhook event types for the land module (`parcel.conflict.detected`,
  `dispute.sla.breached`) and land methods in the Python/TS SDKs.
- Registry `owner_name` vs `name` shape normalization is handled in the
  composite; a shared response schema would remove that wart.
