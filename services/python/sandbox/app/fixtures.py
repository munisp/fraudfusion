"""Deterministic synthetic fixtures for the FraudFusion sandbox.

EVERYTHING in this module is invented. Names, BVNs, NINs, CAC numbers, phones
and emails are synthetic test data — no real PII appears anywhere.

Magic values (documented in README.md):
  BVN ending 000 -> decision "approved" (verified)
  BVN ending 001 -> decision "manual_review"
  BVN ending 002 -> decision "rejected"
  BVN ending 003 -> sanctions hit (sanctions_screening.is_sanctioned = true,
                    decision "rejected")
  any other well-formed BVN/NIN -> "approved"
  malformed NIN/BVN -> format_valid=false in verification_results and the
  verification is rejected, mirroring kyc-api's real behaviour (a 200 with
  decision "rejected", never a fabricated pass).

  CAC number RC000000 -> KYB verdict "verified"
  CAC number RC000001 -> KYB verdict "manual_review"
  CAC number RC000002 -> KYB verdict "rejected"
  any other well-formed CAC number -> "verified"

  /api/v1/document/verify: filename containing "reject" or "fail" -> rejected;
  containing "review" -> manual_review; otherwise verified when the upload is
  structurally valid (recognized format). Empty upload -> 422, mirroring
  kyc-api. Unrecognized format -> structurally_valid=false -> rejected.
"""

from __future__ import annotations

# Demo webhook signing secret for /sandbox/trigger-event. NOT a real secret —
# it exists only so developers can test receivers against the shared signing
# scheme (X-FraudFusion-Signature: t=<unix>,v1=<hex hmac-sha256>).
WEBHOOK_DEMO_SECRET = "whsec_demo0000000000000000000000000000"

WEBHOOK_EVENT_TYPES = (
    "kyc.verification.completed",
    "kyb.verification.completed",
    "identity.exposure.detected",
)

# Deterministic synthetic customer directory (~10 entries). BVNs/NINs are
# invented 11-digit strings; the trailing-3-digit magic rule above applies.
TEST_CUSTOMERS: list[dict] = [
    {"customer_id": "cus_sandbox_001", "first_name": "Adaeze", "last_name": "Okonkwo",
     "bvn": "22300000000", "nin": "70123456000", "phone": "+2348010000001",
     "email": "adaeze.okonkwo@sandbox.example", "expected_decision": "approved",
     "note": "BVN ends 000 -> verified"},
    {"customer_id": "cus_sandbox_002", "first_name": "Babajide", "last_name": "Adeyemi",
     "bvn": "22300000001", "nin": "70123456001", "phone": "+2348010000002",
     "email": "babajide.adeyemi@sandbox.example", "expected_decision": "manual_review",
     "note": "BVN ends 001 -> manual_review"},
    {"customer_id": "cus_sandbox_003", "first_name": "Chiamaka", "last_name": "Eze",
     "bvn": "22300000002", "nin": "70123456002", "phone": "+2348010000003",
     "email": "chiamaka.eze@sandbox.example", "expected_decision": "rejected",
     "note": "BVN ends 002 -> rejected"},
    {"customer_id": "cus_sandbox_004", "first_name": "Damilola", "last_name": "Balogun",
     "bvn": "22300000003", "nin": "70123456003", "phone": "+2348010000004",
     "email": "damilola.balogun@sandbox.example", "expected_decision": "rejected",
     "note": "BVN ends 003 -> sanctions hit"},
    {"customer_id": "cus_sandbox_005", "first_name": "Emeka", "last_name": "Nwosu",
     "bvn": "22300000010", "nin": "70123456010", "phone": "+2348010000005",
     "email": "emeka.nwosu@sandbox.example", "expected_decision": "approved",
     "note": "well-formed, no magic suffix -> approved"},
    {"customer_id": "cus_sandbox_006", "first_name": "Funmilayo", "last_name": "Adeleke",
     "bvn": "22300000011", "nin": "70123456011", "phone": "+2348010000006",
     "email": "funmilayo.adeleke@sandbox.example", "expected_decision": "approved",
     "note": "well-formed, no magic suffix -> approved"},
    {"customer_id": "cus_sandbox_007", "first_name": "Gbenga", "last_name": "Olawale",
     "bvn": "22300000012", "nin": "70123456012", "phone": "+2348010000007",
     "email": "gbenga.olawale@sandbox.example", "expected_decision": "approved",
     "note": "well-formed, no magic suffix -> approved"},
    {"customer_id": "cus_sandbox_008", "first_name": "Halima", "last_name": "Abubakar",
     "bvn": "22300000013", "nin": "70123456013", "phone": "+2348010000008",
     "email": "halima.abubakar@sandbox.example", "expected_decision": "approved",
     "note": "well-formed, no magic suffix -> approved"},
    {"customer_id": "cus_sandbox_009", "first_name": "Ikenna", "last_name": "Ude",
     "bvn": "22300000014", "nin": "70123456014", "phone": "+2348010000009",
     "email": "ikenna.ude@sandbox.example", "expected_decision": "approved",
     "note": "well-formed, no magic suffix -> approved"},
    {"customer_id": "cus_sandbox_010", "first_name": "Jumoke", "last_name": "Salami",
     "bvn": "22300000015", "nin": "70123456015", "phone": "+2348010000010",
     "email": "jumoke.salami@sandbox.example", "expected_decision": "approved",
     "note": "well-formed, no magic suffix -> approved"},
]

# Synthetic KYB fixtures.
TEST_BUSINESSES: list[dict] = [
    {"business_name": "Sandbox Verified Ventures Ltd", "cac_number": "RC000000",
     "expected_verdict": "verified"},
    {"business_name": "Sandbox Review Trading Co", "cac_number": "RC000001",
     "expected_verdict": "manual_review"},
    {"business_name": "Sandbox Rejected Enterprises", "cac_number": "RC000002",
     "expected_verdict": "rejected"},
]
