"""Knowledge-graph schema: entity labels, relation types, versioning.

The schema is versioned (KG_SCHEMA_VERSION). The executor stamps every run
and every emitted row; a store whose schema_version differs from the running
pipeline must be rebuilt (the executor refuses to mix versions unless
--full-rebuild is given, in which case it rewrites the store from scratch).

Entity labels and relation types mirror the platform domains:
  fraud alerts, AML SARs/cases, KYC records, transactions, devices,
  insider events.
"""
from __future__ import annotations

KG_SCHEMA_VERSION = "1.0.0"

# --- Entity labels -----------------------------------------------------------
CUSTOMER = "Customer"
ACCOUNT = "Account"
DEVICE = "Device"
TRANSACTION = "Transaction"
ALERT = "Alert"
CASE = "Case"
SAR = "SAR"
MERCHANT = "Merchant"
AGENT = "Agent"
ADDRESS = "Address"

ENTITY_TYPES = (
    CUSTOMER, ACCOUNT, DEVICE, TRANSACTION, ALERT,
    CASE, SAR, MERCHANT, AGENT, ADDRESS,
)

# --- Relation types ----------------------------------------------------------
TRANSACTED_WITH = "TRANSACTED_WITH"   # Customer/Account -> Customer/Account/Merchant
SHARES_DEVICE = "SHARES_DEVICE"       # Customer <-> Customer (via common Device)
FLAGGED_BY = "FLAGGED_BY"             # Customer/Transaction/Account -> Alert
FILED_AGAINST = "FILED_AGAINST"       # SAR/Case -> Customer/Account
OWNS = "OWNS"                         # Customer -> Account / Device
LOCATED_IN = "LOCATED_IN"             # Customer/Account -> Address
WORKS_WITH = "WORKS_WITH"             # Agent <-> Agent

REL_TYPES = (
    TRANSACTED_WITH, SHARES_DEVICE, FLAGGED_BY, FILED_AGAINST,
    OWNS, LOCATED_IN, WORKS_WITH,
)

# Default relation weights used by kg-qa path scoring. Higher = stronger
# evidentiary signal for an analyst.
REL_WEIGHTS = {
    FILED_AGAINST: 1.0,     # a filed SAR/Case is the strongest signal
    FLAGGED_BY: 0.9,
    SHARES_DEVICE: 0.8,
    WORKS_WITH: 0.6,
    OWNS: 0.5,
    TRANSACTED_WITH: 0.4,
    LOCATED_IN: 0.3,
}

# Canonical dataset names the pipeline knows how to read. Each dataset has a
# reader in sources.py that tolerates both lakehouse-partitioned parquet
# (<name>/dt=YYYY-MM-DD/part-*.parquet) and flat files (<name>.parquet).
DATASETS = (
    "transactions",
    "accounts",       # KYC/account records
    "kyc",            # alias-style KYC extracts
    "alerts",         # fraud alerts (ato_alerts, chargeback_alerts, ...)
    "sars",           # AML SARs (aml_sars)
    "cases",          # AML/fraud cases
    "devices",        # device_fingerprints
    "insider_events",  # insider_fraud_events
    "merchants",
)

# File names inside a KG store directory.
ENTITIES_FILE = "entities.parquet"
RELATIONS_FILE = "relations.parquet"
STATE_FILE = ".kg_state.json"
