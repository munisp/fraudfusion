"""Victim-exposure detection + redress guidance (lane I1).

Closes the "you may not know until EFCC comes knocking" gap from the NIN/BVN
transcript: the platform ingests LAWFULLY OBTAINED breach/leak indicator
batches (e.g. the EFCC account-supplier crackdown, telco fraud reports),
matches them against the identity graph and registries, and writes
`exposure_detected` alerts so affected customers are notified PROACTIVELY.

NDPA / pseudonymization posture: indicator identifiers are hashed (sha256 of
the normalised value) BEFORE persistence. Plaintext NIN/BVN/phone values are
used transiently for matching only — exposure_indicators and alert evidence
carry hashes, never raw identifiers.

Redress guidance (per the transcript): formal complaint to the organisation
involved, copy the FCCPC (consumer protection), report to the NDPC (NDPR
enforcement), plus immediate practical steps (contact bank, rotate
credentials, watch for OTP prompts).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from identity_store import IdentityStore
from registry import RegistryAdapter
from webhook_emitter import emit_event

VALID_IDENTIFIER_TYPES = ("phone", "email", "device", "nin", "bvn")
# severity by identifier sensitivity: BVN/NIN are high-sensitivity identity
# anchors; contact/device identifiers are medium.
HIGH_SENSITIVITY = ("bvn", "nin")

REDRESS_GUIDANCE: dict[str, Any] = {
    "summary": (
        "Your identity data appeared in a breach/leak indicator batch. You may "
        "not know your identity was misused until law enforcement (e.g. EFCC) "
        "comes knocking — act now using the steps below."
    ),
    "steps": [
        {
            "order": 1,
            "id": "formal_complaint",
            "title": "File a formal complaint with the organisation involved",
            "body": (
                "Write formally to the organisation whose identifier was exposed "
                "(your bank for BVN, NIMC/your enrolment centre for NIN, your "
                "telco for a SIM-linked identifier). Demand a written "
                "acknowledgement, an investigation reference number, and "
                "rectification of your record."
            ),
            "channel": "organisation_involved",
        },
        {
            "order": 2,
            "id": "fccpc_complaint",
            "title": "Copy the FCCPC (consumer protection)",
            "body": (
                "Copy the Federal Competition and Consumer Protection Commission "
                "(FCCPC) on your complaint. The FCCPC enforces consumer redress "
                "where a service provider's negligence exposed your data."
            ),
            "channel": "fccpc",
        },
        {
            "order": 3,
            "id": "ndpc_report",
            "title": "Report to the NDPC (NDPR enforcement)",
            "body": (
                "Report the personal-data breach to the Nigeria Data Protection "
                "Commission (NDPC), which enforces the Nigeria Data Protection "
                "Regulation (NDPR). The organisation involved may also have a "
                "statutory duty to notify the NDPC of the breach."
            ),
            "channel": "ndpc",
        },
        {
            "order": 4,
            "id": "immediate_steps",
            "title": "Immediate practical steps",
            "body": (
                "Contact your bank immediately and flag your BVN/accounts for "
                "enhanced monitoring; change your banking credentials, PINs and "
                "passwords; watch for unexpected OTP prompts or SIM-swap "
                "notifications and never share OTPs; check your accounts for "
                "unauthorised transactions."
            ),
            "channel": "self",
        },
    ],
}


def normalise_identifier(identifier_type: str, value: str) -> str:
    """Normalise before hashing so equivalent values match (case/whitespace)."""
    value = value.strip()
    if identifier_type == "email":
        value = value.lower()
    return value


def hash_identifier(identifier_type: str, value: str) -> str:
    """sha256 of the normalised identifier — the ONLY persisted form."""
    return hashlib.sha256(
        normalise_identifier(identifier_type, value).encode("utf-8")
    ).hexdigest()


def import_exposure_batch(
    store: IdentityStore,
    bvn_adapter: RegistryAdapter,
    nin_adapter: RegistryAdapter,
    *,
    batch_id: str,
    source_note: Optional[str],
    rows: list[dict[str, Any]],
    imported_by: str,
    tenant_id: str = "default",
) -> dict[str, Any]:
    """Match a leaked-data indicator batch and write exposure alerts.

    Idempotent: indicators dedupe on (tenant, type, hash, breach_ref); alerts
    dedupe on (customer, identifier_hash, breach_ref); a re-imported batch_id
    refreshes the batch row instead of duplicating it.
    """
    now = datetime.now(timezone.utc).isoformat()
    matched: list[dict[str, Any]] = []
    alerts_written = 0
    alerts_deduped = 0
    rejected: list[dict[str, Any]] = []

    for i, row in enumerate(rows, start=1):
        id_type = (row.get("identifier_type") or "").strip().lower()
        raw_value = (row.get("identifier_value") or "").strip()
        breach_ref = (row.get("breach_ref") or "").strip()
        if id_type not in VALID_IDENTIFIER_TYPES or not raw_value or not breach_ref:
            rejected.append({
                "row": i,
                "reason": "identifier_type must be one of "
                          f"{list(VALID_IDENTIFIER_TYPES)} and identifier_value/breach_ref are required",
            })
            continue
        observed_at = (row.get("observed_at") or "").strip() or None
        id_hash = hash_identifier(id_type, raw_value)

        # Persist the indicator — hash only, never the plaintext value.
        if store._is_pg:
            store.execute(
                "INSERT INTO exposure_indicators (tenant_id, batch_id, identifier_type,"
                " identifier_hash, breach_ref, observed_at)"
                " VALUES (:t, :b, :ty, :h, :br, :o)"
                " ON CONFLICT (tenant_id, identifier_type, identifier_hash, breach_ref) DO NOTHING",
                {"t": tenant_id, "b": batch_id, "ty": id_type, "h": id_hash,
                 "br": breach_ref, "o": observed_at},
            )
        else:
            store.execute(
                "INSERT OR IGNORE INTO exposure_indicators (tenant_id, batch_id, identifier_type,"
                " identifier_hash, breach_ref, observed_at)"
                " VALUES (:t, :b, :ty, :h, :br, :o)",
                {"t": tenant_id, "b": batch_id, "ty": id_type, "h": id_hash,
                 "br": breach_ref, "o": observed_at},
            )

        # --- matching ---------------------------------------------------
        # 1) identity graph: customers holding this exact identifier.
        matched_customers = {
            r["customer_id"]
            for r in store.enrollments_for_identifier(tenant_id, id_type, raw_value)
        }
        matched_via = "customer_identifiers" if matched_customers else None

        # 2) registries: a leaked BVN/NIN that resolves in a registry is
        #    exposure evidence even when no local customer holds it yet.
        registry_status = None
        registry_record: dict[str, Any] = {}
        if id_type == "bvn":
            res = bvn_adapter.lookup(raw_value, tenant_id=tenant_id)
            registry_status = res["status"]
            registry_record = res.get("record") or {}
        elif id_type == "nin":
            res = nin_adapter.lookup(raw_value, tenant_id=tenant_id)
            registry_status = res["status"]
            registry_record = res.get("record") or {}
        if registry_status == "found" and matched_via is None:
            matched_via = f"{id_type}_registry"

        if not matched_customers and registry_status != "found":
            continue  # indicator does not touch any known customer

        severity = "high" if id_type in HIGH_SENSITIVITY else "medium"
        for customer_id in sorted(matched_customers):
            evidence = {
                "identifier_type": id_type,
                "identifier_hash": id_hash,  # hash only — no plaintext
                "breach_ref": breach_ref,
                "observed_at": observed_at,
                "source_note": source_note,
                "matched_via": matched_via,
                "registry_status": registry_status,
                "enrollment_source": registry_record.get("enrollment_source"),
                "enrollment_agent_id": registry_record.get("enrollment_agent_id"),
                "import_batch_id": batch_id,
            }
            if store.exposure_alert_exists(tenant_id, customer_id, id_hash, breach_ref):
                alerts_deduped += 1
                continue
            alert_id = f"exp-{id_hash[:16]}-{abs(hash((customer_id, breach_ref))) % 10**8:08d}"
            store.execute(
                "INSERT INTO identity_theft_alerts (tenant_id, alert_id, user_id,"
                " alert_type, risk_level, details, created_at)"
                " VALUES (:t, :aid, :u, 'exposure_detected', :sev, :d, :ts)",
                {
                    "t": tenant_id,
                    "aid": alert_id,
                    "u": customer_id,
                    "sev": severity,
                    "d": json.dumps(evidence, sort_keys=True),
                    "ts": now,
                },
            )
            alerts_written += 1
            # Round-9 webhook contract: identity.exposure.detected fires ONLY
            # for newly written alerts (deduped re-imports skip it) and
            # carries alert id/type/hash refs ONLY — never plaintext
            # identifiers or customer PII. Fire-and-forget.
            emit_event(
                "identity.exposure.detected",
                tenant_id,
                {
                    "alert_id": alert_id,
                    "alert_type": "exposure_detected",
                    "identifier_type": id_type,
                    "identifier_hash": id_hash,
                    "breach_ref": breach_ref,
                    "risk_level": severity,
                },
            )
        matched.append({
            "identifier_type": id_type,
            "identifier_hash": id_hash,
            "breach_ref": breach_ref,
            "matched_customers": sorted(matched_customers),
            "registry_status": registry_status,
        })

    # Batch bookkeeping (idempotent on batch_id: upsert refreshes counts).
    if store._is_pg:
        store.execute(
            "INSERT INTO exposure_import_batches (tenant_id, batch_id, source_note, row_count,"
            " matched_count, imported_by, imported_at) VALUES (:t, :b, :sn, :rc, :mc, :by, :ts)"
            " ON CONFLICT (tenant_id, batch_id) DO UPDATE SET source_note = EXCLUDED.source_note,"
            " row_count = EXCLUDED.row_count, matched_count = EXCLUDED.matched_count,"
            " imported_by = EXCLUDED.imported_by, imported_at = EXCLUDED.imported_at",
            {"t": tenant_id, "b": batch_id, "sn": source_note, "rc": len(rows),
             "mc": len(matched), "by": imported_by, "ts": now},
        )
    else:
        store.execute(
            "INSERT INTO exposure_import_batches (tenant_id, batch_id, source_note, row_count,"
            " matched_count, imported_by, imported_at) VALUES (:t, :b, :sn, :rc, :mc, :by, :ts)"
            " ON CONFLICT (tenant_id, batch_id) DO UPDATE SET source_note = excluded.source_note,"
            " row_count = excluded.row_count, matched_count = excluded.matched_count,"
            " imported_by = excluded.imported_by, imported_at = excluded.imported_at",
            {"t": tenant_id, "b": batch_id, "sn": source_note, "rc": len(rows),
             "mc": len(matched), "by": imported_by, "ts": now},
        )

    return {
        "batch_id": batch_id,
        "row_count": len(rows),
        "rejected": rejected[:100],
        "rejected_count": len(rejected),
        "matched_count": len(matched),
        "matches": matched,
        "alerts_written": alerts_written,
        "alerts_deduped": alerts_deduped,
        "imported_by": imported_by,
    }


def exposures_for_customer(
    store: IdentityStore, customer_ref: str, tenant_id: str = "default"
) -> list[dict[str, Any]]:
    """Exposure alerts for one customer, evidence parsed from details JSON.
    Carries hashes only — plaintext identifiers are never returned or stored."""
    rows = store.query(
        "SELECT id, alert_id, alert_type, risk_level, details, created_at"
        " FROM identity_theft_alerts WHERE tenant_id = :t AND user_id = :u"
        " AND alert_type = 'exposure_detected' ORDER BY created_at DESC",
        {"t": tenant_id, "u": customer_ref},
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        try:
            details = json.loads(row["details"] or "{}")
        except (TypeError, ValueError):
            details = {}
        out.append({
            "alert_id": row["alert_id"] or str(row["id"]),
            "alert_type": row["alert_type"],
            "severity": row["risk_level"],
            "identifier_type": details.get("identifier_type"),
            "identifier_hash": details.get("identifier_hash"),
            "breach_ref": details.get("breach_ref"),
            "observed_at": details.get("observed_at"),
            "source_note": details.get("source_note"),
            "matched_via": details.get("matched_via"),
            "detected_at": row["created_at"],
        })
    return out
