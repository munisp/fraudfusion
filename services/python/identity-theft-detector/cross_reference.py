"""Real cross-reference engine for the identity-theft-detector.

Given phone/email/device (and optionally NIN/BVN), this queries:
  * customer_identifiers  (the identity graph edges: identifier -> customer)
  * bvn_registry / nin_registry via the configured adapters (forward lookup
    for provided NIN/BVN, reverse lookup by phone/email)
  * identity_theft_alerts (prior fraud signals touching the identifiers or
    the matched customers)

and returns matched identity CLUSTERS with evidence links. An empty result
means genuinely no matches, and `searched_sources` always lists every source
that was consulted (with per-source status) so an outage can never masquerade
as "no matches".
"""

from __future__ import annotations

from typing import Any, Optional

from identity_store import IdentityStore
from registry import RegistryAdapter


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def cross_reference(
    store: IdentityStore,
    bvn_adapter: RegistryAdapter,
    nin_adapter: RegistryAdapter,
    *,
    user_id: str,
    nin: Optional[str] = None,
    bvn: Optional[str] = None,
    phone: Optional[str] = None,
    email: Optional[str] = None,
    device: Optional[str] = None,
    tenant_id: str = "default",
) -> dict[str, Any]:
    searched_sources: list[dict[str, str]] = []
    evidence: list[dict[str, Any]] = []
    source_results: dict[str, Any] = {}
    uf = _UnionFind()
    matched_customers: set[str] = set()

    def identifiers_for(id_type: str, value: str) -> list[dict[str, Any]]:
        return store.query(
            "SELECT customer_id, id_type, id_value FROM customer_identifiers"
            " WHERE tenant_id = :t AND id_type = :ty AND id_value = :v",
            {"t": tenant_id, "ty": id_type, "v": value},
        )

    # -- 1. direct identifier graph lookup (phone/email/device/nin/bvn) ------
    provided = [
        ("phone", phone), ("email", email), ("device", device),
        ("nin", nin), ("bvn", bvn),
    ]
    graph_hit = False
    for id_type, value in provided:
        if not value:
            continue
        rows = identifiers_for(id_type, value)
        graph_hit = True
        for row in rows:
            matched_customers.add(row["customer_id"])
            evidence.append({
                "source": "customer_identifiers",
                "matched_on": f"{id_type}:{value}",
                "customer_id": row["customer_id"],
            })
    if graph_hit:
        searched_sources.append({"source": "customer_identifiers", "status": "searched"})

    # Customers sharing an identifier with a matched customer (1 hop) join the
    # same cluster: collect all identifiers of matched customers, then find
    # every other customer holding any of them.
    if matched_customers:
        for cid in list(matched_customers):
            rows = store.query(
                "SELECT id_type, id_value FROM customer_identifiers"
                " WHERE tenant_id = :t AND customer_id = :c",
                {"t": tenant_id, "c": cid},
            )
            for row in rows:
                for other in identifiers_for(row["id_type"], row["id_value"]):
                    if other["customer_id"] != cid:
                        uf.union(cid, other["customer_id"])
                        matched_customers.add(other["customer_id"])
                        evidence.append({
                            "source": "customer_identifiers",
                            "matched_on": f"{row['id_type']}:{row['id_value']}",
                            "customer_id": other["customer_id"],
                        })

    # -- 2. registry forward lookups (NIN/BVN) --------------------------------
    registry_records: dict[str, dict] = {}
    for adapter, value, key in ((nin_adapter, nin, "nin"), (bvn_adapter, bvn, "bvn")):
        if not value:
            continue
        result = adapter.lookup(value, tenant_id=tenant_id)
        source_results[key] = result
        searched_sources.append({"source": result.get("source", adapter.name),
                                 "status": result["status"]})
        if result["status"] == "found" and result.get("record"):
            registry_records[key] = result["record"]
            evidence.append({
                "source": result.get("source", adapter.name),
                "matched_on": f"{key}:{value}",
                "record": {k: result["record"].get(k) for k in ("full_name", "date_of_birth")},
            })

    # -- 3. registry reverse lookups (phone/email) ----------------------------
    if phone or email:
        for adapter in (nin_adapter, bvn_adapter):
            hits = adapter.search_by_contact(phone=phone, email=email, tenant_id=tenant_id)
            searched_sources.append({"source": f"{adapter.name} (reverse)",
                                     "status": "searched"})
            for hit in hits:
                evidence.append({
                    "source": hit.get("source", adapter.name),
                    "matched_on": f"contact:{phone or email}",
                    "registry_id": hit.get("id_value"),
                    "full_name": hit.get("full_name"),
                    "is_synthetic": bool(hit.get("is_synthetic")),
                })

    # -- 4. prior identity-theft alerts ---------------------------------------
    alerts: list[dict[str, Any]] = []
    if phone:
        alerts += store.alert_matches_identifier(tenant_id, "phone_number", phone)
    if email:
        alerts += store.alert_matches_identifier(tenant_id, "email", email)
    for cid in matched_customers | {user_id}:
        alerts += store.query(
            "SELECT id, alert_id, user_id, alert_type, risk_level, created_at"
            " FROM identity_theft_alerts WHERE tenant_id = :t AND user_id = :u",
            {"t": tenant_id, "u": cid},
        )
    searched_sources.append({"source": "identity_theft_alerts", "status": "searched"})
    deduped_alerts: list[dict[str, Any]] = []
    seen_alerts: set[Any] = set()
    for alert in alerts:
        if alert["id"] in seen_alerts:
            continue
        seen_alerts.add(alert["id"])
        deduped_alerts.append(alert)
        evidence.append({
            "source": "identity_theft_alerts",
            "matched_on": f"alert:{alert.get('alert_id') or alert['id']}",
            "user_id": alert["user_id"],
            "alert_type": alert["alert_type"],
            "risk_level": alert["risk_level"],
        })

    # -- 5. clusters + inconsistencies ----------------------------------------
    clusters: list[dict[str, Any]] = []
    grouped: dict[str, set[str]] = {}
    for cid in matched_customers:
        grouped.setdefault(uf.find(cid), set()).add(cid)
    for members in grouped.values():
        shared = [
            e["matched_on"] for e in evidence
            if e["source"] == "customer_identifiers" and e.get("customer_id") in members
        ]
        clusters.append({
            "customers": sorted(members),
            "cluster_size": len(members),
            "shared_identifiers": sorted(set(shared)),
            "evidence": [e for e in evidence if e.get("customer_id") in members],
        })

    inconsistencies: list[str] = []
    nin_rec, bvn_rec = registry_records.get("nin"), registry_records.get("bvn")
    if nin_rec and bvn_rec:
        if (nin_rec.get("full_name") or "").strip().lower() != (bvn_rec.get("full_name") or "").strip().lower():
            inconsistencies.append("name_mismatch_between_nin_and_bvn")
        if nin_rec.get("date_of_birth") and bvn_rec.get("date_of_birth") \
                and nin_rec["date_of_birth"] != bvn_rec["date_of_birth"]:
            inconsistencies.append("dob_mismatch_between_nin_and_bvn")

    risk_score = 0.0
    if any(c["cluster_size"] > 1 for c in clusters):
        risk_score += 0.6
    risk_score += min(0.3, 0.15 * len(deduped_alerts))
    risk_score += 0.2 * len(inconsistencies)
    risk_score = round(min(risk_score, 1.0), 3)

    unavailable = [s for s in searched_sources if s["status"] == "unavailable"]
    return {
        "matched_customers": sorted(matched_customers),
        "clusters": clusters,
        "alerts": deduped_alerts,
        "source_results": source_results,
        "inconsistencies": inconsistencies,
        "risk_score": risk_score,
        "searched_sources": searched_sources,
        "checks_status": "degraded" if unavailable else "completed",
    }
