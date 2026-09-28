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
        shared = sorted(set(
            e["matched_on"] for e in evidence
            if e["source"] == "customer_identifiers" and e.get("customer_id") in members
        ))
        cluster: dict[str, Any] = {
            "customers": sorted(members),
            "cluster_size": len(members),
            "shared_identifiers": shared,
            "evidence": [e for e in evidence if e.get("customer_id") in members],
        }
        # Enrollment-source tracing: a duplicate-identity cluster must be
        # traceable to source — surface where/how each holder of every shared
        # identifier was enrolled, and which sources/agents DIFFER.
        if len(members) > 1:
            traces: list[dict[str, Any]] = []
            for matched_on in shared:
                id_type, _, id_value = matched_on.partition(":")
                rows = [
                    r for r in store.enrollments_for_identifier(tenant_id, id_type, id_value)
                    if r["customer_id"] in members
                ]
                sources = {r["enrollment_source"] or "unknown" for r in rows}
                agents = {r["enrollment_agent_id"] or "unknown" for r in rows}
                traces.append({
                    "shared_identifier": matched_on,
                    "enrollments": [
                        {
                            "customer_id": r["customer_id"],
                            "enrollment_source": r["enrollment_source"] or "unknown",
                            "enrollment_agent_id": r["enrollment_agent_id"],
                            "enrollment_channel": r["enrollment_channel"],
                            "enrolled_at": r["enrolled_at"],
                        }
                        for r in rows
                    ],
                    "differing_enrollment_sources": sorted(sources) if len(sources) > 1 else [],
                    "differing_enrollment_agents": sorted(agents) if len(agents) > 1 else [],
                })
            cluster["enrollment_traces"] = traces
        clusters.append(cluster)

    inconsistencies: list[str] = []
    nin_rec, bvn_rec = registry_records.get("nin"), registry_records.get("bvn")
    registry_enrollment_tracing: dict[str, Any] = {}
    if nin_rec and bvn_rec:
        if (nin_rec.get("full_name") or "").strip().lower() != (bvn_rec.get("full_name") or "").strip().lower():
            inconsistencies.append("name_mismatch_between_nin_and_bvn")
        if nin_rec.get("date_of_birth") and bvn_rec.get("date_of_birth") \
                and nin_rec["date_of_birth"] != bvn_rec["date_of_birth"]:
            inconsistencies.append("dob_mismatch_between_nin_and_bvn")
        if inconsistencies:
            # A NIN<->BVN conflict is traceable to source: surface where each
            # side of the conflict was enrolled (source/agent/channel/when).
            def _enrollment(rec: dict[str, Any]) -> dict[str, Any]:
                return {
                    "enrollment_source": rec.get("enrollment_source") or "unknown",
                    "enrollment_agent_id": rec.get("enrollment_agent_id"),
                    "enrollment_channel": rec.get("enrollment_channel"),
                    "enrolled_at": rec.get("enrolled_at"),
                    "provenance": rec.get("provenance"),
                }

            nin_enr, bvn_enr = _enrollment(nin_rec), _enrollment(bvn_rec)
            registry_enrollment_tracing = {
                "nin": nin_enr,
                "bvn": bvn_enr,
                "differing_enrollment_sources": (
                    [nin_enr["enrollment_source"], bvn_enr["enrollment_source"]]
                    if nin_enr["enrollment_source"] != bvn_enr["enrollment_source"] else []
                ),
                "differing_enrollment_agents": (
                    [nin_enr["enrollment_agent_id"], bvn_enr["enrollment_agent_id"]]
                    if nin_enr["enrollment_agent_id"] != bvn_enr["enrollment_agent_id"] else []
                ),
            }

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
        "registry_enrollment_tracing": registry_enrollment_tracing,
        "risk_score": risk_score,
        "searched_sources": searched_sources,
        "checks_status": "degraded" if unavailable else "completed",
    }


def enrollment_agent_rollup(store: IdentityStore, tenant_id: str = "default") -> list[dict[str, Any]]:
    """Per-enrollment-agent roll-up: "linked to N flagged clusters".

    A flagged cluster is any identifier value held by MORE THAN ONE distinct
    customer (the duplicate-identity signal). For every such identifier we
    attribute the flag to the enrollment source/agent recorded on each holder's
    row, so an enrollment agent or channel that keeps appearing in flagged
    clusters is traceable to source.
    """
    flagged = store.query(
        "SELECT id_type, id_value, COUNT(DISTINCT customer_id) AS holders"
        " FROM customer_identifiers WHERE tenant_id = :t"
        " GROUP BY id_type, id_value HAVING COUNT(DISTINCT customer_id) > 1",
        {"t": tenant_id},
    )
    rollup: dict[str, dict[str, Any]] = {}
    for row in flagged:
        for enr in store.enrollments_for_identifier(tenant_id, row["id_type"], row["id_value"]):
            agent = enr["enrollment_agent_id"] or "unknown"
            entry = rollup.setdefault(agent, {
                "enrollment_agent_id": None if agent == "unknown" else agent,
                "enrollment_sources": set(),
                "enrollment_channels": set(),
                "flagged_clusters": 0,
                "customers": set(),
                "flagged_identifiers": set(),
            })
            entry["enrollment_sources"].add(enr["enrollment_source"] or "unknown")
            if enr["enrollment_channel"]:
                entry["enrollment_channels"].add(enr["enrollment_channel"])
            entry["customers"].add(enr["customer_id"])
            entry["flagged_identifiers"].add(f"{row['id_type']}:{row['id_value']}")
    out = []
    for agent, entry in sorted(rollup.items()):
        out.append({
            "enrollment_agent_id": entry["enrollment_agent_id"],
            "enrollment_sources": sorted(entry["enrollment_sources"]),
            "enrollment_channels": sorted(entry["enrollment_channels"]),
            "flagged_clusters": len(entry["flagged_identifiers"]),
            "linked_customers": sorted(entry["customers"]),
            "flagged_identifiers": sorted(entry["flagged_identifiers"]),
        })
    out.sort(key=lambda r: (-r["flagged_clusters"], str(r["enrollment_agent_id"])))
    return out
