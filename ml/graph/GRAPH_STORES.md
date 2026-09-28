# Graph stores for FraudFusion: Neo4j vs FalkorDB

Both stores hold the same logical graph — `(:Account)-[:SENT]->(:Transaction)-[:TO]->(:Account)`
— exported from the lakehouse/synthetic parquet by `ml/graph/neo4j_export.py`
and `ml/graph/falkor_export.py`. Both are optional dev/ops dependencies: every
code path feature-detects the server and fails (or skips tests) LOUDLY, never
silently.

| Axis | Neo4j (5.x community) | FalkorDB (4.x) |
|---|---|---|
| Protocol / driver | Bolt, `neo4j` python driver | Redis protocol, plain `redis-py` (`GRAPH.QUERY`) — no extra SDK |
| Query language | Cypher (full) | openCypher subset (MERGE/MATCH/UNWIND/SET all work; check docs for exotic clauses) |
| Engine | JVM, page cache + heap tuning | In-memory Redis module, C — very low latency for traversals |
| Constraints/indexes | `CREATE CONSTRAINT ... IS UNIQUE` (used by our export) | Constraint support varies by version; our export relies on MERGE idempotency alone |
| Ops footprint | heavier (~512MB+ heap), mature k8s helm charts | tiny (~tens of MB), single container, persists like Redis (RDB/AOF) |
| Scaling story | clustering (enterprise license for HA) | replication like Redis; clustering via FalkorDB enterprise / Redis Cluster |
| Best fit here | analyst exploration (Bloom/Browser), long ad-hoc Cypher, constraints | low-latency online features (fan-in/fan-out lookups at scoring time), embedded sidecar |

**Platform recommendation.** Keep **Neo4j as the system of record** for the
account/transaction graph (constraints, mature tooling, `neo4j_train.py`
round-trip path). Use **FalkorDB as an optional hot-path read replica** for
latency-sensitive graph features at inference time — the same MERGE batches
feed both.

## License note (legal review required before any hosted offering)

- **FalkorDB is SSPLv1** (Server Side Public License). Internal use —
  including as a read replica inside our own platform — is fine. **Offering
  FalkorDB itself as a hosted/managed service to third parties triggers SSPL
  source-disclosure obligations**; a multi-tenant SaaS where tenants get
  direct FalkorDB access needs either a FalkorDB commercial license or legal
  sign-off. Our architecture keeps FalkorDB strictly internal (no
  tenant-facing port in the k8s manifests), which stays clear of the trigger.
- **Neo4j Community is GPLv3** — fine for internal use; network use does not
  trigger copyleft for our separate services (they communicate over Bolt, not
  by linking). Neo4j Enterprise (HA clustering) is commercial.
- **Alternatives if legal review fails**: keep the in-memory parquet store
  (already the default fallback), or evaluate Memgraph (BSL→Apache after 4
  years) / Redis Stack graph (RSALv2 — similar hosted-use questions). The
  `GraphStore` protocol in `services/python/kg-qa/app/graph_store.py` exists
  precisely so a store swap is a one-class change.

## Local dev

```bash
# Neo4j
docker compose -f ml/graph/neo4j.compose.yml up -d
python -m ml.graph.neo4j_export --max-txns 20000
python -m ml.graph.neo4j_roundtrip        # export->load->train consistency

# FalkorDB
docker compose -f ml/graph/falkor.compose.yml up -d
pip install redis
python -m ml.graph.falkor_export --max-txns 20000
```

## Kubernetes deploy note

Neither store is added to the repo's main k8s manifests (they are optional).
To deploy:

- **Neo4j**: use the official helm chart (`neo4j/neo4j`), `standalone` mode,
  a PersistentVolumeClaim for `/data`, and a `Secret` for `NEO4J_AUTH`
  (never commit credentials; the compose default `neo4j/password` is dev-only).
  Point services at `bolt://neo4j.<ns>.svc.cluster.local:7687` via `NEO4J_URI`.
- **FalkorDB**: a single `Deployment` + `Service` (port 6379) with a PVC for
  `/data` and AOF persistence enabled; set a password via
  `command: ["redis-server", "--requirepass", "$(FALKOR_PASSWORD)"]`-style
  args or the FalkorDB helm chart. Point clients with `FALKOR_HOST` /
  `FALKOR_PORT`. Run one replica (Raft/HA needs the enterprise tier) and
  treat it as rebuildable-from-lakehouse state: `falkor_export.py` is
  idempotent, so recovery = re-run the export.
