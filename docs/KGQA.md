# KG-QA — knowledge-graph analyst copilot (lane I2)

A local, privacy-preserving question-answering layer over FraudFusion's fraud
knowledge graph. Analysts ask natural-language questions ("Which devices are
shared by accounts flagged in SARs last month?"); the service links the
question to KG entities, reasons over bounded relationship paths, and answers
with **grounded, KG-cited text** — optionally rephrased by a local LLM
(ollama), never fabricated by one.

## Architecture

```
 platform data (alerts, SARs/cases, KYC, transactions, devices, insider events)
        │  parquet lakehouse ($LAKEHOUSE_DIR, hive partitions dt=YYYY-MM-DD)
        │  and/or Postgres source tables (aml_sars, device_fingerprints, ...)
        ▼
 intelligence/kg_pipeline            ← incremental, watermark state,
   (builtin executor or               NDPA-pseudonymized ids, schema-versioned
    optional cocoindex engine)
        │  $KG_DIR/entities.parquet + relations.parquet + .kg_state.json
        ▼
 intelligence/kg_load                ← idempotent MERGE batches
        │        ┌────────────────────┐
        ▼        ▼                    ▼
     FalkorDB   Neo4j           parquet store (disk)
        │        │                    │
        └────────┴────────┬───────────┘
                          ▼
              services/python/kg-qa (:8300)
                entity linking → bounded path reasoning → composition
                          │            (fallback: in-memory parquet store)
                          ▼
                   ollama (optional rephrase)
                   llama3.2:3b, CPU in dev, GPU recommended in prod
```

## Data flow

1. **Build**: `python -m intelligence.kg_pipeline --lakehouse-dir …
   --output-dir …` (or `POST /v1/kg/refresh`). Per-dataset watermarks make it
   incremental; `--full-rebuild` resets. Entity ids are
   `<kind>_pii_<sha256(salt:id)[:32]>` — the same salted-SHA-256 contract as
   the mlops lakehouse export (`LAKEHOUSE_PII_SALT`), so the KG joins back to
   lakehouse features without raw identifiers ever entering the store.
2. **Load**: `python -m intelligence.kg_load --target falkordb --kg-dir …`
   (or `--target neo4j`, env `NEO4J_URI`). MERGE-on-id ⇒ idempotent.
3. **Serve**: kg-qa resolves its graph store in order: FalkorDB
   (`FALKORDB_URL`) → Neo4j (`NEO4J_URI`) → in-memory parquet store
   (`KG_DIR`) — the last is the always-available fallback and the mode tests
   exercise.

## Question answering (EPR-KGQA style)

- **Entity linking** — exact + fuzzy (`difflib`, threshold 0.85) matching of
  question mentions against entity ids and prop aliases (bank, state, city,
  alert_type, SAR status, …). Pseudonymized entity ids pasted by analysts
  match exactly.
- **Path reasoning** — BFS over the relation graph, bounded hops (default 3,
  max 5), simple paths only. With ≥2 linked entities, connecting paths;
  with 1, context paths. Scored by relation evidentiary weight
  (`FILED_AGAINST` 1.0 > `FLAGGED_BY` 0.9 > `SHARES_DEVICE` 0.8 > …) ×
  recency decay (180-day half-life).
- **Composition** — grounded template sentences rendered from the top-k
  paths, then **optionally** rephrased by ollama (`OLLAMA_URL`,
  `OLLAMA_MODEL=llama3.2:3b`, 10s timeout). The LLM prompt contains only the
  extracted facts with a strict no-new-facts instruction; on any failure the
  template answer is returned with `llm_used=false`. When nothing links, the
  answer says so explicitly.

Every answer carries **citations**: the entity ids (+ labels) of every node on
every returned path, and the paths themselves with per-hop type/timestamp.

## API

| endpoint             | description                                             |
|----------------------|---------------------------------------------------------|
| `POST /v1/kgqa/ask`    | `{question, max_hops?, max_paths?}` → answer + citations |
| `GET  /v1/kgqa/health` | store mode, graph size, ollama reachability              |
| `POST /v1/kg/refresh`  | incremental KG rebuild + store reload                    |

### Example

```bash
curl -X POST localhost:8300/v1/kgqa/ask \
  -H 'content-type: application/json' \
  -d '{"question": "Which devices are shared by accounts flagged in SARs last month?"}'
```

```json
{
  "answer": "Based on the fraud knowledge graph, 1 relevant relationship path(s)…\n1. Customer …a1b2 filed against → SAR …c3d4 (as of 2026-09-13) …",
  "llm_used": false,
  "store_mode": "in-memory-parquet",
  "citations": [{"entity_id": "customer_pii_…", "label": "Customer", "role": "path-node"}],
  "paths": [{"score": 0.93, "hops": [{"src": "…", "dst": "…", "type": "FILED_AGAINST"}]}]
}
```

## Deployment

- `deploy/kubernetes/falkordb.yaml` — FalkorDB (CPU, PVC, probes).
- `deploy/kubernetes/ollama.yaml` — ollama CPU deployment + model-pull init
  container + model PVC. **Production note (honest): CPU ollama is fine for
  single-analyst copilot latency but not high-QPS; schedule on GPU nodes or
  front a GPU-backed runtime for production.**
- `local-e2e/docker-compose.yml` — `falkordb`, `ollama`, `kg-qa` services with
  healthchecks; kg-qa degrades to template answers if ollama never comes up.
- kg-qa image: `services/python/kg-qa/Dockerfile` (repo-root build context;
  bundles `intelligence/` so `/v1/kg/refresh` can rebuild the graph).

## Limitations (honest)

- **Entity linking is lexical**, not neural: paraphrases far from KG prop
  values won't link. The fuzzy threshold is deliberately high to avoid false
  links; missed links produce an explicit "could not link" answer, not a
  guess.
- **Path reasoning is bounded exhaustive BFS** — good for explanation, not
  for aggregate questions ("how many…", "total amount…"), which it does not
  answer numerically.
- **No temporal query parsing**: "last month" in a question is not compiled
  to a date filter; recency enters only through path scoring.
- **Derived edges are heuristic**: SHARES_DEVICE comes from shared device
  sightings, WORKS_WITH from co-occurrence in insider events. Counts and
  timestamps are preserved on edges for analyst judgement.
- **The LLM never adds facts by construction**, but rephrasing can still
  garble wording; the `paths` + `citations` payload is always the source of
  truth.
- Pseudonymization is salted-SHA-256 (NDPA-aligned, deterministic); it is
  **not** anonymization — holders of the salt can re-identify by dictionary
  lookup, so the salt must stay in the secret store like the lakehouse one.
- Postgres source requires `psycopg`; the FalkorDB loader requires the
  `falkordb` or `redis` package; Neo4j requires the `neo4j` driver. All are
  optional and fail loudly with install hints — the parquet fallback always
  works.
