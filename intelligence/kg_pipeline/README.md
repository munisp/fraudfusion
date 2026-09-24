# kg_pipeline — incremental knowledge-graph construction

Builds the FraudFusion knowledge graph from platform data, incrementally,
with NDPA-compliant pseudonymized identifiers and a versioned schema.

## Sources

| dataset          | physical source(s)                                                        | watermark column        |
|------------------|---------------------------------------------------------------------------|-------------------------|
| `transactions`   | `$LAKEHOUSE_DIR/transactions/dt=YYYY-MM-DD/part-*.parquet` (ml lane contract) or `transactions.parquet` | `ts`/`created_at`       |
| `accounts`/`kyc` | `accounts.parquet` / `kyc.parquet` or partitioned dirs                    | `created_at`/`updated_at` |
| `alerts`         | `alerts.parquet` (+ Postgres `ato_alerts` when a DSN is given)            | `created_at`            |
| `sars`           | `sars.parquet` (+ Postgres `aml_sars`)                                    | `filing_date`/`created_at` |
| `cases`          | `cases.parquet`                                                           | `created_at`            |
| `devices`        | `devices.parquet` (+ Postgres `device_fingerprints`)                      | `last_seen_at`/`created_at` |
| `insider_events` | `insider_events.parquet` (+ Postgres `insider_fraud_events`)              | `created_at`            |
| `merchants`      | `merchants.parquet`                                                       | `created_at`            |

Missing datasets contribute zero rows (logged) — the KG is best-effort over
whichever sources exist. Column-name variants are tolerated (see
`sources.COLUMN_VARIANTS`). Postgres reading requires `psycopg` and
`KG_POSTGRES_DSN`/`DATABASE_URL`; without the driver it fails loudly.

## Graph model

- **Entities**: Customer, Account, Device, Transaction, Alert, Case, SAR,
  Merchant, Agent, Address
- **Relationships**: TRANSACTED_WITH, SHARES_DEVICE, FLAGGED_BY,
  FILED_AGAINST, OWNS, LOCATED_IN, WORKS_WITH

`SHARES_DEVICE` edges are derived between customers touching the same device;
`WORKS_WITH` edges between agents/employees appearing in the same insider
event context.

## Incrementality (watermark state)

`.kg_state.json` in the output dir holds a per-dataset watermark (max source
event timestamp incorporated). Each run processes only rows strictly newer.
Timestamp-less rows (dimension tables such as accounts or merchants) cannot
be watermark-filtered; they are content-fingerprinted (SHA-256 of the
canonical row set) and skipped entirely when unchanged, so re-runs neither
duplicate entities nor inflate relation counts. Merges are idempotent
(entities MERGE on `id`, relations on `(src,dst,type)`), so even a forced
reprocess is safe for graph shape. A store at a different
`KG_SCHEMA_VERSION` is refused unless `--full-rebuild` is passed.

## NDPA pseudonymization

All entity ids are `<kind>_pii_<sha256(salt:raw_id)[:32]>` — the same salted
SHA-256 contract as `mlops/lakehouse/export.py` (salt from
`LAKEHOUSE_PII_SALT`), so KG nodes join back to lakehouse features without
raw identifiers ever entering the store.

## Engines

- **builtin** (default): the executor in `executor.py`.
- **cocoindex**: `cocoindex_adapter.py` runs the same transform as a
  cocoindex flow when the package is installed; when it is not installed the
  adapter fails loudly and `--engine auto` falls back to builtin. Both
  engines share the watermark state file and the parquet store layout, so
  stores are interchangeable.

## Output store

`$KG_DIR/entities.parquet` — `id, label, props(json), first_seen, last_seen, schema_version`
`$KG_DIR/relations.parquet` — `src_id, dst_id, type, props(json), ts, count, schema_version`

Plain parquet, so `kg-qa` can serve from disk when no graph server is up;
`intelligence/kg_load` ships the same store into FalkorDB/Neo4j.

## Usage

```bash
python -m intelligence.kg_pipeline \
  --lakehouse-dir mlops/data/lakehouse \
  --output-dir intelligence/data/kg \
  --engine auto            # cocoindex if installed, else builtin
# full rebuild after a schema bump:
python -m intelligence.kg_pipeline --full-rebuild
```
