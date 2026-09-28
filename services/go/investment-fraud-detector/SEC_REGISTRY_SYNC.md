# SEC Nigeria Registry Synchronization

The investment-fraud-detector verifies schemes against the SEC Nigeria
register of licensed capital-market operators. This document describes how
the registry is sourced, synchronized, and how the service behaves when the
real register is absent.

## Sources and precedence

| Source | Activation | `registry_source` in responses | Notes |
|---|---|---|---|
| Licensee CSV file | `SEC_REGISTRY_CSV=/path/to/sec_licensees.csv` at startup, or `POST /api/v1/investment-fraud/sec/registry/import` | `file` | Authoritative when loaded |
| Bundled seed table | default (no CSV configured) | `seed` | 6 sample fund managers from `database/20260827_service_base_tables.sql` — **not the full register** |

## Fail-closed behavior

- `SEC_REGISTRY_CSV` set but the file is unreadable or malformed → the
  service refuses to start (log.Fatal). A configured-but-broken registry
  must never silently fall back to the seed data.
- The CSV importer validates structure strictly (header with a `name`
  column; optional `promoter_id`, `registration_number`, `entity_type`;
  no empty names; consistent field counts). Any malformed row rejects the
  whole import; the previously active registry stays in force.
- Registry lookup errors (DB down, circuit breaker open) surface as
  `503 {"dependency_degraded": true, "registry_source": ...}` and callers
  route to manual review — never reported as "not registered".

## CSV format

```csv
name,promoter_id,registration_number,entity_type
Stanbic IBTC Asset Management Limited,PROM-STANBIC-AM,SEC/CMO/AM-001,fund_manager
```

- Obtain the current register from SEC Nigeria (https://sec.gov.ng —
  "Capital Market Operators" licensee listings) and export/normalize to
  this shape. One row per licensee; names are matched case-insensitively.

## Import endpoint (job stub)

```
POST /api/v1/investment-fraud/sec/registry/import
Authorization: Bearer <token with compliance_officer or admin role>
Content-Type: text/csv

<CSV body>
```

Response: `{"imported": <rows>, "persisted": <bool>, "registry_source": "file"}`.

- The upload replaces the in-memory file registry atomically.
- When `SEC_REGISTRY_CSV` is set, the body is also persisted to that path
  (mode 0600) so a restart reloads it (`persisted: true`). Without the env
  var the import is in-memory only and is lost on restart — set the env var
  for durable operation.

## Suggested sync cadence

Weekly refresh via CI/cron job: download the SEC register, normalize to CSV,
`POST` to the import endpoint (or replace the file and restart), and alert
if `registry_source` in `/schemes/verify-sec` responses is `seed` in
production for more than 24h.
