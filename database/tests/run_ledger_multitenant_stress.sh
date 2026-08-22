#!/usr/bin/env bash
set -euo pipefail

: "${PGHOST:?PGHOST is required}"
: "${PGPORT:?PGPORT is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGDATABASE:?PGDATABASE is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TRANSACTION_SQL="$ROOT/database/tests/20260822_ledger_stress_transaction.sql"
TENANTS="${LEDGER_STRESS_TENANTS:-12}"
TRANSACTIONS_PER_TENANT="${LEDGER_STRESS_TRANSACTIONS_PER_TENANT:-40}"
MAX_CONCURRENCY="${LEDGER_STRESS_CONCURRENCY:-16}"

export PGOPTIONS="-c app.stress_tenants=$TENANTS"
psql -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE tenant_number integer;
        tenant text;
BEGIN
  FOR tenant_number IN 1..current_setting('app.stress_tenants')::integer LOOP
    tenant := 'stress-tenant-' || tenant_number;
    INSERT INTO ledger_accounts (id, tenant_id, account_code, account_type, currency)
    VALUES
      (md5(tenant || ':debit')::uuid, tenant, 'stress-debit', 'asset', 'USD'),
      (md5(tenant || ':credit')::uuid, tenant, 'stress-credit', 'liability', 'USD')
    ON CONFLICT (tenant_id, account_code, currency) DO NOTHING;
  END LOOP;
END;
$$;
SQL

running=0
for tenant_number in $(seq 1 "$TENANTS"); do
  tenant="stress-tenant-$tenant_number"
  for sequence in $(seq 1 "$TRANSACTIONS_PER_TENANT"); do
    psql -v ON_ERROR_STOP=1 -v tenant="$tenant" -v sequence="$sequence" -f "$TRANSACTION_SQL" >/dev/null &
    running=$((running + 1))
    if [ "$running" -ge "$MAX_CONCURRENCY" ]; then
      wait -n
      running=$((running - 1))
    fi
  done
done
wait

psql -v ON_ERROR_STOP=1 -v expected_tenants="$TENANTS" -v expected_per_tenant="$TRANSACTIONS_PER_TENANT" <<'SQL'
WITH expected AS (
  SELECT ('stress-tenant-' || n)::text AS tenant_id
  FROM generate_series(1, :'expected_tenants'::integer) AS n
), counts AS (
  SELECT tenant_id, COUNT(*) AS journal_count
  FROM ledger_journals
  WHERE tenant_id LIKE 'stress-tenant-%'
  GROUP BY tenant_id
), balances AS (
  SELECT tenant_id, journal_id,
         SUM(CASE direction WHEN 'D' THEN amount ELSE -amount END) AS net_amount,
         COUNT(*) AS posting_count
  FROM ledger_postings
  WHERE tenant_id LIKE 'stress-tenant-%'
  GROUP BY tenant_id, journal_id
), invalid AS (
  SELECT * FROM balances WHERE posting_count <> 2 OR net_amount <> 0
)
SELECT CASE WHEN (SELECT COUNT(*) FROM counts) = :'expected_tenants'::integer
                   AND NOT EXISTS (SELECT 1 FROM counts WHERE journal_count <> :'expected_per_tenant'::integer)
                   AND NOT EXISTS (SELECT 1 FROM invalid)
            THEN 'PASS'
            ELSE 'FAIL'
       END AS ledger_stress_result,
       (SELECT COUNT(*) FROM counts) AS tenants_observed,
       (SELECT COALESCE(SUM(journal_count), 0) FROM counts) AS journals_observed,
       (SELECT COUNT(*) FROM invalid) AS invalid_journals;
SQL
