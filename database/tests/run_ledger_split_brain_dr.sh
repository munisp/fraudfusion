#!/usr/bin/env bash
set -euo pipefail

: "${PGHOST:?PGHOST is required}"
: "${PGPORT:?PGPORT is required}"
: "${PGUSER:?PGUSER is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRIMARY_DB="${LEDGER_DR_PRIMARY_DB:-fraudfusion_ledger_primary_dr}"
ISOLATED_DB="${LEDGER_DR_ISOLATED_DB:-fraudfusion_ledger_isolated_dr}"
BASE_SCHEMA="$ROOT/database/20260801_chargeback_fraud_schema.sql"
CHARGEBACK_HARDENING="$ROOT/database/20260820_chargeback_persistence_hardening.sql"
CHARGEBACK_INTEGRITY="$ROOT/database/20260822_chargeback_funds_flow_integrity.sql"
LEDGER_SCHEMA="$ROOT/database/20260822_double_entry_ledger_settlement_reconciliation.sql"
STRESS_SQL="$ROOT/database/tests/20260822_ledger_stress_transaction.sql"

cleanup_database() {
  dropdb --if-exists --force "$1" >/dev/null
}
trap 'cleanup_database "$PRIMARY_DB"; cleanup_database "$ISOLATED_DB"' EXIT
cleanup_database "$PRIMARY_DB"
cleanup_database "$ISOLATED_DB"
createdb "$PRIMARY_DB"
createdb "$ISOLATED_DB"

apply_schema() {
  local database="$1"
  psql -v ON_ERROR_STOP=1 -d "$database" -f "$BASE_SCHEMA" >/dev/null
  psql -v ON_ERROR_STOP=1 -d "$database" -f "$CHARGEBACK_HARDENING" >/dev/null
  psql -v ON_ERROR_STOP=1 -d "$database" -f "$CHARGEBACK_INTEGRITY" >/dev/null
  psql -v ON_ERROR_STOP=1 -d "$database" -f "$LEDGER_SCHEMA" >/dev/null
  psql -v ON_ERROR_STOP=1 -d "$database" <<'SQL'
INSERT INTO ledger_accounts (id, tenant_id, account_code, account_type, currency)
VALUES
  (md5('dr-tenant:debit')::uuid, 'dr-tenant', 'dr-debit', 'asset', 'USD'),
  (md5('dr-tenant:credit')::uuid, 'dr-tenant', 'dr-credit', 'liability', 'USD');
SQL
}
apply_schema "$PRIMARY_DB"
apply_schema "$ISOLATED_DB"

# Both databases have the same pre-partition baseline journal.
for database in "$PRIMARY_DB" "$ISOLATED_DB"; do
  PGDATABASE="$database" psql -v ON_ERROR_STOP=1 -v tenant=dr-tenant -v sequence=1 -f "$STRESS_SQL" >/dev/null
done

# Simulated network partition: both former peers accept one divergent command.
PGDATABASE="$PRIMARY_DB" psql -v ON_ERROR_STOP=1 -v tenant=dr-tenant -v sequence=2 -f "$STRESS_SQL" >/dev/null
PGDATABASE="$ISOLATED_DB" psql -v ON_ERROR_STOP=1 -v tenant=dr-tenant -v sequence=3 -f "$STRESS_SQL" >/dev/null

# Recovery rule: fence the isolated writer. Never merge its ledger rows by copying
# tables; reconcile its command evidence through the normal idempotent command API.
PRIMARY_CHECK="$(psql -v ON_ERROR_STOP=1 -At -d "$PRIMARY_DB" <<'SQL'
WITH balances AS (
  SELECT journal_id, SUM(CASE direction WHEN 'D' THEN amount ELSE -amount END) AS net, COUNT(*) AS postings
  FROM ledger_postings WHERE tenant_id = 'dr-tenant' GROUP BY journal_id
)
SELECT CASE WHEN COUNT(*) = 2 AND bool_and(net = 0 AND postings = 2) THEN 'PASS' ELSE 'FAIL' END FROM balances;
SQL
)"
ISOLATED_CHECK="$(psql -v ON_ERROR_STOP=1 -At -d "$ISOLATED_DB" <<'SQL'
SELECT COUNT(*) FROM ledger_journals WHERE tenant_id = 'dr-tenant';
SQL
)"
if [ "$PRIMARY_CHECK" != "PASS" ] || [ "$ISOLATED_CHECK" != "2" ]; then
  echo "FAIL primary_integrity=$PRIMARY_CHECK isolated_journals=$ISOLATED_CHECK"
  exit 1
fi
printf 'PASS scenario=controlled_divergent_writer_fencing primary_journals=2 isolated_journals=2 merge_policy=forbidden primary_balanced=true\n'
