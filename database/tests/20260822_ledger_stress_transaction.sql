\set ON_ERROR_STOP on
BEGIN;

WITH ids AS (
    SELECT md5(:'tenant' || ':journal:' || :'sequence')::uuid AS journal_id,
           md5(:'tenant' || ':debit')::uuid AS debit_account_id,
           md5(:'tenant' || ':credit')::uuid AS credit_account_id
)
INSERT INTO ledger_journals (id, tenant_id, idempotency_key, command_sha256, journal_type, actor_id, external_reference)
SELECT journal_id,
       :'tenant',
       'stress-' || :'sequence',
       md5(:'tenant' || ':command:' || :'sequence') || md5(:'tenant' || ':command:' || :'sequence'),
       'settlement',
       'stress-runner',
       'stress-reference-' || :'sequence'
FROM ids;

WITH ids AS (
    SELECT md5(:'tenant' || ':journal:' || :'sequence')::uuid AS journal_id,
           md5(:'tenant' || ':debit')::uuid AS debit_account_id,
           md5(:'tenant' || ':credit')::uuid AS credit_account_id
), amount AS (
    SELECT ((:'sequence'::int % 97) + 1)::numeric(20,6) AS value
)
INSERT INTO ledger_postings (id, tenant_id, journal_id, account_id, direction, amount, currency)
SELECT md5(:'tenant' || ':posting-debit:' || :'sequence')::uuid,
       :'tenant', journal_id, debit_account_id, 'D', value, 'USD'
FROM ids, amount
UNION ALL
SELECT md5(:'tenant' || ':posting-credit:' || :'sequence')::uuid,
       :'tenant', journal_id, credit_account_id, 'C', value, 'USD'
FROM ids, amount;

COMMIT;
