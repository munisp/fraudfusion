\set ON_ERROR_STOP on
BEGIN;

DO $$
DECLARE close_id uuid := md5('close-test')::uuid;
        rejected boolean := false;
BEGIN
  INSERT INTO financial_close_periods (id, tenant_id, period_start, period_end, requested_by, approved_by, ledger_snapshot_sha256)
  VALUES (close_id, 'close-test-tenant', DATE '2026-08-01', DATE '2026-08-31', 'requester', 'requester', repeat('a',64));
  BEGIN
    UPDATE financial_close_periods SET status = 'review' WHERE id = close_id;
    UPDATE financial_close_periods SET status = 'closed' WHERE id = close_id;
  EXCEPTION WHEN others THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'financial close accepted same-person approval'; END IF;
  UPDATE financial_close_periods SET status = 'review' WHERE id = close_id;
  UPDATE financial_close_periods SET approved_by = 'approver', status = 'closed' WHERE id = close_id;
  IF (SELECT status FROM financial_close_periods WHERE id = close_id) <> 'closed' THEN RAISE EXCEPTION 'valid close did not complete'; END IF;
END;
$$;

DO $$
DECLARE journal_id uuid := md5('close-break-journal')::uuid;
        debit_id uuid := md5('close-break-debit')::uuid;
        credit_id uuid := md5('close-break-credit')::uuid;
        run_id uuid := md5('close-break-run')::uuid;
        close_id uuid := md5('close-break-period')::uuid;
        rejected boolean := false;
BEGIN
  INSERT INTO ledger_accounts (id, tenant_id, account_code, account_type, currency)
  VALUES (debit_id,'close-break-tenant','debit','asset','USD'),(credit_id,'close-break-tenant','credit','liability','USD');
  INSERT INTO ledger_journals (id,tenant_id,idempotency_key,command_sha256,journal_type,actor_id)
  VALUES (journal_id,'close-break-tenant','close-break',repeat('b',64),'settlement','verifier');
  INSERT INTO ledger_postings (id,tenant_id,journal_id,account_id,direction,amount,currency)
  VALUES (md5('close-break-posting-d')::uuid,'close-break-tenant',journal_id,debit_id,'D',1,'USD'),(md5('close-break-posting-c')::uuid,'close-break-tenant',journal_id,credit_id,'C',1,'USD');
  INSERT INTO reconciliation_runs (id,tenant_id,provider,statement_as_of,statement_sha256,actor_id,completed_at)
  VALUES (run_id,'close-break-tenant','simulator',DATE '2026-08-15',repeat('c',64),'verifier',NOW());
  INSERT INTO reconciliation_breaks (id,tenant_id,reconciliation_run_id,break_type,severity,status,expected_payload,observed_payload)
  VALUES (md5('close-break')::uuid,'close-break-tenant',run_id,'amount_mismatch','critical','open','{}'::jsonb,'{}'::jsonb);
  INSERT INTO financial_close_periods (id,tenant_id,period_start,period_end,requested_by,approved_by,ledger_snapshot_sha256)
  VALUES (close_id,'close-break-tenant',DATE '2026-08-01',DATE '2026-08-31','requester','approver',repeat('d',64));
  BEGIN
    UPDATE financial_close_periods SET status='review' WHERE id=close_id;
    UPDATE financial_close_periods SET status='closed' WHERE id=close_id;
  EXCEPTION WHEN others THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'financial close accepted unresolved critical break'; END IF;
END;
$$;

ROLLBACK;
