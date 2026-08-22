BEGIN;

-- Run after 20260822_double_entry_ledger_settlement_reconciliation.sql and
-- 20260822_chargeback_funds_flow_integrity.sql in an isolated test database.
INSERT INTO ledger_accounts (id, tenant_id, account_code, account_type, currency)
VALUES
 ('00000000-0000-0000-0000-000000000101', 'tenant-a', 'customer-available', 'liability', 'USD'),
 ('00000000-0000-0000-0000-000000000102', 'tenant-a', 'provider-clearing', 'clearing', 'USD');

INSERT INTO ledger_journals (id, tenant_id, idempotency_key, command_sha256, journal_type, actor_id)
VALUES ('00000000-0000-0000-0000-000000000201', 'tenant-a', 'payment-command-1', repeat('a', 64), 'settlement', 'actor-a');
INSERT INTO ledger_postings (id, tenant_id, journal_id, account_id, direction, amount, currency)
VALUES
 ('00000000-0000-0000-0000-000000000301', 'tenant-a', '00000000-0000-0000-0000-000000000201', '00000000-0000-0000-0000-000000000101', 'D', 100.00, 'USD'),
 ('00000000-0000-0000-0000-000000000302', 'tenant-a', '00000000-0000-0000-0000-000000000201', '00000000-0000-0000-0000-000000000102', 'C', 100.00, 'USD');
SET CONSTRAINTS ALL IMMEDIATE;

DO $$
BEGIN
    BEGIN
        UPDATE ledger_postings SET amount = 101.00 WHERE id = '00000000-0000-0000-0000-000000000301';
        RAISE EXCEPTION 'expected append-only posting mutation to fail';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%append-only%' THEN RAISE; END IF;
    END;

    BEGIN
        INSERT INTO ledger_journals (id, tenant_id, idempotency_key, command_sha256, journal_type, actor_id)
        VALUES ('00000000-0000-0000-0000-000000000202', 'tenant-a', 'payment-command-1', repeat('b', 64), 'settlement', 'actor-a');
        RAISE EXCEPTION 'expected tenant idempotency collision to fail';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO ledger_journals (id, tenant_id, idempotency_key, command_sha256, journal_type, actor_id)
        VALUES ('00000000-0000-0000-0000-000000000203', 'tenant-a', 'payment-command-unbalanced', repeat('c', 64), 'settlement', 'actor-a');
        INSERT INTO ledger_postings (id, tenant_id, journal_id, account_id, direction, amount, currency)
        VALUES ('00000000-0000-0000-0000-000000000303', 'tenant-a', '00000000-0000-0000-0000-000000000203', '00000000-0000-0000-0000-000000000101', 'D', 1.00, 'USD');
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'expected unbalanced journal to fail';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%requires at least two postings%' AND SQLERRM NOT LIKE '%not balanced%' THEN RAISE; END IF;
    END;
END;
$$;

INSERT INTO settlement_items (id, tenant_id, journal_id, provider, provider_reference, direction, amount, currency, status)
VALUES ('00000000-0000-0000-0000-000000000401', 'tenant-a', '00000000-0000-0000-0000-000000000201', 'test-provider', 'provider-ref-1', 'outbound', 100.00, 'USD', 'pending');
DO $$
BEGIN
    BEGIN
        UPDATE settlement_items SET status = 'settled' WHERE id = '00000000-0000-0000-0000-000000000401';
        RAISE EXCEPTION 'expected invalid pending-to-settled transition to fail';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%invalid settlement state transition%' THEN RAISE; END IF;
    END;
END;
$$;

INSERT INTO provider_settlement_events (id, tenant_id, provider, provider_event_id, settlement_id, payload_sha256, occurred_at)
VALUES ('00000000-0000-0000-0000-000000000501', 'tenant-a', 'test-provider', 'event-1', '00000000-0000-0000-0000-000000000401', repeat('d', 64), NOW());
DO $$
BEGIN
    BEGIN
        INSERT INTO provider_settlement_events (id, tenant_id, provider, provider_event_id, settlement_id, payload_sha256, occurred_at)
        VALUES ('00000000-0000-0000-0000-000000000502', 'tenant-a', 'test-provider', 'event-1', '00000000-0000-0000-0000-000000000401', repeat('e', 64), NOW());
        RAISE EXCEPTION 'expected duplicate provider event to fail';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
END;
$$;

INSERT INTO reconciliation_runs (id, tenant_id, provider, statement_sha256, statement_as_of, actor_id)
VALUES ('00000000-0000-0000-0000-000000000601', 'tenant-a', 'test-provider', repeat('f', 64), CURRENT_DATE, 'reconciler-a');
INSERT INTO reconciliation_breaks (id, tenant_id, reconciliation_run_id, settlement_id, severity, break_type, expected_payload, observed_payload)
VALUES ('00000000-0000-0000-0000-000000000701', 'tenant-a', '00000000-0000-0000-0000-000000000601', '00000000-0000-0000-0000-000000000401', 'high', 'amount_mismatch', '{"amount":"100.00","currency":"USD"}', '{"amount":"99.00","currency":"USD"}');

-- The chargeback migration must reject direct mutation of the captured amount.
INSERT INTO chargeback_transactions (tenant_id, transaction_id, customer_id, merchant_id, amount, currency)
VALUES ('tenant-a', 'txn-integrity-1', 'customer-a', 'merchant-a', 100.00, 'USD');
DO $$
BEGIN
    BEGIN
        UPDATE chargeback_transactions SET amount = 101.00 WHERE tenant_id = 'tenant-a' AND transaction_id = 'txn-integrity-1';
        RAISE EXCEPTION 'expected immutable chargeback amount mutation to fail';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%immutable%' THEN RAISE; END IF;
    END;
END;
$$;

ROLLBACK;
