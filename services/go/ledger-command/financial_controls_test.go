package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReconciliationAndFinancialClosePostgresIntegration(t *testing.T) {
	databaseURL := os.Getenv("LEDGER_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LEDGER_INTEGRATION_DATABASE_URL not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	testID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	tenant := "finance-control-" + testID
	debit, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	credit, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO ledger_accounts (id,tenant_id,account_code,account_type,currency) VALUES ($1::uuid,$2,'close-debit','asset','USD'),($3::uuid,$2,'close-credit','liability','USD')`, debit, tenant, credit); err != nil {
		t.Fatal(err)
	}

	provider := &settlementProvider{name: "reconciliation-provider", callbackKey: []byte("01234567890123456789012345678901"), maxAttempts: outboxMaxAttempts}
	dispatcher, err := newSettlementDispatcher(pool, provider)
	if err != nil {
		t.Fatal(err)
	}
	application := &service{db: pool, dispatcher: dispatcher}
	writer := principal{TenantID: tenant, ActorID: "ledger-writer", Roles: map[string]struct{}{"ledger:write": {}}}
	journal, err := application.postJournal(ctx, writer, journalRequest{IdempotencyKey: "close-control-" + testID, JournalType: "settlement", DebitAccountID: debit, CreditAccountID: credit, Amount: "10.000000", Currency: "USD", ExternalRef: "close-control", Settlement: &settlementInstruction{Provider: provider.name, ProviderReference: "close-ref-" + testID, Direction: "outbound"}})
	if err != nil {
		t.Fatal(err)
	}
	var settlementID string
	if err = pool.QueryRow(ctx, `SELECT id::text FROM settlement_items WHERE tenant_id=$1 AND journal_id=$2::uuid`, tenant, journal.JournalID).Scan(&settlementID); err != nil {
		t.Fatal(err)
	}
	invalidAccepted := providerCallback{TenantID: tenant, ProviderEventID: "close-invalid-" + testID, SettlementID: settlementID, ProviderReference: "close-ref-" + testID, EventType: "accepted", OccurredAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err = dispatcher.applyCallback(ctx, invalidAccepted, mustJSON(t, invalidAccepted), time.Now().UTC()); err == nil {
		t.Fatal("accepted callback should not bypass pending-to-submitted state")
	}
	if _, err = pool.Exec(ctx, `UPDATE settlement_items SET status='submitted' WHERE tenant_id=$1 AND id=$2::uuid`, tenant, settlementID); err != nil {
		t.Fatal(err)
	}
	accepted := providerCallback{TenantID: tenant, ProviderEventID: "close-accepted-" + testID, SettlementID: settlementID, ProviderReference: "close-ref-" + testID, EventType: "accepted", OccurredAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err = dispatcher.applyCallback(ctx, accepted, mustJSON(t, accepted), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	reconciler := principal{TenantID: tenant, ActorID: "reconciliation-maker", Roles: map[string]struct{}{"finance:reconcile": {}}}
	statement := reconciliationRequest{Provider: provider.name, StatementAsOf: time.Now().UTC().Format("2006-01-02"), Entries: []providerStatementEntry{{ProviderReference: "close-ref-" + testID, Amount: "9.000000", Currency: "USD", Status: "accepted", OccurredAt: time.Now().UTC().Format(time.RFC3339)}}}
	response, err := application.reconcile(ctx, reconciler, statement, time.Now().UTC(), mustJSON(t, statement))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Created || response.BreakCount != 1 || response.Matched != 1 {
		t.Fatalf("unexpected reconciliation result: %+v", response)
	}

	period := time.Now().UTC()
	requester := principal{TenantID: tenant, ActorID: "close-requester", Roles: map[string]struct{}{"finance:close_request": {}}}
	close, err := application.openFinancialClose(ctx, requester, period, period)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = application.moveCloseToReview(ctx, requester, close.CloseID); err != nil {
		t.Fatal(err)
	}
	approver := principal{TenantID: tenant, ActorID: "close-approver", Roles: map[string]struct{}{"finance:close_approve": {}}}
	if _, err = application.approveClose(ctx, approver, close.CloseID); err == nil {
		t.Fatal("close approval succeeded despite unresolved critical reconciliation break")
	}

	var breakID string
	if err = pool.QueryRow(ctx, `SELECT id::text FROM reconciliation_breaks WHERE tenant_id=$1 AND reconciliation_run_id=$2::uuid AND break_type='amount_mismatch'`, tenant, response.RunID).Scan(&breakID); err != nil {
		t.Fatal(err)
	}
	resolver := principal{TenantID: tenant, ActorID: "independent-resolver", Roles: map[string]struct{}{"finance:reconcile": {}}}
	commandTag, err := pool.Exec(ctx, `UPDATE reconciliation_breaks rb SET status='resolved',resolved_at=NOW(),resolver_id=$3,resolved_by=$3,resolution_reason=$4 FROM reconciliation_runs rr WHERE rb.tenant_id=$1 AND rb.id=$2::uuid AND rr.tenant_id=rb.tenant_id AND rr.id=rb.reconciliation_run_id AND rr.actor_id <> $3 AND rb.status IN ('open','investigating')`, resolver.TenantID, breakID, resolver.ActorID, "provider statement corrected after independent review")
	if err != nil || commandTag.RowsAffected() != 1 {
		t.Fatalf("independent break resolution failed: rows=%d err=%v", commandTag.RowsAffected(), err)
	}
	closed, err := application.approveClose(ctx, approver, close.CloseID)
	if err != nil || closed.Status != "closed" {
		t.Fatalf("close should succeed after break resolution: result=%+v err=%v", closed, err)
	}

	admin := principal{TenantID: tenant, ActorID: "close-admin", Roles: map[string]struct{}{"finance:close_admin": {}}}
	if err = reopenCloseForTest(ctx, application, admin, close.CloseID, "restatement required after provider correction"); err != nil {
		t.Fatal(err)
	}
	var closeStatus string
	if err = pool.QueryRow(ctx, `SELECT status FROM financial_close_periods WHERE tenant_id=$1 AND id=$2::uuid`, tenant, close.CloseID).Scan(&closeStatus); err != nil {
		t.Fatal(err)
	}
	if closeStatus != "reopened" {
		t.Fatalf("unexpected close status after reopen: %s", closeStatus)
	}
	var auditEvents int
	if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM financial_close_events WHERE tenant_id=$1 AND close_id=$2::uuid`, tenant, close.CloseID).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if auditEvents != 3 {
		t.Fatalf("expected requested, approved, and reopened audit events; got %d", auditEvents)
	}
}

func reopenCloseForTest(ctx context.Context, application *service, actor principal, closeID, reason string) error {
	tx, err := application.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	commandTag, err := tx.Exec(ctx, `UPDATE financial_close_periods SET status='reopened',reopened_by=$3,reopen_reason=$4 WHERE tenant_id=$1 AND id=$2::uuid AND status='closed'`, actor.TenantID, closeID, actor.ActorID, reason)
	if err != nil || commandTag.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return errors.New("close not eligible for reopening")
	}
	if err = insertCloseEvent(ctx, tx, actor.TenantID, closeID, "reopened", actor.ActorID, map[string]string{"reason": reason}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
