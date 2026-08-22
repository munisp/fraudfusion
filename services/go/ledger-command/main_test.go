package main

import (
	"context"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidAmount(t *testing.T) {
	for _, value := range []string{"1", "0.000001", "100.123456"} {
		if !validAmount(value) {
			t.Fatalf("expected valid amount %q", value)
		}
	}
	for _, value := range []string{"0", "00", "0.000000", "-1", "1.1234567", "1e3"} {
		if validAmount(value) {
			t.Fatalf("expected invalid amount %q", value)
		}
	}
}

func TestRandomUUID(t *testing.T) {
	id, err := randomUUID()
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
		t.Fatalf("invalid UUID %q: %v", id, err)
	}
}

func TestPostJournalPostgresIntegration(t *testing.T) {
	databaseURL := os.Getenv("LEDGER_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LEDGER_INTEGRATION_DATABASE_URL not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tenant := "ledger-command-test"
	debit := "11111111-1111-4111-8111-111111111111"
	credit := "22222222-2222-4222-8222-222222222222"
	_, err = pool.Exec(ctx, `INSERT INTO ledger_accounts (id,tenant_id,account_code,account_type,currency) VALUES ($1::uuid,$2,'test-debit','asset','USD'),($3::uuid,$2,'test-credit','liability','USD') ON CONFLICT (tenant_id,account_code,currency) DO NOTHING`, debit, tenant, credit)
	if err != nil {
		t.Fatal(err)
	}
	application := &service{db: pool}
	testID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	request := journalRequest{IdempotencyKey: "post-journal-test-" + testID, JournalType: "settlement", DebitAccountID: debit, CreditAccountID: credit, Amount: "12.500000", Currency: "USD", ExternalRef: "integration-test", Settlement: &settlementInstruction{Provider: "simulator", ProviderReference: "provider-test-" + testID, Direction: "outbound"}}
	principal := principal{TenantID: tenant, ActorID: "service-test", Roles: map[string]struct{}{"ledger:write": {}}}
	first, err := application.postJournal(ctx, principal, request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created {
		t.Fatal("first journal post should create a record")
	}
	second, err := application.postJournal(ctx, principal, request)
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || second.JournalID != first.JournalID {
		t.Fatal("idempotent retry should return original journal")
	}
	request.Amount = "13.000000"
	if _, err = application.postJournal(ctx, principal, request); err != errIdempotencyConflict {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}

	var net string
	var outboxCount int
	if err = pool.QueryRow(ctx, `SELECT SUM(CASE direction WHEN 'D' THEN amount ELSE -amount END)::text FROM ledger_postings WHERE tenant_id=$1 AND journal_id=$2::uuid`, tenant, first.JournalID).Scan(&net); err != nil {
		t.Fatal(err)
	}
	if net != "0.000000" {
		t.Fatalf("journal is not balanced: %s", net)
	}
	if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM ledger_outbox WHERE tenant_id=$1 AND journal_id=$2::uuid`, tenant, first.JournalID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("expected one durable outbox row, got %d", outboxCount)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM ledger_postings WHERE tenant_id=$1 AND journal_id=$2::uuid`, tenant, first.JournalID)
	_, _ = pool.Exec(ctx, `DELETE FROM ledger_outbox WHERE tenant_id=$1 AND journal_id=$2::uuid`, tenant, first.JournalID)
	_, _ = pool.Exec(ctx, `DELETE FROM settlement_items WHERE tenant_id=$1 AND journal_id=$2::uuid`, tenant, first.JournalID)
	_, _ = pool.Exec(ctx, `DELETE FROM ledger_journals WHERE tenant_id=$1 AND id=$2::uuid`, tenant, first.JournalID)
	_ = pgx.ErrNoRows
}
