package main

import (
	"context"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestResolveCurrencyLegs(t *testing.T) {
	base := journalRequest{DebitAccountID: "d", CreditAccountID: "c", Amount: "100.000000", Currency: "NGN"}

	// Same currency: no fx leg.
	fx, err := resolveCurrencyLegs(base, "NGN", "NGN")
	if err != nil || fx != nil {
		t.Fatalf("same-currency should be fx-free, got %+v, %v", fx, err)
	}

	// Cross-currency without quote: rejected (422 upstream).
	if _, err := resolveCurrencyLegs(base, "NGN", "USD"); !errors.Is(err, errCrossCurrency) {
		t.Fatalf("cross-currency without quote must fail, got %v", err)
	}
	withRate := base
	withRate.FxRate = "0.00066"
	// Missing quote id still rejected.
	if _, err := resolveCurrencyLegs(withRate, "NGN", "USD"); !errors.Is(err, errCrossCurrency) {
		t.Fatalf("fx_rate without fx_quote_id must fail, got %v", err)
	}
	withRate.FxQuoteID = "quote-123"
	fx, err = resolveCurrencyLegs(withRate, "NGN", "USD")
	if err != nil || fx == nil {
		t.Fatalf("quoted cross-currency should pass, got %v", err)
	}
	if fx.creditCurrency != "USD" || fx.creditAmount != "0.066000" {
		t.Fatalf("credit leg = %s %s, want 0.066000 USD", fx.creditAmount, fx.creditCurrency)
	}

	// Debit account currency mismatch is never convertible by us.
	if _, err := resolveCurrencyLegs(base, "EUR", "EUR"); !errors.Is(err, errJournalCurrency) {
		t.Fatalf("debit currency mismatch must fail, got %v", err)
	}

	// Bad currency code.
	bad := base
	bad.Currency = "ngn"
	if _, err := resolveCurrencyLegs(bad, "ngn", "ngn"); !errors.Is(err, errJournalCurrency) {
		t.Fatalf("lowercase currency must fail, got %v", err)
	}
}

func TestRatToFixed6(t *testing.T) {
	cases := map[string]string{
		"100/1":    "100.000000",
		"1/3":      "0.333333",
		"2/3":      "0.666667", // half-up
		"1/2000000": "0.000001", // 0.5e-6 rounds up
	}
	for in, want := range cases {
		r, _ := new(big.Rat).SetString(in)
		if got := ratToFixed6(r); got != want {
			t.Fatalf("ratToFixed6(%s) = %s, want %s", in, got, want)
		}
	}
}

// TestReversalStateMachinePostgres is the regression test for the reversal
// status trap: only posted -> reversed is allowed; reversing an
// already-reversed journal or a reversal itself is rejected; the DB trigger
// blocks any other status mutation.
func TestReversalStateMachinePostgres(t *testing.T) {
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

	tenant := "ledger-reversal-test"
	debit := "33333333-3333-4333-8333-333333333333"
	credit := "44444444-4444-4444-8444-444444444444"
	if _, err = pool.Exec(ctx, `INSERT INTO ledger_accounts (id,tenant_id,account_code,account_type,currency) VALUES ($1::uuid,$2,'rev-debit','asset','USD'),($3::uuid,$2,'rev-credit','liability','USD') ON CONFLICT (tenant_id,account_code,currency) DO NOTHING`, debit, tenant, credit); err != nil {
		t.Fatal(err)
	}
	application := &service{db: pool}
	p := principal{TenantID: tenant, ActorID: "reversal-test", Roles: map[string]struct{}{"ledger:write": {}}}
	testID, _ := randomUUID()

	posted, err := application.postJournal(ctx, p, journalRequest{IdempotencyKey: "rev-test-" + testID, JournalType: "capture", DebitAccountID: debit, CreditAccountID: credit, Amount: "5.000000", Currency: "USD"})
	if err != nil {
		t.Fatal(err)
	}

	// posted -> reversed succeeds.
	reversal, err := application.postReversal(ctx, p, posted.JournalID, "rev-of-"+testID)
	if err != nil || !reversal.Created {
		t.Fatalf("first reversal should succeed: %+v, %v", reversal, err)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM ledger_journals WHERE tenant_id=$1 AND id=$2::uuid`, tenant, posted.JournalID).Scan(&status); err != nil || status != "reversed" {
		t.Fatalf("target status = %q, %v; want reversed", status, err)
	}

	// Idempotent replay returns the same reversal journal.
	replay, err := application.postReversal(ctx, p, posted.JournalID, "rev-of-"+testID)
	if err != nil || replay.Created || replay.JournalID != reversal.JournalID {
		t.Fatalf("idempotent replay = %+v, %v", replay, err)
	}

	// Reversing an already-reversed journal (new idempotency key) is 409.
	if _, err := application.postReversal(ctx, p, posted.JournalID, "rev-again-"+testID); !errors.Is(err, errJournalNotReversible) {
		t.Fatalf("reversing a reversed journal must be rejected, got %v", err)
	}

	// Reversing a reversal journal is 409.
	if _, err := application.postReversal(ctx, p, reversal.JournalID, "rev-rev-"+testID); !errors.Is(err, errJournalNotReversible) {
		t.Fatalf("reversing a reversal must be rejected, got %v", err)
	}

	// DB-level state machine: any status mutation other than posted->reversed
	// is rejected by the trigger.
	if _, err := pool.Exec(ctx, `UPDATE ledger_journals SET status='reversed' WHERE tenant_id=$1 AND id=$2::uuid`, tenant, posted.JournalID); err == nil {
		t.Fatal("re-transition of reversed journal must be blocked by DB trigger")
	}
	// Balanced: reversal postings net the original to zero per currency.
	var net string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(SUM(CASE p.direction WHEN 'D' THEN p.amount ELSE -p.amount END),0)::text FROM ledger_postings p WHERE p.tenant_id=$1 AND p.journal_id IN ($2::uuid,$3::uuid)`, tenant, posted.JournalID, reversal.JournalID).Scan(&net); err != nil {
		t.Fatal(err)
	}
	if net != "0.000000" {
		t.Fatalf("original + reversal must net to zero, got %s", net)
	}
}
