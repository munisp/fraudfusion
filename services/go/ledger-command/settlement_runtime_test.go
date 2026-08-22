package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSettlementDispatchAndCallbackPostgresIntegration(t *testing.T) {
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
	tenant := "settlement-runtime-" + testID
	debit, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	credit, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO ledger_accounts (id,tenant_id,account_code,account_type,currency) VALUES ($1::uuid,$2,'dispatch-debit','asset','USD'),($3::uuid,$2,'dispatch-credit','liability','USD')`, debit, tenant, credit); err != nil {
		t.Fatal(err)
	}

	secret := []byte("01234567890123456789012345678901")
	var submissionCount atomic.Int32
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		submissionCount.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") == "" || r.Header.Get("X-FraudFusion-Signature") == "" || r.Header.Get("X-FraudFusion-Timestamp") == "" {
			http.Error(w, "missing settlement control headers", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer providerServer.Close()

	provider := &settlementProvider{name: "runtime-provider", submitURL: providerServer.URL, callbackKey: secret, httpClient: providerServer.Client(), maxAttempts: outboxMaxAttempts}
	dispatcher, err := newSettlementDispatcher(pool, provider)
	if err != nil {
		t.Fatal(err)
	}
	application := &service{db: pool, dispatcher: dispatcher}
	request := journalRequest{IdempotencyKey: "settlement-runtime-" + testID, JournalType: "settlement", DebitAccountID: debit, CreditAccountID: credit, Amount: "10.000000", Currency: "USD", ExternalRef: "runtime-integration", Settlement: &settlementInstruction{Provider: provider.name, ProviderReference: "provider-ref-" + testID, Direction: "outbound"}}
	principal := principal{TenantID: tenant, ActorID: "integration-actor", Roles: map[string]struct{}{"ledger:write": {}}}
	journal, err := application.postJournal(ctx, principal, request)
	if err != nil {
		t.Fatal(err)
	}
	if !journal.Created {
		t.Fatal("expected created journal")
	}
	if err = dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if submissionCount.Load() != 1 {
		t.Fatalf("expected one provider submission, got %d", submissionCount.Load())
	}

	var settlementID, outboxStatus, settlementStatus string
	if err = pool.QueryRow(ctx, `SELECT s.id::text,o.status,s.status FROM settlement_items s JOIN ledger_outbox o ON o.tenant_id=s.tenant_id AND o.journal_id=s.journal_id WHERE s.tenant_id=$1 AND s.journal_id=$2::uuid`, tenant, journal.JournalID).Scan(&settlementID, &outboxStatus, &settlementStatus); err != nil {
		t.Fatal(err)
	}
	if outboxStatus != "published" || settlementStatus != "submitted" {
		t.Fatalf("unexpected post-dispatch state outbox=%s settlement=%s", outboxStatus, settlementStatus)
	}

	accepted := providerCallback{TenantID: tenant, ProviderEventID: "accepted-" + testID, SettlementID: settlementID, ProviderReference: "provider-ref-" + testID, EventType: "accepted", OccurredAt: time.Now().UTC().Format(time.RFC3339)}
	acceptedPayload := mustJSON(t, accepted)
	result, err := dispatcher.applyCallback(ctx, accepted, acceptedPayload, time.Now().UTC())
	if err != nil || result.Status != "processed" {
		t.Fatalf("accepted callback failed: result=%+v err=%v", result, err)
	}
	settled := providerCallback{TenantID: tenant, ProviderEventID: "settled-" + testID, SettlementID: settlementID, ProviderReference: "provider-ref-" + testID, EventType: "settled", OccurredAt: time.Now().UTC().Format(time.RFC3339)}
	settledPayload := mustJSON(t, settled)
	result, err = dispatcher.applyCallback(ctx, settled, settledPayload, time.Now().UTC())
	if err != nil || result.Status != "processed" {
		t.Fatalf("settled callback failed: result=%+v err=%v", result, err)
	}
	result, err = dispatcher.applyCallback(ctx, settled, settledPayload, time.Now().UTC())
	if err != nil || result.Status != "replayed" {
		t.Fatalf("same callback replay should be harmless: result=%+v err=%v", result, err)
	}
	altered := settled
	altered.ProviderReference = "tampered-provider-reference"
	if _, err = dispatcher.applyCallback(ctx, altered, mustJSON(t, altered), time.Now().UTC()); err != errCallbackHashMismatch {
		t.Fatalf("expected callback payload tampering alert, got %v", err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM settlement_items WHERE tenant_id=$1 AND id=$2::uuid`, tenant, settlementID).Scan(&settlementStatus); err != nil {
		t.Fatal(err)
	}
	if settlementStatus != "settled" {
		t.Fatalf("tampered replay changed settlement state to %s", settlementStatus)
	}
	var alertCount int
	if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM provider_callback_alerts WHERE tenant_id=$1 AND provider=$2 AND alert_type='payload_hash_mismatch'`, tenant, provider.name).Scan(&alertCount); err != nil {
		t.Fatal(err)
	}
	if alertCount != 1 {
		t.Fatalf("expected one immutable tampering alert, got %d", alertCount)
	}
}

func TestVerifyProviderSignature(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	body := []byte(`{"settlement_id":"example"}`)
	timestamp := "1755853200"
	signature := signProviderPayload(key, timestamp, body)
	now := time.Unix(1755853200, 0).UTC()
	if !verifyProviderSignature(key, timestamp, signature, body, now) {
		t.Fatal("valid callback signature rejected")
	}
	if verifyProviderSignature(key, timestamp, signature, []byte(`{"settlement_id":"changed"}`), now) {
		t.Fatal("altered callback payload accepted")
	}
	if verifyProviderSignature(key, "1755850000", signature, body, now) {
		t.Fatal("stale callback accepted")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
