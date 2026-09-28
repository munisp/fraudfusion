package mlclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/munisp/fraudfusion/services/go/authcommon"
)

func TestBreakerOpensAndFailsFast(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	// 5 failed scoring calls (2 HTTP attempts each) open the breaker.
	for i := 0; i < 5; i++ {
		if _, err := client.AnalyzeTransaction(context.Background(), &TransactionRequest{}); err == nil {
			t.Fatalf("call %d should fail", i)
		}
	}
	if client.BreakerState() != authcommon.BreakerOpen {
		t.Fatalf("breaker state = %s, want open", client.BreakerState())
	}
	callsBefore := calls
	// Open breaker: fail fast, no HTTP attempts.
	_, err = client.AnalyzeTransaction(context.Background(), &TransactionRequest{})
	if !errors.Is(err, authcommon.ErrBreakerOpen) {
		t.Fatalf("expected ErrBreakerOpen, got %v", err)
	}
	if calls != callsBefore {
		t.Fatalf("open breaker must not hit the dependency: %d -> %d", callsBefore, calls)
	}
}

func TestNewClientDefaultsToRouter(t *testing.T) {
	client, err := NewClient("")
	if err != nil {
		t.Fatal(err)
	}
	if client.BaseURL() != "http://localhost:8200" {
		t.Fatalf("default base URL = %s, want router :8200", client.BaseURL())
	}
}
