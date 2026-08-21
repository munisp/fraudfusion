package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestHMACIngestionHighConcurrencyUniqueAndReplay(t *testing.T) {
	const uniqueRequests = 500
	const replayRequests = 500

	key := []byte("0123456789abcdef0123456789abcdef")
	store := newTestStore()
	handler := store.ingestHandler(keyring{"current": key})
	timestamp := time.Now().UTC().Format(time.RFC3339)

	type workItem struct {
		body string
		kind string
	}
	work := make(chan workItem, uniqueRequests+replayRequests)
	for i := 0; i < uniqueRequests; i++ {
		work <- workItem{
			kind: "unique",
			body: fmt.Sprintf(`{"event":"ci_gate","gate":"dependency-security","result":"failure","run_id":"load-unique-%04d"}`, i),
		}
	}
	replayBody := `{"event":"e2e_scenario","scenario":"kyc-session-create","result":"success","run_id":"load-replay-0001"}`
	for i := 0; i < replayRequests; i++ {
		work <- workItem{kind: "replay", body: replayBody}
	}
	close(work)

	var workers sync.WaitGroup
	errs := make(chan error, uniqueRequests+replayRequests)
	for worker := 0; worker < 64; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range work {
				response := httptest.NewRecorder()
				handler(response, signedRequest(t, key, "current", timestamp, item.body, "application/json"))
				if response.Code != http.StatusAccepted {
					errs <- fmt.Errorf("%s request returned %d", item.kind, response.Code)
				}
			}
		}()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	if got := store.releaseGateFailure["dependency-security"]; got != uniqueRequests {
		t.Fatalf("expected %d unique failure events, got %d", uniqueRequests, got)
	}
	if got := store.e2eScenario["kyc-session-create"]["success"]; got != 1 {
		t.Fatalf("expected exactly one replay-safe E2E event, got %d", got)
	}
	if got := len(store.seenEvents); got != uniqueRequests+1 {
		t.Fatalf("expected %d replay-cache entries, got %d", uniqueRequests+1, got)
	}
}
