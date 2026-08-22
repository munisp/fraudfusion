package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func FuzzIngestHandlerMalformedPayloads(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	validBody := `{"event":"ci_gate","gate":"go-race","result":"success","run_id":"fuzz-run-0001"}`
	validTimestamp := time.Now().UTC().Format(time.RFC3339)
	f.Add("application/json", validTimestamp, validBody, "current", "")
	f.Add("text/plain", "not-a-time", "{", "unknown", "not-hex")
	f.Add("application/json; charset=utf-8", validTimestamp, strings.Repeat("x", maxRequestBytes+1), "current", "")

	f.Fuzz(func(t *testing.T, contentType, timestamp, body, keyID, suppliedSignature string) {
		if len(body) > maxRequestBytes+1 {
			body = body[:maxRequestBytes+1]
		}
		if len(contentType) > 256 {
			contentType = contentType[:256]
		}
		if len(timestamp) > 256 {
			timestamp = timestamp[:256]
		}
		if len(keyID) > 128 {
			keyID = keyID[:128]
		}
		if len(suppliedSignature) > 256 {
			suppliedSignature = suppliedSignature[:256]
		}

		store := newTestStore()
		handler := store.ingestHandler(keyring{"current": key})
		request := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		request.Header.Set("X-FraudFusion-Timestamp", timestamp)
		request.Header.Set("X-FraudFusion-Key-ID", keyID)
		if suppliedSignature == "" && timestamp != "" {
			request.Header.Set("X-FraudFusion-Signature", signatureForTest(key, keyID, timestamp, body))
		} else {
			request.Header.Set("X-FraudFusion-Signature", suppliedSignature)
		}
		response := httptest.NewRecorder()
		handler(response, request)
		if response.Code < http.StatusOK || response.Code > http.StatusServiceUnavailable {
			t.Fatalf("unexpected status %d", response.Code)
		}
	})
}
