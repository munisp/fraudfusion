package workflows

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Environment variables configuring the downstream services the journey
// activities call. When a variable is unset the corresponding activity fails
// loudly (Temporal retries, then the workflow fails) — no journey fabricates
// claimants, court cases, professionals, or bookings.
const (
	// LandVerificationURLEnv points at the land-verification-service base URL.
	LandVerificationURLEnv = "LAND_VERIFICATION_URL"
	// BookingServiceURLEnv points at the booking service base URL.
	BookingServiceURLEnv = "BOOKING_SERVICE_URL"
	// NotificationServiceURLEnv points at the notification service base URL.
	NotificationServiceURLEnv = "NOTIFICATION_SERVICE_URL"
)

// activityHTTPTimeout bounds a single downstream HTTP attempt; Temporal's
// activity retry policy (configured on the workflow) provides the retries.
const activityHTTPTimeout = 10 * time.Second

// serviceHTTPClient is shared across activities; it only carries a timeout.
var serviceHTTPClient = &http.Client{Timeout: activityHTTPTimeout}

// serviceBaseURL resolves and validates a service base URL from the
// environment. A missing or malformed URL is an error so callers fail closed.
func serviceBaseURL(envKey string) (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv(envKey)), "/")
	if baseURL == "" {
		return "", fmt.Errorf("%s must be configured", envKey)
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return "", fmt.Errorf("invalid %s: %w", envKey, err)
	}
	return baseURL, nil
}

// callServiceJSON POSTs payload to {baseURL}{path} and decodes the JSON
// response body into out. Transport failures, non-2xx statuses, and malformed
// payloads are returned as errors; nothing is fabricated locally.
func callServiceJSON(ctx context.Context, envKey, path string, payload interface{}, out interface{}) error {
	baseURL, err := serviceBaseURL(envKey)
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request for %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request for %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := serviceHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read %s response: %w", path, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%s returned status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(respBody[:min(len(respBody), 256)])))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
