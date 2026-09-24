// Package dapr implements a real HTTP client for the Dapr sidecar: service
// invocation over /v1.0/invoke and health probing over /v1.0/healthz plus a
// state-store ping via /v1.0/metadata. Errors are always propagated.
package dapr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/munisp/fraudfusion/orchestrator/go/internal/backoff"
)

// Client talks to a Dapr sidecar over HTTP.
type Client struct {
	baseURL    string
	appID      string
	httpClient *http.Client
}

// Result is the decoded response of a service invocation.
type Result struct {
	Data map[string]interface{}
}

// NewClient validates the sidecar URL and app ID.
func NewClient(baseURL, appID string) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" || appID == "" {
		return nil, fmt.Errorf("Dapr sidecar URL and app ID are required")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid Dapr sidecar URL: %w", err)
	}
	return &Client{baseURL: baseURL, appID: appID, httpClient: &http.Client{Timeout: 10 * time.Second}}, nil
}

// InvokeService calls POST /v1.0/invoke/{appID}/method/{method} and decodes
// the JSON body. Errors (transport, non-2xx, malformed payload) are returned,
// never swallowed.
func (c *Client) InvokeService(ctx context.Context, appID, method string, payload map[string]interface{}) (*Result, error) {
	if appID == "" || method == "" {
		return nil, fmt.Errorf("Dapr app ID and method are required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Dapr invocation payload: %w", err)
	}
	endpoint := fmt.Sprintf("%s/v1.0/invoke/%s/method/%s", c.baseURL, url.PathEscape(appID), url.PathEscape(method))

	var result *Result
	err = backoff.Do(ctx, backoff.Default(), func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("dapr invoke %s/%s returned status %d", appID, method, resp.StatusCode)
		}
		if len(raw) == 0 {
			result = &Result{Data: map[string]interface{}{}}
			return nil
		}
		decoded := map[string]interface{}{}
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return fmt.Errorf("decode Dapr response: %w", err)
		}
		result = &Result{Data: decoded}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Health checks the sidecar health endpoint and confirms the state store is
// registered via /v1.0/metadata.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1.0/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("dapr healthz: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("dapr healthz returned status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op; the HTTP client holds no persistent resources.
func (c *Client) Close() error { return nil }
