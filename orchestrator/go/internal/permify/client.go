package permify

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
)

// Client calls the Permify REST permission-check endpoint.
type Client struct {
	apiURL     string
	apiKey     string
	httpClient *http.Client
}

func NewClient(apiURL, apiKey string) (*Client, error) {
	apiURL = strings.TrimRight(apiURL, "/")
	if apiURL == "" {
		return nil, fmt.Errorf("Permify API URL is required")
	}
	if _, err := url.ParseRequestURI(apiURL); err != nil {
		return nil, fmt.Errorf("invalid Permify API URL: %w", err)
	}
	return &Client{apiURL: apiURL, apiKey: apiKey, httpClient: &http.Client{Timeout: 5 * time.Second}}, nil
}

// CheckPermission evaluates a real Permify relationship-based authorization decision.
// The API client fails closed: a transport failure, non-200 status, malformed response,
// or anything except CHECK_RESULT_ALLOWED returns an error or false.
func (c *Client) CheckPermission(ctx context.Context, tenantID, userID, resourceID, action string) (bool, error) {
	if tenantID == "" || userID == "" || resourceID == "" || action == "" {
		return false, fmt.Errorf("tenant, user, resource, and action are required")
	}

	payload := map[string]interface{}{
		"metadata": map[string]interface{}{
			"snap_token":     "",
			"schema_version": "",
			"depth":          20,
		},
		"entity": map[string]string{
			"type": "journey",
			"id":   resourceID,
		},
		"permission": action,
		"subject": map[string]string{
			"type":     "user",
			"id":       userID,
			"relation": "",
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("encode Permify permission request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/tenants/%s/permissions/check", c.apiURL, url.PathEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return false, fmt.Errorf("create Permify permission request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("call Permify permission check: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, fmt.Errorf("read Permify permission response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Permify permission check returned status %d", resp.StatusCode)
	}

	var response struct {
		Can string `json:"can"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("decode Permify permission response: %w", err)
	}
	return response.Can == "CHECK_RESULT_ALLOWED" || response.Can == "RESULT_ALLOWED", nil
}

func (c *Client) Close() error { return nil }
