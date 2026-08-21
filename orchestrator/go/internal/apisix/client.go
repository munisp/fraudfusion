package apisix

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

// Client manages routes through the APISIX Admin API.
type Client struct {
	adminURL   string
	apiKey     string
	httpClient *http.Client
}

// Route is the minimum route definition needed for a gateway route upsert.
type Route struct {
	ID          string
	URI         string
	Methods     []string
	UpstreamURL string
}

func NewClient(adminURL, apiKey string) (*Client, error) {
	adminURL = strings.TrimRight(adminURL, "/")
	if adminURL == "" || apiKey == "" {
		return nil, fmt.Errorf("APISIX admin URL and API key are required")
	}
	if _, err := url.ParseRequestURI(adminURL); err != nil {
		return nil, fmt.Errorf("invalid APISIX admin URL: %w", err)
	}
	return &Client{adminURL: adminURL, apiKey: apiKey, httpClient: &http.Client{Timeout: 10 * time.Second}}, nil
}

// CreateRoute creates or replaces a named APISIX route via PUT /apisix/admin/routes/{id}.
func (c *Client) CreateRoute(ctx context.Context, route Route) error {
	if route.ID == "" || !strings.HasPrefix(route.URI, "/") || route.UpstreamURL == "" {
		return fmt.Errorf("route ID, absolute URI path, and upstream URL are required")
	}
	upstream, err := url.Parse(route.UpstreamURL)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return fmt.Errorf("invalid APISIX upstream URL")
	}
	if len(route.Methods) == 0 {
		return fmt.Errorf("at least one route method is required")
	}

	payload := map[string]interface{}{
		"uri":     route.URI,
		"methods": route.Methods,
		"upstream": map[string]interface{}{
			"type": "roundrobin",
			"nodes": map[string]int{upstream.Host: 1},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode APISIX route: %w", err)
	}

	endpoint := fmt.Sprintf("%s/apisix/admin/routes/%s", c.adminURL, url.PathEscape(route.ID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create APISIX route request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call APISIX Admin API: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read APISIX route response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("APISIX route upsert returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (c *Client) Close() error { return nil }
