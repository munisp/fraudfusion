// Package permify implements the orchestrator's Permify ReBAC client over the
// Permify REST API: permission checks (fail closed), schema writes, data
// writes, and an idempotent Bootstrap so journey authorization can actually
// allow instead of never matching an empty schema.
package permify

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/munisp/fraudfusion/orchestrator/go/internal/backoff"
)

//go:embed schema.perm
var schema string

// Client calls the Permify REST endpoints.
type Client struct {
	apiURL     string
	apiKey     string
	httpClient *http.Client
}

// NewClient validates the Permify configuration. The API key is required:
// there is no insecure default.
func NewClient(apiURL, apiKey string) (*Client, error) {
	apiURL = strings.TrimRight(apiURL, "/")
	if apiURL == "" {
		return nil, fmt.Errorf("Permify API URL is required")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("Permify API key is required (PERMIFY_API_KEY)")
	}
	if _, err := url.ParseRequestURI(apiURL); err != nil {
		return nil, fmt.Errorf("invalid Permify API URL: %w", err)
	}
	return &Client{apiURL: apiURL, apiKey: apiKey, httpClient: &http.Client{Timeout: 5 * time.Second}}, nil
}

func (c *Client) do(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	var responseBody []byte
	err := backoff.Do(ctx, backoff.Default(), func() error {
		var reqBody io.Reader
		if payload != nil {
			encoded, err := json.Marshal(payload)
			if err != nil {
				return fmt.Errorf("encode Permify request: %w", err)
			}
			reqBody = bytes.NewReader(encoded)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.apiURL+path, reqBody)
		if err != nil {
			return fmt.Errorf("create Permify request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("call Permify %s %s: %w", method, path, err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return fmt.Errorf("read Permify response: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("Permify %s %s returned status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		responseBody = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return responseBody, nil
}

// CheckPermission evaluates a real Permify relationship-based authorization
// decision. The client fails closed: transport failure, non-2xx status,
// malformed response, or anything except an allowed result denies access.
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

	raw, err := c.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/permissions/check", payload)
	if err != nil {
		return false, err
	}
	var response struct {
		Can string `json:"can"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return false, fmt.Errorf("decode Permify permission response: %w", err)
	}
	return response.Can == "CHECK_RESULT_ALLOWED" || response.Can == "RESULT_ALLOWED", nil
}

// WriteSchema uploads the embedded ReBAC schema for a tenant and returns the
// schema version assigned by Permify. Retried with capped backoff.
func (c *Client) WriteSchema(ctx context.Context, tenantID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("tenant ID is required")
	}
	raw, err := c.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/schemas/write", map[string]interface{}{
		"schema": schema,
	})
	if err != nil {
		return "", err
	}
	var response struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return "", fmt.Errorf("decode Permify schema write response: %w", err)
	}
	return response.SchemaVersion, nil
}

// tuple is a single Permify relationship tuple.
type tuple struct {
	entityType  string
	entityID    string
	relation    string
	subjectType string
	subjectID   string
	subjectRel  string
}

func (t tuple) toJSON() map[string]interface{} {
	return map[string]interface{}{
		"entity":   map[string]string{"type": t.entityType, "id": t.entityID},
		"relation": t.relation,
		"subject":  map[string]string{"type": t.subjectType, "id": t.subjectID, "relation": t.subjectRel},
	}
}

// WriteData writes relationship tuples for a tenant. Retried with capped
// backoff; Permify deduplicates tuples so re-writing is idempotent.
func (c *Client) WriteData(ctx context.Context, tenantID string, tuples ...tuple) error {
	if tenantID == "" || len(tuples) == 0 {
		return fmt.Errorf("tenant ID and at least one tuple are required")
	}
	encoded := make([]map[string]interface{}, 0, len(tuples))
	for _, t := range tuples {
		encoded = append(encoded, t.toJSON())
	}
	_, err := c.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/data/write", map[string]interface{}{
		"tuples":   encoded,
		"metadata": map[string]interface{}{"schema_version": ""},
	})
	return err
}

// Bootstrap idempotently provisions a tenant: it writes the embedded schema
// and seeds the relationships required for journey authorization — the
// journey→tenant link and the bootstrap admin as both tenant admin and
// journey owner/analyst. Without this, every CheckPermission call can only
// ever deny. Safe to call on every startup.
func (c *Client) Bootstrap(ctx context.Context, tenantID, adminUserID string, journeyIDs []string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID is required for Permify bootstrap")
	}
	version, err := c.WriteSchema(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("bootstrap Permify schema: %w", err)
	}

	var tuples []tuple
	if adminUserID != "" {
		tuples = append(tuples, tuple{entityType: "tenant", entityID: tenantID, relation: "admin", subjectType: "user", subjectID: adminUserID})
	}
	for _, journeyID := range journeyIDs {
		if journeyID == "" {
			continue
		}
		tuples = append(tuples,
			tuple{entityType: "journey", entityID: journeyID, relation: "tenant", subjectType: "tenant", subjectID: tenantID},
		)
		if adminUserID != "" {
			tuples = append(tuples,
				tuple{entityType: "journey", entityID: journeyID, relation: "owner", subjectType: "user", subjectID: adminUserID},
				tuple{entityType: "journey", entityID: journeyID, relation: "analyst", subjectType: "user", subjectID: adminUserID},
			)
		}
	}
	if len(tuples) > 0 {
		if err := c.WriteData(ctx, tenantID, tuples...); err != nil {
			return fmt.Errorf("bootstrap Permify data: %w", err)
		}
	}
	_ = version
	return nil
}

// Health performs a real Permify liveness probe for the /health endpoint.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("create Permify health request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call Permify healthz: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("Permify unhealthy: status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op; the HTTP client owns no persistent connection.
func (c *Client) Close() error { return nil }
