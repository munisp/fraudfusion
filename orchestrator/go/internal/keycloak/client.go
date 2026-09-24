package keycloak

import (
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

// Client performs confidential-client OpenID Connect interactions with Keycloak.
type Client struct {
	serverURL    string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// TokenResponse is the Keycloak token response returned by the OpenID Connect token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// NewClient validates the confidential-client configuration. Requests use a bounded timeout and never
// substitute locally generated or fixed tokens.
func NewClient(serverURL, realm, clientID, clientSecret string) (*Client, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	if serverURL == "" || realm == "" || clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("Keycloak server URL, realm, client ID, and client secret are required")
	}
	if _, err := url.ParseRequestURI(serverURL); err != nil {
		return nil, fmt.Errorf("invalid Keycloak server URL: %w", err)
	}

	return &Client{
		serverURL:    serverURL,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *Client) endpoint(path string) string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/%s", c.serverURL, url.PathEscape(c.realm), path)
}

// Login uses Keycloak's confidential-client direct grant endpoint. Deployments should prefer
// authorization-code flow with PKCE for interactive clients; this method exists only for the legacy
// server-side credential path already exposed by the orchestrator API.
func (c *Client) Login(ctx context.Context, username, password string) (*TokenResponse, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"username":      {username},
		"password":      {password},
	}
	var token TokenResponse
	err := backoff.Do(ctx, backoff.Default(), func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("token"), strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("create Keycloak token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("request Keycloak token: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return fmt.Errorf("read Keycloak token response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Keycloak token request rejected with status %d", resp.StatusCode)
		}

		if err := json.Unmarshal(body, &token); err != nil {
			return fmt.Errorf("decode Keycloak token response: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") {
		return nil, fmt.Errorf("Keycloak returned an invalid token response")
	}
	return &token, nil
}

// ValidateToken uses Keycloak's confidential-client token introspection endpoint and returns
// only claims reported by the identity provider. Any transport, protocol, or inactive-token result
// denies access.
func (c *Client) ValidateToken(ctx context.Context, token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, fmt.Errorf("access token is required")
	}

	form := url.Values{
		"token":         {token},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	claims := make(map[string]interface{})
	err := backoff.Do(ctx, backoff.Default(), func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("token/introspect"), strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("create Keycloak introspection request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("introspect Keycloak token: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return fmt.Errorf("read Keycloak introspection response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Keycloak introspection rejected with status %d", resp.StatusCode)
		}

		if err := json.Unmarshal(body, &claims); err != nil {
			return fmt.Errorf("decode Keycloak introspection response: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	active, ok := claims["active"].(bool)
	if !ok || !active {
		return nil, fmt.Errorf("Keycloak reports token inactive")
	}
	return claims, nil
}

// Health performs a real realm lookup so /health reflects Keycloak
// availability instead of a hardcoded "connected".
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/realms/%s", c.serverURL, url.PathEscape(c.realm)), nil)
	if err != nil {
		return fmt.Errorf("create Keycloak health request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call Keycloak realm endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Keycloak realm %q unavailable: status %d", c.realm, resp.StatusCode)
	}
	return nil
}

// Close satisfies the orchestrator client contract; the HTTP client owns no persistent connection requiring close.
func (c *Client) Close() error { return nil }
