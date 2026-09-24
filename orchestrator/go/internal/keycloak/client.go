package keycloak

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/munisp/fraudfusion/orchestrator/go/internal/backoff"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/httpx"
)

const (
	// introspectCacheTTL bounds how long a positive introspection result is
	// reused. Tokens typically live 5+ minutes; 45s bounds revocation lag.
	introspectCacheTTL = 45 * time.Second
	// introspectNegTTL bounds how long an inactive/failed introspection is
	// reused, so a newly-activated token recovers quickly.
	introspectNegTTL = 5 * time.Second
	// introspectCacheMaxSize bounds memory: distinct tokens in flight.
	introspectCacheMaxSize = 10000
)

// cacheEntry is a bounded-TTL introspection result. Err is set for negative
// entries (inactive token, upstream failure); Claims is set for positive ones.
type cacheEntry struct {
	claims    map[string]interface{}
	err       error
	expiresAt time.Time
}

// Client performs confidential-client OpenID Connect interactions with Keycloak.
type Client struct {
	serverURL    string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	cacheMu sync.Mutex
	cache   map[string]*cacheEntry
	group   singleflight.Group
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
		httpClient:   &http.Client{Timeout: 10 * time.Second, Transport: httpx.SharedTransport()},
		cache:        make(map[string]*cacheEntry),
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
//
// Results are cached in-process: positive results for introspectCacheTTL,
// negative results for introspectNegTTL, keyed by SHA-256 of the token (the
// raw token is never used as a map key). Concurrent misses for the same token
// are deduplicated via singleflight so an expired-token burst costs one
// upstream round trip instead of N.
func (c *Client) ValidateToken(ctx context.Context, token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, fmt.Errorf("access token is required")
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])

	if claims, err, ok := c.lookupCache(key); ok {
		return claims, err
	}

	result, err, _ := c.group.Do(key, func() (interface{}, error) {
		if claims, err, ok := c.lookupCache(key); ok {
			return claims, err
		}
		claims, introspectErr := c.introspectUncached(ctx, token)
		if introspectErr != nil {
			c.storeCache(key, &cacheEntry{err: introspectErr, expiresAt: time.Now().Add(introspectNegTTL)})
			// Return a nil error to singleflight so every waiter shares the
			// negative outcome; the real error travels inside the entry.
			return nil, nil
		}
		c.storeCache(key, &cacheEntry{claims: claims, expiresAt: time.Now().Add(introspectCacheTTL)})
		return claims, nil
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		// Negative outcome shared by the singleflight leader.
		if _, cacheErr, ok := c.lookupCache(key); ok {
			return nil, cacheErr
		}
		return nil, fmt.Errorf("token introspection failed")
	}
	return result.(map[string]interface{}), nil
}

func (c *Client) lookupCache(key string) (map[string]interface{}, error, bool) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, nil, false
	}
	return entry.claims, entry.err, true
}

func (c *Client) storeCache(key string, entry *cacheEntry) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if len(c.cache) >= introspectCacheMaxSize {
		now := time.Now()
		for k, e := range c.cache {
			if now.After(e.expiresAt) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= introspectCacheMaxSize {
			// Cache full of live entries: skip caching rather than evicting
			// arbitrarily; correctness never depends on the cache.
			return
		}
	}
	c.cache[key] = entry
}

// introspectUncached performs the upstream introspection round trip.
func (c *Client) introspectUncached(ctx context.Context, token string) (map[string]interface{}, error) {
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
