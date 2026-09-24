package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Keycloak token-introspection authentication, FAIL-CLOSED. The previous
// middleware only checked that an Authorization header was present.

const (
	// introspectCacheTTL bounds reuse of a positive introspection result;
	// short enough to bound revocation lag, long enough to take the Keycloak
	// round trip (10-40ms) off every scoring call.
	introspectCacheTTL = 45 * time.Second
	// introspectNegTTL bounds reuse of negative results so newly-activated
	// tokens recover within seconds.
	introspectNegTTL = 5 * time.Second
	// introspectCacheMaxSize bounds cache memory (distinct live tokens).
	introspectCacheMaxSize = 10000
)

type authPrincipal struct {
	Subject  string
	TenantID string
	Roles    map[string]struct{}
}

// introspectEntry is a bounded-TTL cached introspection outcome.
type introspectEntry struct {
	principal *authPrincipal
	err       error
	expiresAt time.Time
}

// introspectCall deduplicates concurrent misses for the same token
// (singleflight): waiters block on done and share the leader's outcome.
type introspectCall struct {
	done      chan struct{}
	principal *authPrincipal
	err       error
}

type keycloakIntrospector struct {
	introspectionURL string
	clientID         string
	clientSecret     string
	httpClient       *http.Client

	cacheMu sync.Mutex
	cache   map[string]*introspectEntry
	inflight map[string]*introspectCall
}

func newKeycloakIntrospector() (*keycloakIntrospector, error) {
	introspectionURL := strings.TrimSpace(os.Getenv("KEYCLOAK_INTROSPECTION_URL"))
	if introspectionURL == "" {
		base := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
		realm := getEnv("KEYCLOAK_REALM", "fraudfusion")
		if base == "" {
			return nil, errors.New("KEYCLOAK_INTROSPECTION_URL or KEYCLOAK_URL must be configured")
		}
		introspectionURL = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", base, realm)
	}
	parsed, err := url.ParseRequestURI(introspectionURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Keycloak introspection URL: %w", err)
	}
	if parsed.Scheme != "https" && !strings.EqualFold(os.Getenv("KEYCLOAK_INSECURE_HTTP"), "true") {
		return nil, errors.New("Keycloak introspection URL must be https (KEYCLOAK_INSECURE_HTTP=true for local dev only)")
	}
	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET must be configured")
	}
	return &keycloakIntrospector{
		introspectionURL: introspectionURL,
		clientID:         clientID,
		clientSecret:     clientSecret,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		cache:    make(map[string]*introspectEntry),
		inflight: make(map[string]*introspectCall),
	}, nil
}

func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (k *keycloakIntrospector) lookupCache(key string) (*authPrincipal, error, bool) {
	k.cacheMu.Lock()
	defer k.cacheMu.Unlock()
	entry, ok := k.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, nil, false
	}
	return entry.principal, entry.err, true
}

func (k *keycloakIntrospector) storeCache(key string, entry *introspectEntry) {
	k.cacheMu.Lock()
	defer k.cacheMu.Unlock()
	if len(k.cache) >= introspectCacheMaxSize {
		now := time.Now()
		for ck, e := range k.cache {
			if now.After(e.expiresAt) {
				delete(k.cache, ck)
			}
		}
		if len(k.cache) >= introspectCacheMaxSize {
			return // correctness never depends on the cache
		}
	}
	k.cache[key] = entry
}

// introspect validates the token with a bounded TTL cache (keyed by token
// hash, never the raw token) and singleflight dedup; only a cache miss with
// no in-flight call reaches Keycloak, with capped exponential backoff. Any
// failure denies access.
func (k *keycloakIntrospector) introspect(ctx context.Context, token string) (*authPrincipal, error) {
	key := tokenCacheKey(token)
	if principal, err, ok := k.lookupCache(key); ok {
		return principal, err
	}

	k.cacheMu.Lock()
	if call, ok := k.inflight[key]; ok {
		k.cacheMu.Unlock()
		select {
		case <-call.done:
			return call.principal, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &introspectCall{done: make(chan struct{})}
	k.inflight[key] = call
	k.cacheMu.Unlock()

	principal, err := k.introspectWithRetry(ctx, token)
	ttl := introspectCacheTTL
	if err != nil {
		ttl = introspectNegTTL
	}
	k.storeCache(key, &introspectEntry{principal: principal, err: err, expiresAt: time.Now().Add(ttl)})

	k.cacheMu.Lock()
	delete(k.inflight, key)
	call.principal, call.err = principal, err
	close(call.done)
	k.cacheMu.Unlock()
	return principal, err
}

func (k *keycloakIntrospector) introspectWithRetry(ctx context.Context, token string) (*authPrincipal, error) {
	var principal *authPrincipal
	var lastErr error
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				delay *= 2
			}
		}
		principal, lastErr = k.introspectOnce(ctx, token)
		if lastErr == nil {
			return principal, nil
		}
	}
	return nil, lastErr
}

func (k *keycloakIntrospector) introspectOnce(ctx context.Context, token string) (*authPrincipal, error) {
	form := url.Values{"token": {token}, "client_id": {k.clientID}, "client_secret": {k.clientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned status %d", resp.StatusCode)
	}
	var claims struct {
		Active      bool   `json:"active"`
		Sub         string `json:"sub"`
		TenantID    string `json:"tenant_id"`
		Tenant      string `json:"tenant"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode introspection response: %w", err)
	}
	if !claims.Active || claims.Sub == "" {
		return nil, errors.New("token inactive")
	}
	roles := make(map[string]struct{}, len(claims.RealmAccess.Roles))
	for _, role := range claims.RealmAccess.Roles {
		roles[role] = struct{}{}
	}
	tenant := claims.TenantID
	if tenant == "" {
		tenant = claims.Tenant
	}
	return &authPrincipal{Subject: claims.Sub, TenantID: tenant, Roles: roles}, nil
}

func principalHasRole(p *authPrincipal, roles ...string) bool {
	for _, want := range roles {
		if _, ok := p.Roles[want]; ok {
			return true
		}
	}
	return false
}

// authMiddleware requires a valid Keycloak token for every route except the
// health endpoint.
func authMiddleware() gin.HandlerFunc {
	introspector, err := newKeycloakIntrospector()
	if err != nil {
		panic(fmt.Sprintf("auth middleware configuration: %v", err))
	}
	return func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, "/health") {
			c.Next()
			return
		}
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bearer token required"})
			return
		}
		principal, err := introspector.introspect(c.Request.Context(), strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token validation failed"})
			return
		}
		c.Set("principal", principal)
		c.Next()
	}
}

// requireRole enforces realm roles for destructive actions.
func requireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, exists := c.Get("principal")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		principal, ok := value.(*authPrincipal)
		if !ok || !principalHasRole(principal, roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role", "required": roles})
			return
		}
		c.Next()
	}
}

// withBackoff retries op with capped exponential backoff (5 attempts).
func withBackoff(op func() error) error {
	var err error
	delay := 200 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if err = op(); err == nil {
			return nil
		}
		time.Sleep(delay)
		delay *= 2
		if delay > 4*time.Second {
			delay = 4 * time.Second
		}
	}
	return err
}
