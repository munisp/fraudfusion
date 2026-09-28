// Package authcommon is the single shared authentication/authorization
// implementation for FraudFusion Go services. It consolidates the four
// previously copy-pasted Keycloak token-introspection middlewares
// (advance-fee, crypto, investment, sim-swap detectors) and adds:
//
//   - Introspector: OIDC token introspection with a bounded TTL cache keyed
//     by token hash (never the raw token) and singleflight dedup on misses.
//     Fail-closed: any error denies access.
//   - JWTVerifier: local RS256 JWT validation against a JWKS endpoint with
//     JWKS cache (TTL + singleflight) and clock-skew leeway.
//   - Gin middleware helpers and tenant binding (see tenant.go): the token's
//     tenant_id claim must match the path/header tenant, optionally enforced
//     against Permify.
//   - Breaker: a small dependency circuit breaker (breaker.go).
//
// Per-service wiring is done entirely through option funcs; nothing in this
// package reads process env directly except the explicit FromEnv option
// loader.
package authcommon

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
)

const (
	// DefaultCacheTTL bounds reuse of a positive introspection result;
	// short enough to bound revocation lag, long enough to take the Keycloak
	// round trip (10-40ms) off every scoring call.
	DefaultCacheTTL = 45 * time.Second
	// DefaultNegativeTTL bounds reuse of negative results so newly-activated
	// tokens recover within seconds.
	DefaultNegativeTTL = 5 * time.Second
	// cacheMaxSize bounds cache memory (distinct live tokens).
	cacheMaxSize = 10000
	// maxResponseBytes caps introspection/JWKS response bodies.
	maxResponseBytes = 1 << 20
)

// Principal is the authenticated caller.
type Principal struct {
	Subject  string
	TenantID string
	Roles    map[string]struct{}
}

// HasRole reports whether the principal carries any of the given roles.
func (p *Principal) HasRole(roles ...string) bool {
	if p == nil {
		return false
	}
	for _, want := range roles {
		if _, ok := p.Roles[want]; ok {
			return true
		}
	}
	return false
}

// introspectEntry is a bounded-TTL cached introspection outcome.
type introspectEntry struct {
	principal *Principal
	err       error
	expiresAt time.Time
}

// introspectCall deduplicates concurrent misses for the same token
// (singleflight): waiters block on done and share the leader's outcome.
type introspectCall struct {
	done      chan struct{}
	principal *Principal
	err       error
}

// Introspector validates bearer tokens against a Keycloak (RFC 7662)
// introspection endpoint.
type Introspector struct {
	introspectionURL string
	clientID         string
	clientSecret     string
	httpClient       *http.Client
	cacheTTL         time.Duration
	negativeTTL      time.Duration
	retries          int

	cacheMu  sync.Mutex
	cache    map[string]*introspectEntry
	inflight map[string]*introspectCall
}

// Option configures an Introspector (or other authcommon component).
type Option func(*config) error

type config struct {
	introspectionURL string
	keycloakBaseURL  string
	realm            string
	clientID         string
	clientSecret     string
	insecureHTTP     bool
	httpClient       *http.Client
	cacheTTL         time.Duration
	negativeTTL      time.Duration
	retries          int
}

// WithIntrospectionURL sets the exact RFC 7666 introspection endpoint.
func WithIntrospectionURL(u string) Option {
	return func(c *config) error {
		c.introspectionURL = strings.TrimSpace(u)
		return nil
	}
}

// WithKeycloakBase derives the introspection endpoint from the Keycloak base
// URL and realm.
func WithKeycloakBase(baseURL, realm string) Option {
	return func(c *config) error {
		c.keycloakBaseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
		c.realm = strings.TrimSpace(realm)
		return nil
	}
}

// WithClientCredentials sets the confidential client credentials used for
// the introspection call.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *config) error {
		c.clientID = clientID
		c.clientSecret = clientSecret
		return nil
	}
}

// WithInsecureHTTP allows http:// introspection endpoints. Local development
// only; production must terminate TLS at the identity provider.
func WithInsecureHTTP(allow bool) Option {
	return func(c *config) error {
		c.insecureHTTP = allow
		return nil
	}
}

// WithHTTPClient overrides the HTTP client (e.g. in tests).
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) error {
		if client != nil {
			c.httpClient = client
		}
		return nil
	}
}

// WithCacheTTLs overrides the positive/negative cache TTLs.
func WithCacheTTLs(positive, negative time.Duration) Option {
	return func(c *config) error {
		if positive > 0 {
			c.cacheTTL = positive
		}
		if negative > 0 {
			c.negativeTTL = negative
		}
		return nil
	}
}

// WithRetries sets the number of introspection attempts (default 3).
func WithRetries(n int) Option {
	return func(c *config) error {
		if n >= 1 && n <= 5 {
			c.retries = n
		}
		return nil
	}
}

// FromEnv builds options from the conventional KEYCLOAK_* environment
// variables. It returns an error only for malformed values; missing values
// surface at NewIntrospector time.
func FromEnv() []Option {
	return []Option{
		WithIntrospectionURL(envOr("KEYCLOAK_INTROSPECTION_URL", "")),
		WithKeycloakBase(envOr("KEYCLOAK_URL", ""), envOr("KEYCLOAK_REALM", "fraudfusion")),
		WithClientCredentials(envOr("KEYCLOAK_CLIENT_ID", ""), envOr("KEYCLOAK_CLIENT_SECRET", "")),
		WithInsecureHTTP(strings.EqualFold(envOr("KEYCLOAK_INSECURE_HTTP", ""), "true")),
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// NewIntrospector validates configuration and builds an Introspector.
// Fail-closed: incomplete or insecure configuration is an error.
func NewIntrospector(opts ...Option) (*Introspector, error) {
	cfg := &config{
		cacheTTL:    DefaultCacheTTL,
		negativeTTL: DefaultNegativeTTL,
		retries:     3,
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	introspectionURL := cfg.introspectionURL
	if introspectionURL == "" && cfg.keycloakBaseURL != "" {
		introspectionURL = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", cfg.keycloakBaseURL, url.PathEscape(cfg.realm))
	}
	if introspectionURL == "" {
		return nil, errors.New("authcommon: introspection URL or Keycloak base URL must be configured")
	}
	parsed, err := url.ParseRequestURI(introspectionURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("authcommon: invalid introspection URL: %w", err)
	}
	if parsed.Scheme != "https" && !cfg.insecureHTTP {
		return nil, errors.New("authcommon: introspection URL must be https (WithInsecureHTTP for local dev only)")
	}
	if cfg.clientID == "" || cfg.clientSecret == "" {
		return nil, errors.New("authcommon: client ID and secret must be configured")
	}
	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
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
		}
	}
	return &Introspector{
		introspectionURL: introspectionURL,
		clientID:         cfg.clientID,
		clientSecret:     cfg.clientSecret,
		httpClient:       httpClient,
		cacheTTL:         cfg.cacheTTL,
		negativeTTL:      cfg.negativeTTL,
		retries:          cfg.retries,
		cache:            make(map[string]*introspectEntry),
		inflight:         make(map[string]*introspectCall),
	}, nil
}

func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (k *Introspector) lookupCache(key string) (*Principal, error, bool) {
	k.cacheMu.Lock()
	defer k.cacheMu.Unlock()
	entry, ok := k.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, nil, false
	}
	return entry.principal, entry.err, true
}

func (k *Introspector) storeCache(key string, entry *introspectEntry) {
	k.cacheMu.Lock()
	defer k.cacheMu.Unlock()
	if len(k.cache) >= cacheMaxSize {
		now := time.Now()
		for ck, e := range k.cache {
			if now.After(e.expiresAt) {
				delete(k.cache, ck)
			}
		}
		if len(k.cache) >= cacheMaxSize {
			return // correctness never depends on the cache
		}
	}
	k.cache[key] = entry
}

// Introspect validates the token with a bounded TTL cache (keyed by token
// hash, never the raw token) and singleflight dedup; only a cache miss with
// no in-flight call reaches Keycloak, with capped exponential backoff. Any
// failure denies access (fail-closed).
func (k *Introspector) Introspect(ctx context.Context, token string) (*Principal, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("authcommon: empty access token")
	}
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
	ttl := k.cacheTTL
	if err != nil {
		ttl = k.negativeTTL
	}
	k.storeCache(key, &introspectEntry{principal: principal, err: err, expiresAt: time.Now().Add(ttl)})

	k.cacheMu.Lock()
	delete(k.inflight, key)
	call.principal, call.err = principal, err
	close(call.done)
	k.cacheMu.Unlock()
	return principal, err
}

func (k *Introspector) introspectWithRetry(ctx context.Context, token string) (*Principal, error) {
	var principal *Principal
	var lastErr error
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < k.retries; attempt++ {
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

func (k *Introspector) introspectOnce(ctx context.Context, token string) (*Principal, error) {
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
		return nil, fmt.Errorf("authcommon: introspection returned status %d", resp.StatusCode)
	}
	var claims struct {
		Active      bool   `json:"active"`
		Sub         string `json:"sub"`
		TenantID    string `json:"tenant_id"`
		Tenant      string `json:"tenant"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("authcommon: decode introspection response: %w", err)
	}
	if !claims.Active || claims.Sub == "" {
		return nil, errors.New("authcommon: token inactive")
	}
	roles := make(map[string]struct{}, len(claims.RealmAccess.Roles)+len(claims.Roles))
	for _, role := range claims.RealmAccess.Roles {
		roles[role] = struct{}{}
	}
	for _, role := range claims.Roles {
		roles[role] = struct{}{}
	}
	tenant := claims.TenantID
	if tenant == "" {
		tenant = claims.Tenant
	}
	if tenant == "" {
		return nil, errors.New("authcommon: tenant claim absent")
	}
	return &Principal{Subject: claims.Sub, TenantID: tenant, Roles: roles}, nil
}

// WithBackoff retries op with capped exponential backoff (5 attempts).
func WithBackoff(op func() error) error {
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
