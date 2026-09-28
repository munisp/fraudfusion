package authcommon

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultJWKSCacheTTL bounds reuse of fetched JWKS documents; key rotation
// lag is bounded by the TTL.
const DefaultJWKSCacheTTL = 10 * time.Minute

// DefaultClockSkewLeeway is tolerated when validating exp/nbf to absorb
// clock drift between issuer and verifier.
const DefaultClockSkewLeeway = 60 * time.Second

// JWTVerifier validates RS256 JWTs against a remote JWKS endpoint. The JWKS
// document is cached with a bounded TTL and fetches are deduplicated
// (singleflight). Verification is fail-closed: unknown kid after a forced
// refresh, bad signature, expired/not-yet-valid token (beyond leeway), and
// issuer/audience mismatch all deny.
type JWTVerifier struct {
	jwksURL    string
	issuer     string
	audience   string
	leeway     time.Duration
	cacheTTL   time.Duration
	httpClient *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	fetching  *jwksCall
}

type jwksCall struct {
	done chan struct{}
	err  error
}

// JWTOption configures a JWTVerifier.
type JWTOption func(*JWTVerifier)

// WithJWKSURL sets the JWKS endpoint (required).
func WithJWKSURL(u string) JWTOption {
	return func(v *JWTVerifier) { v.jwksURL = strings.TrimSpace(u) }
}

// WithIssuer requires the iss claim to match (optional but recommended).
func WithIssuer(issuer string) JWTOption {
	return func(v *JWTVerifier) { v.issuer = strings.TrimSpace(issuer) }
}

// WithAudience requires the aud claim to contain this value (optional).
func WithAudience(aud string) JWTOption {
	return func(v *JWTVerifier) { v.audience = strings.TrimSpace(aud) }
}

// WithClockSkewLeeway overrides DefaultClockSkewLeeway.
func WithClockSkewLeeway(d time.Duration) JWTOption {
	return func(v *JWTVerifier) {
		if d >= 0 {
			v.leeway = d
		}
	}
}

// WithJWKSHTTPClient overrides the HTTP client (e.g. in tests).
func WithJWKSHTTPClient(client *http.Client) JWTOption {
	return func(v *JWTVerifier) {
		if client != nil {
			v.httpClient = client
		}
	}
}

// NewJWTVerifier builds a verifier; jwksURL must be absolute.
func NewJWTVerifier(opts ...JWTOption) (*JWTVerifier, error) {
	v := &JWTVerifier{
		leeway:     DefaultClockSkewLeeway,
		cacheTTL:   DefaultJWKSCacheTTL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.jwksURL == "" {
		return nil, errors.New("authcommon: JWKS URL must be configured")
	}
	return v, nil
}

type jwtClaims struct {
	Sub      string `json:"sub"`
	TenantID string `json:"tenant_id"`
	Tenant   string `json:"tenant"`
	Issuer   string `json:"iss"`
	Audience any    `json:"aud"`
	Expiry   int64  `json:"exp"`
	NotBefore int64 `json:"nbf"`
	IssuedAt int64  `json:"iat"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	Roles []string `json:"roles"`
}

// Verify validates a compact RS256 JWT and returns the principal.
func (v *JWTVerifier) Verify(ctx context.Context, token string) (*Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("authcommon: malformed JWT")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("authcommon: malformed JWT header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil || header.Kid == "" {
		return nil, errors.New("authcommon: JWT header without kid")
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("authcommon: unsupported JWT alg %q (RS256 only)", header.Alg)
	}

	key, err := v.publicKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("authcommon: malformed JWT signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("authcommon: JWT signature invalid")
	}

	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("authcommon: malformed JWT claims")
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsRaw, &claims); err != nil {
		return nil, errors.New("authcommon: malformed JWT claims")
	}

	now := time.Now().Unix()
	if claims.Expiry == 0 || now > claims.Expiry+int64(v.leeway.Seconds()) {
		return nil, errors.New("authcommon: JWT expired")
	}
	if claims.NotBefore != 0 && now+int64(v.leeway.Seconds()) < claims.NotBefore {
		return nil, errors.New("authcommon: JWT not yet valid")
	}
	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, errors.New("authcommon: JWT issuer mismatch")
	}
	if v.audience != "" && !audienceContains(claims.Audience, v.audience) {
		return nil, errors.New("authcommon: JWT audience mismatch")
	}
	if claims.Sub == "" {
		return nil, errors.New("authcommon: JWT sub absent")
	}
	tenant := claims.TenantID
	if tenant == "" {
		tenant = claims.Tenant
	}
	if tenant == "" {
		return nil, errors.New("authcommon: JWT tenant claim absent")
	}
	roles := make(map[string]struct{}, len(claims.RealmAccess.Roles)+len(claims.Roles))
	for _, role := range claims.RealmAccess.Roles {
		roles[role] = struct{}{}
	}
	for _, role := range claims.Roles {
		roles[role] = struct{}{}
	}
	return &Principal{Subject: claims.Sub, TenantID: tenant, Roles: roles}, nil
}

func audienceContains(aud any, want string) bool {
	switch value := aud.(type) {
	case string:
		return value == want
	case []any:
		for _, item := range value {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// publicKey returns the cached key for kid, refreshing the JWKS document on
// TTL expiry or unknown kid (single deduplicated fetch).
func (v *JWTVerifier) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	if key, ok := v.keys[kid]; ok && time.Since(v.fetchedAt) < v.cacheTTL {
		v.mu.Unlock()
		return key, nil
	}
	if call := v.fetching; call != nil {
		v.mu.Unlock()
		select {
		case <-call.done:
			v.mu.Lock()
			key, ok := v.keys[kid]
			v.mu.Unlock()
			if !ok {
				return nil, fmt.Errorf("authcommon: no JWKS key for kid %q", kid)
			}
			return key, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &jwksCall{done: make(chan struct{})}
	v.fetching = call
	v.mu.Unlock()

	err := v.refresh(ctx)

	v.mu.Lock()
	v.fetching = nil
	call.err = err
	close(call.done)
	if err != nil {
		v.mu.Unlock()
		return nil, err
	}
	key, ok := v.keys[kid]
	v.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("authcommon: no JWKS key for kid %q", kid)
	}
	return key, nil
}

func (v *JWTVerifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authcommon: JWKS fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authcommon: JWKS fetch status %d", resp.StatusCode)
	}
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&document); err != nil {
		return fmt.Errorf("authcommon: decode JWKS: %w", err)
	}
	fresh := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, jwk := range document.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		nBytes, errN := base64.RawURLEncoding.DecodeString(jwk.N)
		eBytes, errE := base64.RawURLEncoding.DecodeString(jwk.E)
		if errN != nil || errE != nil || len(nBytes) == 0 || len(eBytes) == 0 {
			continue
		}
		exponent := 0
		for _, b := range eBytes {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 3 {
			continue
		}
		fresh[jwk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}
	}
	if len(fresh) == 0 {
		return errors.New("authcommon: JWKS contained no usable RSA signing keys")
	}
	v.mu.Lock()
	v.keys = fresh
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}
