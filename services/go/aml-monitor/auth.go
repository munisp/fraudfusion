package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// JWT authentication against Keycloak, FAIL-CLOSED.
//
// The previous implementation decoded claims and "verified" signatures by
// merely checking the JWKS endpoint returned keys, and explicitly allowed
// requests when Keycloak was unreachable. This rewrite verifies the RS256
// signature against the realm JWKS (cached), enforces expiry and issuer, and
// denies on any error.

// JWTClaims is the verified claim set extracted from a Keycloak access token.
type JWTClaims struct {
	Subject   string   `json:"sub"`
	Email     string   `json:"email"`
	Roles     []string `json:"-"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Issuer    string   `json:"iss"`
}

type jwksKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksCache caches parsed RSA public keys per realm with a TTL.
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
}

var keyCache = &jwksCache{ttl: 5 * time.Minute}

func keycloakConfig() (baseURL, realm string, err error) {
	baseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
	realm = strings.TrimSpace(os.Getenv("KEYCLOAK_REALM"))
	if baseURL == "" {
		return "", "", fmt.Errorf("KEYCLOAK_URL must be configured")
	}
	if realm == "" {
		realm = "fraudfusion"
	}
	return baseURL, realm, nil
}

// fetchJWKS downloads and caches the realm signing keys. Any failure is an
// error — callers must deny the request.
func fetchJWKS(keycloakURL, realm string) (map[string]*rsa.PublicKey, error) {
	keyCache.mu.RLock()
	if time.Since(keyCache.fetchedAt) < keyCache.ttl && len(keyCache.keys) > 0 {
		defer keyCache.mu.RUnlock()
		return keyCache.keys, nil
	}
	keyCache.mu.RUnlock()

	// Deduplicate concurrent refetches: a burst of tokens with an unknown
	// (rotated) kid must trigger one JWKS download, not a thundering herd.
	result, err, _ := jwksGroup.Do("jwks", func() (interface{}, error) {
		// Re-check inside the flight: a concurrent fetch may have landed.
		keyCache.mu.RLock()
		if time.Since(keyCache.fetchedAt) < keyCache.ttl && len(keyCache.keys) > 0 {
			defer keyCache.mu.RUnlock()
			return keyCache.keys, nil
		}
		keyCache.mu.RUnlock()
		return fetchJWKSUncached(keycloakURL, realm)
	})
	if err != nil {
		return nil, err
	}
	return result.(map[string]*rsa.PublicKey), nil
}

var jwksGroup singleflight.Group

func fetchJWKSUncached(keycloakURL, realm string) (map[string]*rsa.PublicKey, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakURL, realm)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	var body struct {
		Keys []jwksKey `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	if len(body.Keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no keys")
	}

	keys := map[string]*rsa.PublicKey{}
	for _, k := range body.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode JWKS modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode JWKS exponent: %w", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e == 0 {
			return nil, fmt.Errorf("JWKS key %s has empty exponent", k.Kid)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable RSA keys")
	}

	keyCache.mu.Lock()
	keyCache.keys = keys
	keyCache.fetchedAt = time.Now()
	keyCache.mu.Unlock()
	return keys, nil
}

// validateJWTToken verifies signature, expiry, and issuer. It fails closed:
// any error denies the request.
func validateJWTToken(tokenString string) (*JWTClaims, error) {
	keycloakURL, realm, err := keycloakConfig()
	if err != nil {
		return nil, err
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse token header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported token algorithm %q (RS256 required)", header.Alg)
	}
	if header.Kid == "" {
		return nil, fmt.Errorf("token header missing kid")
	}

	keys, err := fetchJWKS(keycloakURL, realm)
	if err != nil {
		return nil, fmt.Errorf("signature verification unavailable: %w", err)
	}
	key, ok := keys[header.Kid]
	if !ok {
		// Force a single cache refresh in case of key rotation.
		keyCache.mu.Lock()
		keyCache.fetchedAt = time.Time{}
		keyCache.mu.Unlock()
		keys, err = fetchJWKS(keycloakURL, realm)
		if err != nil {
			return nil, fmt.Errorf("signature verification unavailable after refresh: %w", err)
		}
		key, ok = keys[header.Kid]
		if !ok {
			return nil, fmt.Errorf("token signed by unknown key %q", header.Kid)
		}
	}

	signed := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode token signature: %w", err)
	}
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, fmt.Errorf("invalid token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode token payload: %w", err)
	}
	var raw struct {
		JWTClaims
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		RolesClaim []string `json:"roles"`
	}
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, fmt.Errorf("parse token claims: %w", err)
	}
	claims := raw.JWTClaims
	claims.Roles = append(claims.Roles, raw.RealmAccess.Roles...)
	claims.Roles = append(claims.Roles, raw.RolesClaim...)

	if claims.Subject == "" {
		return nil, fmt.Errorf("token subject is required")
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}
	expectedIssuer := fmt.Sprintf("%s/realms/%s", keycloakURL, realm)
	altIssuer := fmt.Sprintf("%s/auth/realms/%s", keycloakURL, realm)
	if claims.Issuer != expectedIssuer && claims.Issuer != altIssuer {
		return nil, fmt.Errorf("invalid token issuer")
	}
	return &claims, nil
}

// hasAnyRole reports whether the claims carry at least one required role.
func hasAnyRole(claims *JWTClaims, roles ...string) bool {
	for _, have := range claims.Roles {
		for _, want := range roles {
			if have == want {
				return true
			}
		}
	}
	return false
}
