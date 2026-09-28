package authcommon

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newTestIntrospector(t *testing.T, handler http.HandlerFunc) (*Introspector, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	in, err := NewIntrospector(
		WithIntrospectionURL(server.URL),
		WithClientCredentials("id", "secret"),
		WithInsecureHTTP(true),
		WithRetries(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	return in, server
}

func TestIntrospectorSuccessAndCaching(t *testing.T) {
	var calls int32
	in, _ := newTestIntrospector(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		json.NewEncoder(w).Encode(map[string]any{
			"active": true, "sub": "user-1", "tenant_id": "tenant-a",
			"realm_access": map[string]any{"roles": []string{"fraud_analyst"}},
		})
	})
	p, err := in.Introspect(context.Background(), "token-1")
	if err != nil || p.TenantID != "tenant-a" || !p.HasRole("fraud_analyst") {
		t.Fatalf("introspect = %+v, %v", p, err)
	}
	if _, err := in.Introspect(context.Background(), "token-1"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 upstream call (cache hit on second), got %d", got)
	}
}

func TestIntrospectorFailClosed(t *testing.T) {
	in, _ := newTestIntrospector(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"active": false})
	})
	if _, err := in.Introspect(context.Background(), "dead-token"); err == nil {
		t.Fatal("inactive token must be rejected")
	}
	in2, _ := newTestIntrospector(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := in2.Introspect(context.Background(), "token"); err == nil {
		t.Fatal("upstream 500 must deny")
	}
	if _, err := in.Introspect(context.Background(), "  "); err == nil {
		t.Fatal("empty token must be rejected")
	}
}

func TestNewIntrospectorRequiresHTTPSAndCredentials(t *testing.T) {
	if _, err := NewIntrospector(WithIntrospectionURL("http://kc/introspect"), WithClientCredentials("a", "b")); err == nil {
		t.Fatal("http introspection URL must be rejected without WithInsecureHTTP")
	}
	if _, err := NewIntrospector(WithIntrospectionURL("https://kc/introspect")); err == nil {
		t.Fatal("missing client credentials must be rejected")
	}
	if _, err := NewIntrospector(WithClientCredentials("a", "b")); err == nil {
		t.Fatal("missing introspection URL must be rejected")
	}
}

func TestBreakerTransitions(t *testing.T) {
	b := NewBreaker("test-dep", WithFailureThreshold(5), WithResetTimeout(30*time.Second))
	now := time.Now()
	b.now = func() time.Time { return now }
	fail := func() error { return errors.New("boom") }
	ok := func() error { return nil }

	for i := 0; i < 4; i++ {
		if err := b.Execute(fail); err == nil || errors.Is(err, ErrBreakerOpen) {
			t.Fatalf("call %d should execute and fail without opening", i)
		}
	}
	if b.State() != BreakerClosed {
		t.Fatalf("state after 4 failures = %s, want closed", b.State())
	}
	_ = b.Execute(fail) // 5th consecutive failure opens
	if b.State() != BreakerOpen {
		t.Fatalf("state after 5 failures = %s, want open", b.State())
	}
	if err := b.Execute(ok); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("open breaker must fail fast with ErrBreakerOpen, got %v", err)
	}
	// Within reset timeout: still open.
	now = now.Add(29 * time.Second)
	if err := b.Execute(ok); !errors.Is(err, ErrBreakerOpen) {
		t.Fatal("breaker should still be open before reset timeout")
	}
	// After reset timeout: half-open trial admitted; success closes.
	now = now.Add(2 * time.Second)
	if err := b.Execute(ok); err != nil {
		t.Fatalf("half-open trial should execute, got %v", err)
	}
	if b.State() != BreakerClosed {
		t.Fatalf("state after successful trial = %s, want closed", b.State())
	}
	// Re-open and verify failed trial re-opens.
	for i := 0; i < 5; i++ {
		_ = b.Execute(fail)
	}
	now = now.Add(31 * time.Second)
	if b.State() != BreakerHalfOpen {
		t.Fatalf("state after timeout = %s, want half-open", b.State())
	}
	_ = b.Execute(fail)
	if b.State() != BreakerOpen {
		t.Fatalf("failed half-open trial must re-open, got %s", b.State())
	}
}

// --- JWT verifier tests ---

func jwkForKey(kid string, pub *rsa.PublicKey) map[string]any {
	e := pub.E
	eBytes := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestJWTVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwkForKey("kid-1", &key.PublicKey)}})
	}))
	defer server.Close()
	verifier, err := NewJWTVerifier(WithJWKSURL(server.URL), WithIssuer("https://issuer.test"), WithAudience("fraudfusion"))
	if err != nil {
		t.Fatal(err)
	}
	validClaims := map[string]any{
		"sub": "user-1", "tenant_id": "tenant-a", "iss": "https://issuer.test", "aud": "fraudfusion",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"realm_access": map[string]any{"roles": []string{"fraud_analyst"}},
	}
	token := signTestJWT(t, key, "kid-1", validClaims)
	p, err := verifier.Verify(context.Background(), token)
	if err != nil || p.Subject != "user-1" || p.TenantID != "tenant-a" || !p.HasRole("fraud_analyst") {
		t.Fatalf("verify = %+v, %v", p, err)
	}

	// Expired beyond leeway: reject.
	expired := signTestJWT(t, key, "kid-1", map[string]any{
		"sub": "user-1", "tenant_id": "tenant-a", "iss": "https://issuer.test", "aud": "fraudfusion",
		"exp": time.Now().Add(-10 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), expired); err == nil {
		t.Fatal("expired token must be rejected")
	}
	// Within leeway: accept.
	recent := signTestJWT(t, key, "kid-1", map[string]any{
		"sub": "user-1", "tenant_id": "tenant-a", "iss": "https://issuer.test", "aud": "fraudfusion",
		"exp": time.Now().Add(-30 * time.Second).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), recent); err != nil {
		t.Fatalf("token within clock-skew leeway should verify: %v", err)
	}
	// Wrong issuer: reject.
	wrongIss := signTestJWT(t, key, "kid-1", map[string]any{
		"sub": "u", "tenant_id": "t", "iss": "https://evil.test", "aud": "fraudfusion",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), wrongIss); err == nil {
		t.Fatal("issuer mismatch must be rejected")
	}
	// Wrong key: reject.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := signTestJWT(t, otherKey, "kid-1", validClaims)
	if _, err := verifier.Verify(context.Background(), forged); err == nil {
		t.Fatal("forged signature must be rejected")
	}
	// Unknown kid: reject (after forced refresh).
	unknownKid := signTestJWT(t, key, "kid-2", validClaims)
	if _, err := verifier.Verify(context.Background(), unknownKid); err == nil {
		t.Fatal("unknown kid must be rejected")
	}
	// alg=none style downgrade: reject.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"kid-1"}`))
	body, _ := json.Marshal(validClaims)
	downgrade := noneHeader + "." + base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString([]byte("x"))
	if _, err := verifier.Verify(context.Background(), downgrade); err == nil || !strings.Contains(err.Error(), "RS256") {
		t.Fatalf("non-RS256 alg must be rejected, got %v", err)
	}
	// JWKS fetch failure is fail-closed.
	deadVerifier, _ := NewJWTVerifier(WithJWKSURL("http://127.0.0.1:1/jwks"))
	if _, err := deadVerifier.Verify(context.Background(), token); err == nil {
		t.Fatal("JWKS fetch failure must deny")
	}
}

// --- Tenant binding tests ---

func tenantBindingContext(t *testing.T, tenant, headerTenant string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	if headerTenant != "" {
		c.Request.Header.Set("X-Tenant-ID", headerTenant)
	}
	c.Set(PrincipalContextKey, &Principal{Subject: "user-1", TenantID: tenant, Roles: map[string]struct{}{}})
	return c, w
}

func TestTenantBindingClaimEquality(t *testing.T) {
	binding := NewTenantBinding()
	c, w := tenantBindingContext(t, "tenant-a", "tenant-a")
	binding.Middleware()(c)
	if w.Code == http.StatusForbidden {
		t.Fatal("matching header tenant must pass")
	}

	c, w = tenantBindingContext(t, "tenant-a", "tenant-b")
	binding.Middleware()(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("mismatched header tenant must be 403, got %d", w.Code)
	}

	// No principal: 403.
	gin.SetMode(gin.TestMode)
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	binding.Middleware()(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing principal must be 403, got %d", w.Code)
	}
}

func TestTenantBindingPermifyEnforcement(t *testing.T) {
	permify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/tenants/tenant-a/permissions/check") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"can": "RESULT_ALLOWED"})
	}))
	defer permify.Close()

	binding := NewTenantBinding(WithPermify(permify.URL, "access"), WithPermifyEnforcement(true))
	c, w := tenantBindingContext(t, "tenant-a", "")
	binding.Middleware()(c)
	if w.Code == http.StatusForbidden {
		t.Fatal("permify-allowed subject must pass")
	}

	c, w = tenantBindingContext(t, "tenant-b", "")
	binding.Middleware()(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("permify 404/deny must fail closed with 403, got %d", w.Code)
	}

	// Permify down: fail closed.
	dead := NewTenantBinding(WithPermify("http://127.0.0.1:1", "access"), WithPermifyEnforcement(true))
	c, w = tenantBindingContext(t, "tenant-a", "")
	dead.Middleware()(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unreachable permify must fail closed with 403, got %d", w.Code)
	}

	// Enforcement disabled (default): claim equality only, no permify call.
	off := NewTenantBinding(WithPermify("http://127.0.0.1:1", "access"))
	c, w = tenantBindingContext(t, "tenant-a", "")
	off.Middleware()(c)
	if w.Code == http.StatusForbidden {
		t.Fatal("PERMIFY_ENFORCE=false must not call permify")
	}
}

func TestWithBackoffEventuallySucceeds(t *testing.T) {
	attempts := 0
	if err := WithBackoff(func() error {
		attempts++
		if attempts < 2 {
			return fmt.Errorf("not yet")
		}
		return nil
	}); err != nil || attempts != 2 {
		t.Fatalf("withBackoff attempts=%d err=%v", attempts, err)
	}
	if err := WithBackoff(func() error { return errors.New("always") }); err == nil {
		t.Fatal("persistent failure must return error")
	}
}

var _ = big.NewInt
