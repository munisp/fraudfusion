package authcommon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// TenantBinding asserts that the authenticated token's tenant_id claim
// matches the tenant carried by the request (path parameter and/or
// X-Tenant-ID-style header) and, when a Permify URL is configured and
// enforcement is enabled, that Permify grants the subject access to the
// tenant. Everything fails closed with 403.
type TenantBinding struct {
	header          string
	pathParam       string
	permifyURL      string
	permifyPerm     string
	permifyEnforced bool
	httpClient      *http.Client
	breaker         *Breaker
}

// TenantOption configures TenantBinding.
type TenantOption func(*TenantBinding)

// WithTenantHeader sets the tenant header name (default "X-Tenant-ID").
// An empty header value is ignored; a present mismatched value denies.
func WithTenantHeader(header string) TenantOption {
	return func(t *TenantBinding) {
		if strings.TrimSpace(header) != "" {
			t.header = header
		}
	}
}

// WithTenantPathParam names a gin path parameter that must equal the token
// tenant when present in the route (e.g. "tenant_id").
func WithTenantPathParam(param string) TenantOption {
	return func(t *TenantBinding) { t.pathParam = param }
}

// WithPermify enables a Permify permission check per request. permifyURL is
// the base URL (e.g. https://permify:3476); permission is the Permify
// permission name checked on entity tenant:<tenantID> for subject
// user:<sub>.
func WithPermify(permifyURL, permission string) TenantOption {
	return func(t *TenantBinding) {
		t.permifyURL = strings.TrimRight(strings.TrimSpace(permifyURL), "/")
		if strings.TrimSpace(permission) != "" {
			t.permifyPerm = strings.TrimSpace(permission)
		}
	}
}

// WithPermifyEnforcement toggles whether a configured Permify check is
// actually enforced. Default false: the binding logs loudly at construction
// and only enforces claim/path/header equality.
func WithPermifyEnforcement(enforced bool) TenantOption {
	return func(t *TenantBinding) { t.permifyEnforced = enforced }
}

// WithTenantHTTPClient overrides the Permify HTTP client (e.g. in tests).
func WithTenantHTTPClient(client *http.Client) TenantOption {
	return func(t *TenantBinding) {
		if client != nil {
			t.httpClient = client
		}
	}
}

// WithTenantBreaker wraps the Permify call in the given circuit breaker so
// a down Permify fails fast instead of stacking timeouts.
func WithTenantBreaker(b *Breaker) TenantOption {
	return func(t *TenantBinding) { t.breaker = b }
}

// NewTenantBinding builds the middleware. When a Permify URL is configured
// but enforcement is disabled (the default, e.g. PERMIFY_ENFORCE=false), a
// loud startup warning is logged because tenant authorization is then
// claim-only.
func NewTenantBinding(opts ...TenantOption) *TenantBinding {
	t := &TenantBinding{
		header:      "X-Tenant-ID",
		permifyPerm: "access",
		httpClient:  &http.Client{Timeout: 3 * time.Second},
		breaker:     NewBreaker("permify"),
	}
	for _, opt := range opts {
		opt(t)
	}
	if t.permifyURL != "" && !t.permifyEnforced {
		log.Printf("WARNING: Permify URL configured (%s) but PERMIFY_ENFORCE=false — tenant authorization is claim/header equality ONLY, Permify checks are NOT enforced", t.permifyURL)
	}
	if t.permifyURL == "" {
		log.Printf("WARNING: no Permify URL configured (PERMIFY_URL unset) — tenant authorization is claim/header equality ONLY")
	}
	return t
}

// TenantBindingFromEnv builds the middleware from PERMIFY_URL /
// PERMIFY_ENFORCE (default false) / PERMIFY_PERMISSION env vars.
func TenantBindingFromEnv(opts ...TenantOption) *TenantBinding {
	all := append([]TenantOption{
		WithPermify(envOr("PERMIFY_URL", ""), envOr("PERMIFY_PERMISSION", "access")),
		WithPermifyEnforcement(strings.EqualFold(envOr("PERMIFY_ENFORCE", "false"), "true")),
	}, opts...)
	return NewTenantBinding(all...)
}

// Middleware returns the gin middleware. It must run after GinMiddleware.
func (t *TenantBinding) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, "/health") {
			c.Next()
			return
		}
		principal, ok := PrincipalFromContext(c)
		if !ok || principal == nil || principal.TenantID == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant binding requires an authenticated tenant claim"})
			return
		}
		claimTenant := principal.TenantID
		if t.pathParam != "" {
			if pathTenant := strings.TrimSpace(c.Param(t.pathParam)); pathTenant != "" && pathTenant != claimTenant {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "path tenant does not match token tenant"})
				return
			}
		}
		if headerTenant := strings.TrimSpace(c.GetHeader(t.header)); headerTenant != "" && headerTenant != claimTenant {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "header tenant does not match token tenant"})
			return
		}
		if t.permifyEnforced && t.permifyURL != "" {
			if err := t.checkPermify(c.Request.Context(), claimTenant, principal.Subject); err != nil {
				log.Printf("permify tenant check denied tenant=%s subject=%s: %v", claimTenant, principal.Subject, err)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant authorization denied"})
				return
			}
		}
		c.Next()
	}
}

type permifyCheckRequest struct {
	Metadata struct {
		SchemaVersion string `json:"schema_version"`
		Depth         int    `json:"depth"`
	} `json:"metadata"`
	Entity struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"entity"`
	Permission string `json:"permission"`
	Subject    struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"subject"`
}

// checkPermify calls Permify's /v1/tenants/{tenant}/permissions/check API.
// Any transport error, non-200 status, or non-ALLOWED result denies.
func (t *TenantBinding) checkPermify(ctx context.Context, tenantID, subject string) error {
	return t.breaker.Execute(func() error {
		var payload permifyCheckRequest
		payload.Metadata.Depth = 20
		payload.Entity.Type = "tenant"
		payload.Entity.ID = tenantID
		payload.Permission = t.permifyPerm
		payload.Subject.Type = "user"
		payload.Subject.ID = subject
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		endpoint := fmt.Sprintf("%s/v1/tenants/%s/permissions/check", t.permifyURL, tenantID)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := t.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("permify check: %w", err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("permify check status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		var result struct {
			Can string `json:"can"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return fmt.Errorf("decode permify result: %w", err)
		}
		if !strings.EqualFold(result.Can, "RESULT_ALLOWED") {
			return fmt.Errorf("permify result %q", result.Can)
		}
		return nil
	})
}
