package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/munisp/fraudfusion/services/go/authcommon"
)

// Authentication/authorization is consolidated in services/go/authcommon
// (shared Keycloak introspection with TTL cache + singleflight, RS256
// JWT/JWKS verifier, tenant binding). This file only wires the shared
// module into this service; the previous local copy was deleted.

// authPrincipal is kept as an alias for existing call sites.
type authPrincipal = authcommon.Principal

func authMiddleware() gin.HandlerFunc {
	introspector, err := authcommon.NewIntrospector(authcommon.FromEnv()...)
	if err != nil {
		panic(fmt.Sprintf("auth middleware configuration: %v", err))
	}
	return authcommon.GinMiddleware(introspector)
}

// tenantBindingMiddleware asserts token tenant_id == path/header tenant and,
// when PERMIFY_URL is set and PERMIFY_ENFORCE=true, checks Permify.
// PERMIFY_ENFORCE defaults to false (authcommon logs a loud startup warning).
func tenantBindingMiddleware() gin.HandlerFunc {
	return authcommon.TenantBindingFromEnv().Middleware()
}

// requireRole enforces realm roles for destructive actions.
func requireRole(roles ...string) gin.HandlerFunc { return authcommon.RequireRole(roles...) }

func principalHasRole(p *authPrincipal, roles ...string) bool { return p.HasRole(roles...) }

// withBackoff retries op with capped exponential backoff (5 attempts).
func withBackoff(op func() error) error { return authcommon.WithBackoff(op) }
