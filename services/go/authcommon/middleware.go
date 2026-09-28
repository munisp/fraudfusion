package authcommon

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// PrincipalContextKey is the gin context key the middleware stores the
// authenticated *Principal under.
const PrincipalContextKey = "principal"

// PrincipalFromContext extracts the authenticated principal.
func PrincipalFromContext(c *gin.Context) (*Principal, bool) {
	value, exists := c.Get(PrincipalContextKey)
	if !exists {
		return nil, false
	}
	principal, ok := value.(*Principal)
	return principal, ok
}

// GinMiddleware returns gin middleware requiring a valid bearer token for
// every route except paths ending in /health. Fail-closed: 401 on any
// validation failure.
func GinMiddleware(introspector *Introspector) gin.HandlerFunc {
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
		principal, err := introspector.Introspect(c.Request.Context(), strings.TrimPrefix(header, "Bearer "))
		if err != nil || principal == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token validation failed"})
			return
		}
		c.Set(PrincipalContextKey, principal)
		c.Next()
	}
}

// RequireRole enforces realm roles for sensitive actions. Must run after
// GinMiddleware.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := PrincipalFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		if !principal.HasRole(roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role", "required": roles})
			return
		}
		c.Next()
	}
}
