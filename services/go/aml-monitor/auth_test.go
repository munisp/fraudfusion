package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestValidateJWTFailsClosed verifies malformed/unsigned tokens are denied
// and that no code path allows a request when verification is impossible.
func TestValidateJWTFailsClosed(t *testing.T) {
	t.Setenv("KEYCLOAK_URL", "http://127.0.0.1:0") // unreachable on purpose
	t.Setenv("KEYCLOAK_REALM", "fraudfusion")

	if _, err := validateJWTToken("not-a-jwt"); err == nil {
		t.Fatal("malformed token must be rejected")
	}

	// Well-formed but unsigned/forged RS256 token: must fail closed when the
	// JWKS endpoint is unreachable (previous code allowed this through).
	b64 := base64.RawURLEncoding.EncodeToString
	header := b64([]byte(`{"alg":"RS256","kid":"test","typ":"JWT"}`))
	payload := b64([]byte(`{"sub":"attacker","exp":9999999999,"iss":"http://127.0.0.1:0/realms/fraudfusion"}`))
	signature := b64([]byte("forged"))
	if _, err := validateJWTToken(strings.Join([]string{header, payload, signature}, ".")); err == nil {
		t.Fatal("forged token must be rejected when JWKS is unreachable (fail-closed)")
	} else {
		fmt.Println("fail-closed error:", err)
	}
}

func TestHasAnyRole(t *testing.T) {
	claims := &JWTClaims{Subject: "u1", Roles: []string{"viewer"}}
	if hasAnyRole(claims, "compliance_officer", "admin") {
		t.Fatal("viewer must not satisfy compliance_officer/admin")
	}
	claims.Roles = append(claims.Roles, "compliance_officer")
	if !hasAnyRole(claims, "compliance_officer", "admin") {
		t.Fatal("compliance_officer must satisfy role check")
	}
}
