package main

import (
	"context"
	"testing"
)

func TestRequiredHTTPSURL(t *testing.T) {
	t.Setenv("TEST_HTTPS_URL", "https://identity.example.test/introspect")
	value, err := requiredHTTPSURL("TEST_HTTPS_URL")
	if err != nil || value != "https://identity.example.test/introspect" {
		t.Fatalf("valid HTTPS URL rejected: value=%q err=%v", value, err)
	}
	for _, value := range []string{"http://identity.example.test/introspect", "https://user:password@identity.example.test/introspect", "not-a-url"} {
		t.Setenv("TEST_HTTPS_URL", value)
		if _, err = requiredHTTPSURL("TEST_HTTPS_URL"); err == nil {
			t.Fatalf("insecure URL accepted: %q", value)
		}
	}
}

func TestProductionPoolRequiresVerifyFull(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://ledger@db.example.test:5432/ledger?sslmode=disable")
	if _, err := newProductionPool(context.Background()); err == nil {
		t.Fatal("database URL without verify-full TLS accepted")
	}
	t.Setenv("DATABASE_URL", "postgresql://ledger@db.example.test:5432/ledger?sslmode=verify-full")
	pool, err := newProductionPool(context.Background())
	if err != nil {
		t.Fatalf("valid production database URL rejected: %v", err)
	}
	pool.Close()
}

func TestHostAllowed(t *testing.T) {
	if !hostAllowed("provider.example.test", []string{"provider.example.test", "backup.example.test"}) {
		t.Fatal("configured provider host rejected")
	}
	if !hostAllowed("PROVIDER.example.test", []string{"provider.example.test"}) {
		t.Fatal("host comparison should be case-insensitive")
	}
	if hostAllowed("attacker.example.test", []string{"provider.example.test"}) {
		t.Fatal("unallowlisted provider host accepted")
	}
}
