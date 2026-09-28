package main

import (
	"testing"
	"time"
)

func TestReputationCacheTTLDefault(t *testing.T) {
	t.Setenv("REPUTATION_CACHE_TTL_SECONDS", "")
	if got := reputationCacheTTL(); got != time.Hour {
		t.Fatalf("default TTL = %v, want 1h", got)
	}
}

func TestReputationCacheTTLConfigurable(t *testing.T) {
	t.Setenv("REPUTATION_CACHE_TTL_SECONDS", "300")
	if got := reputationCacheTTL(); got != 5*time.Minute {
		t.Fatalf("configured TTL = %v, want 5m", got)
	}
	t.Setenv("REPUTATION_CACHE_TTL_SECONDS", "not-a-number")
	if got := reputationCacheTTL(); got != time.Hour {
		t.Fatalf("invalid TTL should fail back to 1h, got %v", got)
	}
	t.Setenv("REPUTATION_CACHE_TTL_SECONDS", "-5")
	if got := reputationCacheTTL(); got != time.Hour {
		t.Fatalf("negative TTL should fail back to 1h, got %v", got)
	}
}

func TestMinBaselineSamples(t *testing.T) {
	// The price-deviation baseline must require a meaningful sample and the
	// subject offer must be excluded (enforced by the SQL id <> $2 clause).
	if minBaselineSamples < 5 {
		t.Fatalf("minBaselineSamples = %d, want >= 5", minBaselineSamples)
	}
}
