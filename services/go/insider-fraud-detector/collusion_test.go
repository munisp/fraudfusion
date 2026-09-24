package main

import "testing"

// TestCollusionOutcome is the regression test for the "one shared privileged
// resource = collusion" defect: detection requires at least two distinct
// shared privileged resources (configurable), and anything below scores 0.
func TestCollusionOutcome(t *testing.T) {
	cases := []struct {
		name      string
		shared    int
		minShared int
		detected  bool
		score     int
	}{
		{"none", 0, 2, false, 0},
		{"single resource is teamwork", 1, 2, false, 0},
		{"two resources at default threshold", 2, 2, true, 70},
		{"three resources", 3, 2, true, 100}, // capped at 100
		{"below raised threshold", 2, 3, false, 0},
		{"at raised threshold", 3, 3, true, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detected, score, factors := collusionOutcome(tc.shared, tc.minShared)
			if detected != tc.detected {
				t.Fatalf("detected = %v, want %v", detected, tc.detected)
			}
			if score != tc.score {
				t.Fatalf("score = %d, want %d", score, tc.score)
			}
			if detected && len(factors) == 0 {
				t.Fatal("detection must record a factor")
			}
			if !detected && tc.shared > 0 && len(factors) == 0 {
				t.Fatal("below-threshold case must explain why no alert fired")
			}
		})
	}
}

// TestCollusionThresholdConfigurable covers COLLUSION_MIN_SHARED_RESOURCES.
func TestCollusionThresholdConfigurable(t *testing.T) {
	t.Setenv("COLLUSION_MIN_SHARED_RESOURCES", "")
	if got := collusionMinSharedResources(); got != 2 {
		t.Fatalf("default threshold = 2, got %d", got)
	}
	t.Setenv("COLLUSION_MIN_SHARED_RESOURCES", "3")
	if got := collusionMinSharedResources(); got != 3 {
		t.Fatalf("env override = 3, got %d", got)
	}
	t.Setenv("COLLUSION_MIN_SHARED_RESOURCES", "bogus")
	if got := collusionMinSharedResources(); got != 2 {
		t.Fatalf("invalid override must fall back to 2, got %d", got)
	}
}
