package main

import (
	"testing"
	"time"
)

func TestAccessRiskUsesTimeResourceAndVelocity(t *testing.T) {
	event := accessEvent{EmployeeID: "employee-1", Resource: "ledger", Timestamp: time.Date(2026, 8, 20, 23, 30, 0, 0, time.UTC)}
	score, factors := accessRisk(event, history{total: 20, privileged: 10})
	if score != 85 {
		t.Fatalf("score = %d, want 85", score)
	}
	if len(factors) != 4 {
		t.Fatalf("factor count = %d, want 4: %#v", len(factors), factors)
	}
	if riskLevel(score) != "critical" {
		t.Fatalf("riskLevel(%d) = %s, want critical", score, riskLevel(score))
	}
}

func TestUnusualAccessThresholdScalesWithWindow(t *testing.T) {
	if got := unusualAccessThreshold(1); got != 10 {
		t.Fatalf("unusualAccessThreshold(1) = %d, want 10", got)
	}
	if got := unusualAccessThreshold(8); got != 24 {
		t.Fatalf("unusualAccessThreshold(8) = %d, want 24", got)
	}
}

func TestExternalDestinationDetection(t *testing.T) {
	for _, destination := range []string{"external", "personal_email", "https://example.test/exfiltration"} {
		if !isExternalDestination(destination) {
			t.Errorf("isExternalDestination(%q) = false, want true", destination)
		}
	}
	if isExternalDestination("approved_internal_archive") {
		t.Fatal("approved internal destination must not be classified as external")
	}
}

func TestAfterHoursPolicyTimezoneExplicit(t *testing.T) {
	lagos, err := time.LoadLocation("Africa/Lagos")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	policy := afterHoursPolicy{Timezone: "Africa/Lagos", BusinessStart: 6, BusinessEnd: 22, WeekendAllDay: true}

	// 2026-09-28 is a Monday. 12:00 Lagos (UTC+1) = 11:00 UTC: business hours.
	mondayNoon := time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC)
	if got := mondayNoon.In(lagos).Hour(); got != 12 {
		t.Fatalf("test setup: Lagos hour = %d, want 12", got)
	}
	if policy.isAfterHours(mondayNoon) {
		t.Fatal("Monday 12:00 Lagos should be business hours")
	}
	// 23:30 Lagos = 22:30 UTC: after hours even though UTC hour is 22.
	mondayNight := time.Date(2026, 9, 28, 22, 30, 0, 0, time.UTC)
	if !policy.isAfterHours(mondayNight) {
		t.Fatal("Monday 23:30 Lagos should be after hours")
	}
	// Weekend: 2026-09-27 is a Sunday; midday still after hours.
	sundayNoon := time.Date(2026, 9, 27, 11, 0, 0, 0, time.UTC)
	if !policy.isAfterHours(sundayNoon) {
		t.Fatal("Sunday 12:00 Lagos should be after hours with WeekendAllDay")
	}
	// Weekend awareness disabled: Sunday midday is business hours.
	policy.WeekendAllDay = false
	if policy.isAfterHours(sundayNoon) {
		t.Fatal("Sunday 12:00 Lagos should be business hours when WeekendAllDay=false")
	}
}

func TestLoadAfterHoursPolicyDefaults(t *testing.T) {
	t.Setenv("AFTER_HOURS_TIMEZONE", "")
	t.Setenv("AFTER_HOURS_BUSINESS_START", "")
	t.Setenv("AFTER_HOURS_BUSINESS_END", "")
	t.Setenv("AFTER_HOURS_WEEKEND_ALL_DAY", "")
	p := loadAfterHoursPolicy()
	if p.Timezone != "Africa/Lagos" || p.BusinessStart != 6 || p.BusinessEnd != 22 || !p.WeekendAllDay {
		t.Fatalf("defaults = %+v", p)
	}
	t.Setenv("AFTER_HOURS_TIMEZONE", "Not/AZone")
	if p := loadAfterHoursPolicy(); p.Timezone != "Africa/Lagos" {
		t.Fatalf("invalid timezone must fall back to Africa/Lagos, got %q", p.Timezone)
	}
	t.Setenv("AFTER_HOURS_TIMEZONE", "UTC")
	t.Setenv("AFTER_HOURS_BUSINESS_START", "8")
	t.Setenv("AFTER_HOURS_BUSINESS_END", "18")
	t.Setenv("AFTER_HOURS_WEEKEND_ALL_DAY", "false")
	p = loadAfterHoursPolicy()
	if p.Timezone != "UTC" || p.BusinessStart != 8 || p.BusinessEnd != 18 || p.WeekendAllDay {
		t.Fatalf("configured policy = %+v", p)
	}
}
