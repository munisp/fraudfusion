package workflows

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestActivitiesFailLoudlyWithoutServiceURL proves the journey activities
// error out when the downstream service URL is not configured instead of
// returning fabricated data.
func TestActivitiesFailLoudlyWithoutServiceURL(t *testing.T) {
	t.Setenv(LandVerificationURLEnv, "")
	t.Setenv(BookingServiceURLEnv, "")
	t.Setenv(NotificationServiceURLEnv, "")

	ctx := context.Background()
	if _, err := ExtractLandDetailsActivity(ctx, "ZG9j"); err == nil {
		t.Fatal("ExtractLandDetailsActivity must fail when LAND_VERIFICATION_URL is unset")
	}
	if _, err := DetectMultipleClaimantsActivity(ctx, map[string]interface{}{"property_address": "x", "state": "Lagos"}); err == nil {
		t.Fatal("DetectMultipleClaimantsActivity must fail when LAND_VERIFICATION_URL is unset")
	}
	if _, err := SearchCourtDisputesActivity(ctx, map[string]interface{}{"property_address": "x"}); err == nil {
		t.Fatal("SearchCourtDisputesActivity must fail when LAND_VERIFICATION_URL is unset")
	}
	if _, err := SearchProfessionalDirectoryActivity(ctx, map[string]interface{}{"professional_type": "lawyer", "state": "Lagos"}); err == nil {
		t.Fatal("SearchProfessionalDirectoryActivity must fail when LAND_VERIFICATION_URL is unset")
	}
	if _, err := CreateBookingActivity(ctx, map[string]interface{}{
		"user_id": "u", "professional_id": "p", "date": "2026-01-01", "start_time": "10:00", "consultation_type": "virtual",
	}); err == nil {
		t.Fatal("CreateBookingActivity must fail when BOOKING_SERVICE_URL is unset")
	}
	if _, err := SendBookingNotificationsActivity(ctx, map[string]interface{}{
		"booking_id": "b", "user_id": "u", "professional_id": "p",
	}); err == nil {
		t.Fatal("SendBookingNotificationsActivity must fail when NOTIFICATION_SERVICE_URL is unset")
	}
}

// TestActivitiesFailLoudlyOnServiceError proves HTTP 500s propagate as errors.
func TestActivitiesFailLoudlyOnServiceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv(LandVerificationURLEnv, server.URL)

	ctx := context.Background()
	if _, err := DetectMultipleClaimantsActivity(ctx, map[string]interface{}{"property_address": "x", "state": "Lagos"}); err == nil {
		t.Fatal("expected error on downstream 500")
	}
	if _, err := SearchCourtDisputesActivity(ctx, map[string]interface{}{"property_address": "x"}); err == nil {
		t.Fatal("expected error on downstream 500")
	}
}

// TestActivitiesUseRealServiceResponses proves decoded downstream data is
// returned verbatim (and re-filtered for directory search).
func TestActivitiesUseRealServiceResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/detect-claimants"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"claimants": []map[string]interface{}{
				{"name": "Real Claimant", "claim_date": "2024-01-01T00:00:00Z", "document_type": "C of O", "document_ref": "X/1", "verified": true, "conflicting": false},
			}})
		case strings.HasSuffix(r.URL.Path, "/court-disputes"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"disputes": []map[string]interface{}{}})
		case strings.HasSuffix(r.URL.Path, "/professionals/search"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"professionals": []map[string]interface{}{
				{"id": "P1", "name": "Real Lawyer", "type": "lawyer", "state": "Lagos", "rating": 4.9, "contact": map[string]interface{}{"phone": "+234"}},
				{"id": "P2", "name": "Wrong State", "type": "lawyer", "state": "Kano", "rating": 5.0},
			}})
		default:
			http.Error(w, "unknown path", http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv(LandVerificationURLEnv, server.URL)

	ctx := context.Background()
	claimants, err := DetectMultipleClaimantsActivity(ctx, map[string]interface{}{"property_address": "x", "state": "Lagos"})
	if err != nil || len(claimants) != 1 || claimants[0].Name != "Real Claimant" {
		t.Fatalf("claimants = %+v, err = %v", claimants, err)
	}
	disputes, err := SearchCourtDisputesActivity(ctx, map[string]interface{}{"property_address": "x"})
	if err != nil || len(disputes) != 0 {
		t.Fatalf("disputes = %+v, err = %v", disputes, err)
	}
	pros, err := SearchProfessionalDirectoryActivity(ctx, map[string]interface{}{"professional_type": "lawyer", "state": "Lagos", "min_rating": 4.0})
	if err != nil || len(pros) != 1 || pros[0].ID != "P1" {
		t.Fatalf("professionals = %+v, err = %v", pros, err)
	}
}

// TestCreateBookingRequiresServiceBookingID ensures a booking is rejected when
// the service does not mint a booking ID.
func TestCreateBookingRequiresServiceBookingID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "confirmed"})
	}))
	defer server.Close()
	t.Setenv(BookingServiceURLEnv, server.URL)

	input := map[string]interface{}{
		"user_id": "u", "professional_id": "p", "date": "2026-01-01", "start_time": "10:00", "consultation_type": "virtual",
	}
	if _, err := CreateBookingActivity(context.Background(), input); err == nil {
		t.Fatal("expected error when booking service omits booking_id")
	}
}
