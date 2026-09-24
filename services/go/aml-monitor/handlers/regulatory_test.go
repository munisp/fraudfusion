package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/munisp/fraudfusion/services/go/aml-monitor/repository"
)

func TestRequiresCTR(t *testing.T) {
	t.Setenv("CTR_THRESHOLD_NGN", "")
	if !requiresCTR("NGN", 10_000_000) {
		t.Fatal("₦10,000,000 NGN must trigger CTR at the default threshold")
	}
	if !requiresCTR("NGN", 25_000_000) {
		t.Fatal("₦25M NGN must trigger CTR")
	}
	if requiresCTR("NGN", 9_999_999.99) {
		t.Fatal("sub-threshold amount must not trigger CTR")
	}
	if requiresCTR("USD", 50_000_000) {
		t.Fatal("non-NGN currency must not trigger the NGN CTR rule")
	}
	// Configurable threshold override.
	t.Setenv("CTR_THRESHOLD_NGN", "5000000")
	if !requiresCTR("NGN", 5_000_000) {
		t.Fatal("CTR_THRESHOLD_NGN override must be honored")
	}
}

func TestSarFilingOutcomeOnlyFilesOnSuccess(t *testing.T) {
	if got := sarFilingOutcome(true); got != "filed" {
		t.Fatalf("successful filing must be filed, got %q", got)
	}
	if got := sarFilingOutcome(false); got != "filing_failed" {
		t.Fatalf("failed filing must be filing_failed (never filed), got %q", got)
	}
}

func TestFiledWithinSLA(t *testing.T) {
	t.Setenv("STR_SLA_HOURS", "")
	detected := time.Now().Add(-71 * time.Hour)
	if !filedWithinSLA(detected, time.Now()) {
		t.Fatal("filing at 71h must be within the 72h SLA")
	}
	late := time.Now().Add(-73 * time.Hour)
	if filedWithinSLA(late, time.Now()) {
		t.Fatal("filing at 73h must breach the 72h SLA")
	}
	t.Setenv("STR_SLA_HOURS", "24")
	if filedWithinSLA(detected, time.Now()) {
		t.Fatal("STR_SLA_HOURS override must tighten the deadline")
	}
}

func TestRecordSTRSLAOutcomeCountsBreaches(t *testing.T) {
	before := STRSLABreaches()
	recordSTRSLAOutcome(time.Now().Add(-100*time.Hour), time.Now())
	if STRSLABreaches() != before+1 {
		t.Fatal("late filing must increment the SLA breach metric")
	}
	recordSTRSLAOutcome(time.Now(), time.Now())
	if STRSLABreaches() != before+1 {
		t.Fatal("timely filing must not increment the breach metric")
	}
}

func TestWatchlistMatching(t *testing.T) {
	list := &Watchlist{Entries: []WatchlistEntry{
		{Name: "Boko Haram", ListName: "UN Security Council Consolidated List", Reference: "QDe.138",
			Aliases: []string{"Jama'atu Ahlis Sunna Lidda'Awati Wal-Jihad"}},
	}}
	cases := []struct {
		query     string
		wantMatch bool
		matchType string
	}{
		{"Boko Haram", true, "exact"},
		{"boko haram", true, "exact"},
		{"BOKO  HARAM!", true, "exact"},
		{"Jama'atu Ahlis Sunna Lidda'Awati Wal-Jihad", true, "alias"},
		{"Boko Harram", true, "fuzzy"},
		{"Haram Boko", true, "fuzzy"}, // token reorder
		{"Good Citizen Enterprises", false, ""},
		{"Alibaba", false, ""},
	}
	for _, tc := range cases {
		matches := list.Match(tc.query)
		if tc.wantMatch {
			if len(matches) == 0 {
				t.Fatalf("expected match for %q", tc.query)
			}
			if matches[0].ListName != "UN Security Council Consolidated List" {
				t.Fatalf("match for %q lacks real list name: %+v", tc.query, matches[0])
			}
			if matches[0].MatchType != tc.matchType {
				t.Fatalf("match for %q: type %q, want %q", tc.query, matches[0].MatchType, tc.matchType)
			}
		} else if len(matches) != 0 {
			t.Fatalf("unexpected match for %q: %+v", tc.query, matches)
		}
	}
}

func TestLoadWatchlistValidation(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "list.json")
	if err := os.WriteFile(valid, []byte(`{"entries":[{"name":"X","list_name":"L"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWatchlist(valid); err != nil {
		t.Fatalf("valid list must load: %v", err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWatchlist(empty); err == nil {
		t.Fatal("empty watchlist must fail to load")
	}
	if _, err := LoadWatchlist(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing watchlist must fail to load")
	}
}

// TestFileSARNeverMarksFailedFilingAsFiled is the DEFECT-3 regression test:
// when the regulator filing fails (unsupported authority here), the SAR must
// transition to filing_failed, never "filed".
func TestFileSARNeverMarksFailedFilingAsFiled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	repo := repository.NewAMLRepository(db, nil)
	h := NewAMLHandler(repo, nil, nil)

	sarID := "SAR-1"
	// GetSAR lookup.
	mock.ExpectQuery(`SELECT id, sar_id, user_id, filing_institution, activity_type, narrative,`).
		WithArgs(sarID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "sar_id", "user_id", "filing_institution", "activity_type", "narrative",
			"transaction_ids", "filing_date", "status", "reference_number", "filed_within_sla", "created_at", "updated_at",
		}).AddRow(1, sarID, "user-1", "inst", "fraud", "narrative", `[]`, time.Now(), "draft", "", nil, time.Now(), time.Now()))
	// The update MUST persist filing_failed — a status of "filed" here fails
	// the expectation and the test.
	mock.ExpectExec(`UPDATE aml_sars SET status=`).
		WithArgs(sarID, "filing_failed", "", false).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "sar_id", Value: sarID}}
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/aml/sar/"+sarID+"/file",
		strings.NewReader(`{"regulatory_authority":"UNKNOWN"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	h.FileSAR(c)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("failed filing must return 502, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "filing_failed" {
		t.Fatalf("failed filing must report filing_failed, got %v", body["status"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("DB expectations not met: %v", err)
	}
}
