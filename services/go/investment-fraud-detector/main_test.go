package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

// setTestDB swaps the package-level DB handle and returns the previous one.
func setTestDB(d *sql.DB) *sql.DB {
	prev := db
	db = d
	return prev
}

// TestCheckSECRegistrationUnavailableVsUnregistered is the DEFECT-9
// regression test: a registry outage must surface an error (so callers apply
// caution, not the full "not registered" penalty), while a genuine miss
// returns registered=false with a nil error.
func TestCheckSECRegistrationUnavailableVsUnregistered(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	prevDB := setTestDB(db)
	defer setTestDB(prevDB)

	// Genuine miss: not in the SEC registry.
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("MMM Global Clone", "promo-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	registered, err := checkSECRegistration("MMM Global Clone", "promo-1")
	if err != nil || registered {
		t.Fatalf("unregistered scheme: got registered=%v err=%v", registered, err)
	}

	// Case-insensitive hit on a seeded entity.
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("stanbic ibtc asset management limited", "").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	registered, err = checkSECRegistration("stanbic ibtc asset management limited", "")
	if err != nil || !registered {
		t.Fatalf("registered entity: got registered=%v err=%v", registered, err)
	}

	// Registry error propagates (caller must NOT treat as "not registered").
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("Anything", "").
		WillReturnError(sqlmock.ErrCancelled)
	if _, err := checkSECRegistration("Anything", ""); err == nil {
		t.Fatal("registry errors must propagate")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestCheckSECRegistrationNilDBFailsClosed proves a missing DB handle is an
// error, not a silent "not registered".
func TestCheckSECRegistrationNilDBFailsClosed(t *testing.T) {
	prevDB := setTestDB(nil)
	defer setTestDB(prevDB)
	if _, err := checkSECRegistration("X", ""); err == nil {
		t.Fatal("nil DB must error")
	}
}

// TestGetDailyReportQueriesRealData proves the daily report reads from
// investment_schemes rather than returning hardcoded zeros.
func TestGetDailyReportQueriesRealData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	prevDB := setTestDB(db)
	defer setTestDB(prevDB)

	date := "2026-08-27"
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs(date).
		WillReturnRows(sqlmock.NewRows([]string{"count", "ponzi", "sec", "avg"}).AddRow(12, 3, 5, 61.5))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/investment/reports/daily?date="+date, nil)

	getDailyReport(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["schemes_analyzed"].(float64) != 12 || body["ponzi_detected"].(float64) != 3 {
		t.Fatalf("report must reflect real DB counts: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestGetFlaggedSchemesQueriesRealData proves flagged schemes come from the
// database ordered by risk, not an empty stub.
func TestGetFlaggedSchemesQueriesRealData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	prevDB := setTestDB(db)
	defer setTestDB(prevDB)

	mock.ExpectQuery(`SELECT id, name, promoter_id`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "promoter_id", "promised_returns", "risk_score", "risk_level", "is_ponzi", "sec_registered", "created_at",
		}).AddRow("sch-1", "Double Money Fast", "promo-9", 80.0, 95, "critical", true, false, time.Now()))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/investment/schemes/flagged", nil)

	getFlaggedSchemes(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Double Money Fast") {
		t.Fatalf("expected real DB row in response: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestVerifySECRegistrationServiceUnavailable proves the endpoint is honest
// when the registry cannot be reached.
func TestVerifySECRegistrationServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	prevDB := setTestDB(nil)
	defer setTestDB(prevDB)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/investment/sec/verify",
		strings.NewReader(`{"entity_name":"X"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	verifySECRegistration(c)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}
