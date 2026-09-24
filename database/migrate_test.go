package database

import (
	"strings"
	"testing"
)

// TestMigrationFilesEmbeddedAndOrdered verifies all SQL migrations are
// embedded and sort in application order. The count is a floor, not an
// exact match: new dated migrations are added over time.
func TestMigrationFilesEmbeddedAndOrdered(t *testing.T) {
	names, err := MigrationFilenames()
	if err != nil {
		t.Fatalf("MigrationFilenames: %v", err)
	}
	if len(names) < 9 {
		t.Fatalf("expected at least 9 embedded migrations, got %d: %v", len(names), names)
	}
	if names[0] != "20260801_chargeback_fraud_schema.sql" {
		t.Fatalf("base schema must sort first, got %s", names[0])
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("migrations not lexically ordered: %v", names)
		}
	}
}

// TestServiceBaseTablesMigration covers the detector base tables that the
// ALTER-only hardening migrations (20260820_*) depend on: the 20260827
// migration must create every table the services query, idempotently.
func TestServiceBaseTablesMigration(t *testing.T) {
	raw, err := migrationsFS.ReadFile("20260827_service_base_tables.sql")
	if err != nil {
		t.Fatalf("read base tables migration: %v", err)
	}
	contents := string(raw)
	requiredTables := []string{
		"ato_events", "ato_alerts", "login_patterns", "device_fingerprints",
		"credential_stuffing_attempts", "sim_swap_events", "account_access_logs",
		"sim_swap_alerts", "insider_fraud_events", "privileged_access_logs",
		"unusual_activities", "data_exfiltration_attempts", "insider_fraud_alerts",
		"crypto_transactions", "crypto_blacklist", "p2p_trades", "p2p_trading_alerts",
		"advance_fee_messages", "investment_schemes", "sec_registered_entities",
		"identity_theft_alerts",
	}
	for _, table := range requiredTables {
		if !strings.Contains(contents, "CREATE TABLE IF NOT EXISTS "+table+" ") {
			t.Fatalf("base tables migration missing idempotent CREATE TABLE for %s", table)
		}
	}
	// sim-swap queries device_fingerprints.first_seen_at; the column must exist.
	if !strings.Contains(contents, "first_seen_at TIMESTAMPTZ") {
		t.Fatalf("device_fingerprints must include first_seen_at (queried by sim-swap detector)")
	}
	// sec_registered_entities must be seeded so the SEC check has real data.
	if !strings.Contains(contents, "INSERT INTO sec_registered_entities") ||
		!strings.Contains(contents, "ON CONFLICT (name) DO NOTHING") {
		t.Fatalf("sec_registered_entities must be seeded idempotently")
	}
}

// TestMigrationsParseSanity performs structural checks we can do without a
// live Postgres: non-empty content, balanced dollar-quoting, and balanced
// BEGIN/COMMIT when explicit transactions are used.
func TestMigrationsParseSanity(t *testing.T) {
	names, err := MigrationFilenames()
	if err != nil {
		t.Fatalf("MigrationFilenames: %v", err)
	}
	for _, name := range names {
		raw, err := migrationsFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		contents := string(raw)
		if strings.TrimSpace(contents) == "" {
			t.Fatalf("%s is empty", name)
		}
		if got := strings.Count(contents, "$$"); got%2 != 0 {
			t.Fatalf("%s has unbalanced $$ dollar quoting (%d occurrences)", name, got)
		}
		begins := strings.Count(strings.ToUpper(contents), "\nBEGIN;")
		commits := strings.Count(strings.ToUpper(contents), "COMMIT;")
		if begins > 0 && commits == 0 {
			t.Fatalf("%s opens explicit transactions (%d) but has no COMMIT", name, begins)
		}
	}
}

// TestInsiderSoDMigration verifies the segregation-of-duties migration ships
// idempotent DDL for every object the insider-fraud-detector service queries.
func TestInsiderSoDMigration(t *testing.T) {
	raw, err := migrationsFS.ReadFile("20260828_insider_sod.sql")
	if err != nil {
		t.Fatalf("read insider SoD migration: %v", err)
	}
	contents := string(raw)
	for _, table := range []string{
		"sod_matrix", "sod_assignments", "sod_violations",
		"employee_vendor_overlap", "access_review_campaigns", "expense_claims",
	} {
		if !strings.Contains(contents, "CREATE TABLE IF NOT EXISTS "+table+" ") {
			t.Fatalf("insider SoD migration missing idempotent CREATE TABLE for %s", table)
		}
	}
	for _, fn := range []string{"sod_check_assignment", "sod_enforce_assignment", "vacation_compliance_pct"} {
		if !strings.Contains(contents, "CREATE OR REPLACE FUNCTION "+fn) {
			t.Fatalf("insider SoD migration missing function %s", fn)
		}
	}
	if !strings.Contains(contents, "CREATE TRIGGER sod_assignments_enforce") {
		t.Fatal("insider SoD migration must install the fail-closed assignment trigger")
	}
	// seeded incompatible-duty pairs the program document cites
	for _, pair := range [][2]string{
		{"approve_payment", "initiate_payment"},
		{"approve_user", "create_user"},
		{"delete_audit", "export_data"},
		{"file_sar", "modify_watchlist"},
	} {
		if !strings.Contains(contents, "'"+pair[0]+"'") || !strings.Contains(contents, "'"+pair[1]+"'") {
			t.Fatalf("sod_matrix seed missing pair %v", pair)
		}
	}
	if !strings.Contains(contents, "ON CONFLICT DO NOTHING") {
		t.Fatal("sod_matrix seed must be idempotent (ON CONFLICT DO NOTHING)")
	}
}
