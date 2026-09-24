package database

import (
	"strings"
	"testing"
)

// TestMigrationFilesEmbeddedAndOrdered verifies all 9 SQL migrations are
// embedded and sort in application order.
func TestMigrationFilesEmbeddedAndOrdered(t *testing.T) {
	names, err := MigrationFilenames()
	if err != nil {
		t.Fatalf("MigrationFilenames: %v", err)
	}
	if len(names) != 9 {
		t.Fatalf("expected 9 embedded migrations, got %d: %v", len(names), names)
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
