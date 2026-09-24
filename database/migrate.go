// Package database provides an embedded, golang-migrate-style migration
// runner. All database/*.sql migrations are embedded at build time and
// applied in lexical (filename) order; applied versions are recorded in a
// schema_migrations table so re-runs are idempotent.
package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed *.sql
var migrationsFS embed.FS

// AppliedMigration records one applied migration.
type AppliedMigration struct {
	Version   string
	AppliedAt time.Time
}

// MigrationFilenames returns the embedded migration filenames in application
// (lexical) order.
func MigrationFilenames() ([]string, error) {
	entries, err := migrationsFS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Migrate applies all pending embedded migrations in lexical order. Each
// migration runs in its own transaction; already-applied versions are
// skipped. databaseURL must be an absolute postgres:// URL or keyword DSN.
func Migrate(ctx context.Context, databaseURL string) ([]AppliedMigration, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, fmt.Errorf("database URL is required")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}

	names, err := MigrationFilenames()
	if err != nil {
		return nil, err
	}

	var newlyApplied []AppliedMigration
	for _, name := range names {
		if applied[name] {
			continue
		}
		contents, err := migrationsFS.ReadFile(name)
		if err != nil {
			return newlyApplied, fmt.Errorf("read migration %s: %w", name, err)
		}
		if err := applyMigration(ctx, db, name, string(contents)); err != nil {
			return newlyApplied, err
		}
		newlyApplied = append(newlyApplied, AppliedMigration{Version: name, AppliedAt: time.Now().UTC()})
	}
	return newlyApplied, nil
}

func applyMigration(ctx context.Context, db *sql.DB, name, contents string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, contents); err != nil {
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}
