// Command migrate applies the embedded database/*.sql migrations in lexical
// order, recording applied versions in schema_migrations.
//
// Usage:
//
//	DATABASE_URL=postgres://user:pass@host:5432/dbname?sslmode=require go run ./cmd/migrate
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/munisp/fraudfusion/database"
)

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required (e.g. postgres://user:pass@host:5432/fraudfusion?sslmode=require)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	applied, err := database.Migrate(ctx, databaseURL)
	if err != nil {
		log.Fatalf("migration failed: %v", err)
	}
	if len(applied) == 0 {
		fmt.Println("no pending migrations")
		return
	}
	for _, m := range applied {
		fmt.Printf("applied %s\n", m.Version)
	}
}
