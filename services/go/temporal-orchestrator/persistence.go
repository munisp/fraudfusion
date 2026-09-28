package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// JourneyResultActivities persists journey outcomes to Postgres
// (journey_results, created by database/20260901_journey_results.sql),
// which is the durable system of record. The orchestrator's Redis copy is
// only a hot cache with a 1h TTL.
type JourneyResultActivities struct {
	pool *pgxpool.Pool
}

// PersistJourneyResult upserts one journey outcome. Idempotent: keyed by
// (tenant_id, journey_id) so Temporal activity retries and workflow replays
// converge to the same row.
func (a *JourneyResultActivities) PersistJourneyResult(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	if a.pool == nil {
		return nil, errors.New("journey result store not initialized (DATABASE_URL)")
	}
	journeyID, _ := params["journey_id"].(string)
	if strings.TrimSpace(journeyID) == "" {
		return nil, errors.New("journey_id required")
	}
	tenantID, _ := params["tenant_id"].(string)
	if strings.TrimSpace(tenantID) == "" {
		tenantID = "default"
	}
	journeyType, _ := params["journey_type"].(string)
	if strings.TrimSpace(journeyType) == "" {
		journeyType = "ExecuteJourneyWorkflow"
	}
	status, _ := params["status"].(string)
	switch status {
	case "completed", "failed", "compensated", "timed_out":
	default:
		return nil, fmt.Errorf("invalid journey result status %q", status)
	}
	outcome, err := json.Marshal(params["outcome"])
	if err != nil {
		return nil, fmt.Errorf("encode journey outcome: %w", err)
	}
	if len(outcome) > 1<<20 {
		return nil, errors.New("journey outcome exceeds 1MiB")
	}

	var id string
	err = a.pool.QueryRow(ctx, `
		INSERT INTO journey_results (id, tenant_id, journey_id, journey_type, status, outcome, completed_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5::jsonb, NOW())
		ON CONFLICT (tenant_id, journey_id)
		DO UPDATE SET status = EXCLUDED.status, outcome = EXCLUDED.outcome, completed_at = EXCLUDED.completed_at
		RETURNING id::text`,
		tenantID, journeyID, journeyType, status, string(outcome)).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("persist journey result %s: %w", journeyID, err)
	}
	return map[string]interface{}{"journey_result_id": id, "status": status}, nil
}

// newJourneyResultPool connects to Postgres for journey result persistence.
// Fail-closed: DATABASE_URL must be configured; a worker that cannot persist
// durably must not start.
func newJourneyResultPool(ctx context.Context) (*pgxpool.Pool, error) {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return nil, errors.New("DATABASE_URL must be configured for durable journey result persistence")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	config.MaxConns = 4
	config.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL for journey results: %w", err)
	}
	return pool, nil
}
