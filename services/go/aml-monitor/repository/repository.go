// Package repository implements Postgres (pgx stdlib) persistence and Redis
// caching for AML alerts, patterns, SARs, sanctions checks, and source-of-funds
// verifications. All SQL is parameterized; schema creation is idempotent.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/munisp/fraudfusion/services/go/aml-monitor/models"
)

// AMLRepository persists AML domain objects.
type AMLRepository struct {
	db  *sql.DB
	rdb *redis.Client
}

// NewAMLRepository builds the repository. Either handle may be nil in tests;
// methods degrade to errors instead of panics.
func NewAMLRepository(db *sql.DB, rdb *redis.Client) *AMLRepository {
	return &AMLRepository{db: db, rdb: rdb}
}

// withRetry executes op with 3 attempts and linear backoff for transient
// database/cache errors.
func withRetry(op func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = op(); err == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return err
}

// EnsureSchema idempotently creates the AML tables.
func (r *AMLRepository) EnsureSchema(ctx context.Context) error {
	if r.db == nil {
		return errors.New("repository database handle is nil")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS aml_transaction_analyses (
			id BIGSERIAL PRIMARY KEY,
			transaction_id TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			risk_score INT NOT NULL,
			risk_level TEXT NOT NULL,
			flagged BOOLEAN NOT NULL DEFAULT FALSE,
			sar_required BOOLEAN NOT NULL DEFAULT FALSE,
			risk_factors JSONB NOT NULL DEFAULT '[]',
			recommendation TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS aml_patterns (
			id BIGSERIAL PRIMARY KEY,
			user_id TEXT NOT NULL,
			pattern_type TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			confidence INT NOT NULL DEFAULT 0,
			transaction_ids JSONB NOT NULL DEFAULT '[]',
			total_amount NUMERIC NOT NULL DEFAULT 0,
			detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS aml_sars (
			id BIGSERIAL PRIMARY KEY,
			sar_id TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			filing_institution TEXT NOT NULL DEFAULT '',
			activity_type TEXT NOT NULL DEFAULT '',
			narrative TEXT NOT NULL DEFAULT '',
			transaction_ids JSONB NOT NULL DEFAULT '[]',
			filing_date TIMESTAMPTZ,
			status TEXT NOT NULL DEFAULT 'draft',
			reference_number TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS aml_sanctions_checks (
			id BIGSERIAL PRIMARY KEY,
			entity_name TEXT NOT NULL,
			entity_type TEXT NOT NULL DEFAULT '',
			is_sanctioned BOOLEAN NOT NULL DEFAULT FALSE,
			match_count INT NOT NULL DEFAULT 0,
			confidence INT NOT NULL DEFAULT 0,
			checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS aml_sof_verifications (
			id BIGSERIAL PRIMARY KEY,
			user_id TEXT NOT NULL,
			amount NUMERIC NOT NULL DEFAULT 0,
			declared_source TEXT NOT NULL DEFAULT '',
			verified BOOLEAN NOT NULL DEFAULT FALSE,
			confidence_score INT NOT NULL DEFAULT 0,
			verification_method TEXT NOT NULL DEFAULT '',
			discrepancies JSONB NOT NULL DEFAULT '[]',
			verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// STR filing SLA tracking (NFIU 72h deadline from detection).
		`ALTER TABLE aml_sars ADD COLUMN IF NOT EXISTS filed_within_sla BOOLEAN`,
		// CTR obligations (₦10M NGN currency transaction reports to the NFIU).
		`CREATE TABLE IF NOT EXISTS aml_ctr_reports (
			id BIGSERIAL PRIMARY KEY,
			transaction_id TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			amount NUMERIC NOT NULL,
			currency TEXT NOT NULL DEFAULT 'NGN',
			threshold NUMERIC NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending_report',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	}
	for _, stmt := range statements {
		if _, err := r.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("ensure AML schema: %w", err)
		}
	}
	return nil
}

func (r *AMLRepository) requireDB() error {
	if r.db == nil {
		return errors.New("repository database handle is nil")
	}
	return nil
}

// StoreTransactionAnalysis upserts a transaction analysis.
func (r *AMLRepository) StoreTransactionAnalysis(a *models.TransactionAnalysis) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	factors, err := json.Marshal(a.RiskFactors)
	if err != nil {
		return fmt.Errorf("encode risk factors: %w", err)
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.db.ExecContext(ctx, `INSERT INTO aml_transaction_analyses
			(transaction_id, user_id, risk_score, risk_level, flagged, sar_required, risk_factors, recommendation)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (transaction_id) DO UPDATE SET
			risk_score=EXCLUDED.risk_score, risk_level=EXCLUDED.risk_level, flagged=EXCLUDED.flagged,
			sar_required=EXCLUDED.sar_required, risk_factors=EXCLUDED.risk_factors, recommendation=EXCLUDED.recommendation`,
			a.TransactionID, a.UserID, a.RiskScore, a.RiskLevel, a.Flagged, a.SARRequired, factors, a.Recommendation)
		return err
	})
}

// GetTransactionAnalysis fetches the latest analysis for a transaction.
func (r *AMLRepository) GetTransactionAnalysis(transactionID string) (*models.TransactionAnalysis, error) {
	if err := r.requireDB(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a := &models.TransactionAnalysis{}
	var factors []byte
	err := r.db.QueryRowContext(ctx, `SELECT id, transaction_id, user_id, risk_score, risk_level, flagged,
		sar_required, risk_factors, recommendation, created_at FROM aml_transaction_analyses
		WHERE transaction_id=$1 ORDER BY created_at DESC LIMIT 1`, transactionID).
		Scan(&a.ID, &a.TransactionID, &a.UserID, &a.RiskScore, &a.RiskLevel, &a.Flagged, &a.SARRequired, &factors, &a.Recommendation, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(factors, &a.RiskFactors)
	return a, nil
}

// GetCachedRiskScore returns the cached risk score for a transaction.
func (r *AMLRepository) GetCachedRiskScore(transactionID string) (int, bool) {
	if r.rdb == nil {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	score, err := r.rdb.Get(ctx, "aml:risk:"+transactionID).Int()
	if err != nil {
		return 0, false
	}
	return score, true
}

// CacheRiskScore caches a risk score; errors are logged, not swallowed silently.
func (r *AMLRepository) CacheRiskScore(transactionID string, score int) {
	if r.rdb == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.rdb.Set(ctx, "aml:risk:"+transactionID, score, time.Hour).Err(); err != nil {
		log.Printf("aml: failed to cache risk score for %s: %v", transactionID, err)
	}
}

// StorePattern persists a detected suspicious pattern.
func (r *AMLRepository) StorePattern(p *models.SuspiciousPattern) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	txnIDs, err := json.Marshal(p.TransactionIDs)
	if err != nil {
		return fmt.Errorf("encode pattern transaction ids: %w", err)
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.db.ExecContext(ctx, `INSERT INTO aml_patterns
			(user_id, pattern_type, description, confidence, transaction_ids, total_amount)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			p.UserID, p.PatternType, p.Description, p.Confidence, txnIDs, p.TotalAmount)
		return err
	})
}

// GetUserPatterns lists patterns detected for a user within a lookback window.
func (r *AMLRepository) GetUserPatterns(userID string, days int, limit int) ([]*models.SuspiciousPattern, error) {
	if err := r.requireDB(); err != nil {
		return nil, err
	}
	if days <= 0 {
		days = 30
	}
	// Bound the result set: previously unbounded, scanning and marshaling
	// every pattern row for the user on each request.
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := r.db.QueryContext(ctx, `SELECT id, user_id, pattern_type, description, confidence,
		transaction_ids, total_amount, detected_at FROM aml_patterns
		WHERE user_id=$1 AND detected_at >= now() - ($2 || ' days')::interval ORDER BY detected_at DESC LIMIT $3`, userID, days, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	patterns := []*models.SuspiciousPattern{}
	for rows.Next() {
		p := &models.SuspiciousPattern{}
		var txnIDs []byte
		if err := rows.Scan(&p.ID, &p.UserID, &p.PatternType, &p.Description, &p.Confidence, &txnIDs, &p.TotalAmount, &p.DetectedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(txnIDs, &p.TransactionIDs)
		patterns = append(patterns, p)
	}
	return patterns, rows.Err()
}

// StoreSAR persists a new SAR.
func (r *AMLRepository) StoreSAR(s *models.SAR) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	txnIDs, err := json.Marshal(s.TransactionIDs)
	if err != nil {
		return fmt.Errorf("encode SAR transaction ids: %w", err)
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.db.ExecContext(ctx, `INSERT INTO aml_sars
			(sar_id, user_id, filing_institution, activity_type, narrative, transaction_ids, filing_date, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (sar_id) DO NOTHING`,
			s.SARID, s.UserID, s.FilingInstitution, s.ActivityType, s.Narrative, txnIDs, s.FilingDate, s.Status)
		return err
	})
}

// GetSAR fetches a SAR by its public ID.
func (r *AMLRepository) GetSAR(sarID string) (*models.SAR, error) {
	if err := r.requireDB(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := &models.SAR{}
	var txnIDs []byte
	err := r.db.QueryRowContext(ctx, `SELECT id, sar_id, user_id, filing_institution, activity_type, narrative,
		transaction_ids, COALESCE(filing_date, created_at), status, reference_number, filed_within_sla, created_at, updated_at
		FROM aml_sars WHERE sar_id=$1`, sarID).
		Scan(&s.ID, &s.SARID, &s.UserID, &s.FilingInstitution, &s.ActivityType, &s.Narrative, &txnIDs, &s.FilingDate, &s.Status, &s.ReferenceNumber, &s.FiledWithinSLA, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(txnIDs, &s.TransactionIDs)
	return s, nil
}

// ListSARs lists SARs with an optional status filter.
func (r *AMLRepository) ListSARs(status string, limit, offset int) ([]*models.SAR, int, error) {
	if err := r.requireDB(); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 50
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var total int
	if status == "" {
		if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM aml_sars`).Scan(&total); err != nil {
			return nil, 0, err
		}
	} else {
		if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM aml_sars WHERE status=$1`, status).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	query := `SELECT id, sar_id, user_id, filing_institution, activity_type, narrative,
		transaction_ids, COALESCE(filing_date, created_at), status, reference_number, filed_within_sla, created_at, updated_at
		FROM aml_sars`
	args := []interface{}{}
	if status != "" {
		query += ` WHERE status=$1`
		args = append(args, status)
	}
	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d OFFSET %d`, limit, offset)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	sars := []*models.SAR{}
	for rows.Next() {
		s := &models.SAR{}
		var txnIDs []byte
		if err := rows.Scan(&s.ID, &s.SARID, &s.UserID, &s.FilingInstitution, &s.ActivityType, &s.Narrative, &txnIDs, &s.FilingDate, &s.Status, &s.ReferenceNumber, &s.FiledWithinSLA, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(txnIDs, &s.TransactionIDs)
		sars = append(sars, s)
	}
	return sars, total, rows.Err()
}

// UpdateSARStatus updates the filing status of a SAR.
func (r *AMLRepository) UpdateSARStatus(sarID, status, referenceNumber string) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := r.db.ExecContext(ctx, `UPDATE aml_sars SET status=$2, reference_number=$3,
			filing_date=CASE WHEN $2='filed' THEN now() ELSE filing_date END, updated_at=now()
			WHERE sar_id=$1`, sarID, status, referenceNumber)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err == nil && affected == 0 {
			return sql.ErrNoRows
		}
		return err
	})
}

// UpdateSARFiling records the outcome of a regulator filing attempt,
// including whether the filing met the 72h NFIU STR deadline from detection.
func (r *AMLRepository) UpdateSARFiling(sarID, status, referenceNumber string, filedWithinSLA bool) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := r.db.ExecContext(ctx, `UPDATE aml_sars SET status=$2, reference_number=$3,
			filed_within_sla=$4,
			filing_date=CASE WHEN $2='filed' THEN now() ELSE filing_date END, updated_at=now()
			WHERE sar_id=$1`, sarID, status, referenceNumber, filedWithinSLA)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err == nil && affected == 0 {
			return sql.ErrNoRows
		}
		return err
	})
}

// CountOverdueUnfiledSARs counts SARs that are still unfiled past the STR
// deadline — the breach alert metric for the compliance endpoint.
func (r *AMLRepository) CountOverdueUnfiledSARs(sla time.Duration) (int, error) {
	if err := r.requireDB(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM aml_sars
		WHERE status NOT IN ('filed') AND created_at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(sla.Seconds()))).Scan(&count)
	return count, err
}

// StoreCTRReport records a CTR obligation (idempotent per transaction).
func (r *AMLRepository) StoreCTRReport(report *models.CTRReport) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.db.ExecContext(ctx, `INSERT INTO aml_ctr_reports
			(transaction_id, user_id, amount, currency, threshold, status)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (transaction_id) DO NOTHING`,
			report.TransactionID, report.UserID, report.Amount, report.Currency, report.Threshold, report.Status)
		return err
	})
}

// GetCachedSanctionsCheck returns a cached sanctions result.
func (r *AMLRepository) GetCachedSanctionsCheck(entityName string) (*models.CachedSanctionsResult, bool) {
	if r.rdb == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := r.rdb.Get(ctx, "aml:sanctions:"+entityName).Bytes()
	if err != nil {
		return nil, false
	}
	result := &models.CachedSanctionsResult{}
	if err := json.Unmarshal(raw, result); err != nil {
		return nil, false
	}
	return result, true
}

// CacheSanctionsCheck caches a sanctions result; failures are logged.
func (r *AMLRepository) CacheSanctionsCheck(entityName string, sanctioned bool, matches []*models.SanctionsMatch) error {
	if r.rdb == nil {
		return nil
	}
	raw, err := json.Marshal(&models.CachedSanctionsResult{IsSanctioned: sanctioned, Matches: matches})
	if err != nil {
		return fmt.Errorf("encode sanctions cache entry: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.rdb.Set(ctx, "aml:sanctions:"+entityName, raw, 24*time.Hour).Err(); err != nil {
		log.Printf("aml: failed to cache sanctions check for %s: %v", entityName, err)
		return err
	}
	return nil
}

// StoreSanctionsCheck persists a sanctions screening result.
func (r *AMLRepository) StoreSanctionsCheck(c *models.SanctionsCheck) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.db.ExecContext(ctx, `INSERT INTO aml_sanctions_checks
			(entity_name, entity_type, is_sanctioned, match_count, confidence)
			VALUES ($1,$2,$3,$4,$5)`,
			c.EntityName, c.EntityType, c.IsSanctioned, c.MatchCount, c.Confidence)
		return err
	})
}

// GetEntitySanctionsHistory returns prior checks for an entity name.
func (r *AMLRepository) GetEntitySanctionsHistory(entityID string) ([]*models.SanctionsCheck, error) {
	if err := r.requireDB(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := r.db.QueryContext(ctx, `SELECT id, entity_name, entity_type, is_sanctioned, match_count,
		confidence, checked_at FROM aml_sanctions_checks WHERE entity_name=$1 ORDER BY checked_at DESC LIMIT 100`, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	checks := []*models.SanctionsCheck{}
	for rows.Next() {
		c := &models.SanctionsCheck{}
		if err := rows.Scan(&c.ID, &c.EntityName, &c.EntityType, &c.IsSanctioned, &c.MatchCount, &c.Confidence, &c.CheckedAt); err != nil {
			return nil, err
		}
		checks = append(checks, c)
	}
	return checks, rows.Err()
}

// StoreSourceOfFundsVerification persists a SoF verification result.
func (r *AMLRepository) StoreSourceOfFundsVerification(v *models.SourceOfFundsVerification) error {
	if err := r.requireDB(); err != nil {
		return err
	}
	discrepancies, err := json.Marshal(v.Discrepancies)
	if err != nil {
		return fmt.Errorf("encode discrepancies: %w", err)
	}
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.db.ExecContext(ctx, `INSERT INTO aml_sof_verifications
			(user_id, amount, declared_source, verified, confidence_score, verification_method, discrepancies)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			v.UserID, v.Amount, v.DeclaredSource, v.Verified, v.ConfidenceScore, v.VerificationMethod, discrepancies)
		return err
	})
}

// GetDailyReport aggregates AML activity for a UTC day.
func (r *AMLRepository) GetDailyReport(date time.Time) (*models.DailyReport, error) {
	if err := r.requireDB(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	report := &models.DailyReport{Date: start}
	// The four aggregates touch different tables, so they run concurrently
	// instead of serially (worst-case latency = slowest scan, not the sum).
	// The two aml_sars counts are merged into one scan with FILTER.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	wg.Add(4)
	go func() {
		defer wg.Done()
		errs[0] = r.db.QueryRowContext(ctx, `SELECT COUNT(*),
			COUNT(*) FILTER (WHERE flagged),
			COUNT(*) FILTER (WHERE risk_level IN ('high','critical','manual_review')),
			COALESCE(AVG(risk_score),0) FROM aml_transaction_analyses
			WHERE created_at >= $1 AND created_at < $2`, start, end).
			Scan(&report.TotalTransactions, &report.FlaggedTransactions, &report.HighRiskTransactions, &report.AverageRiskScore)
	}()
	go func() {
		defer wg.Done()
		errs[1] = r.db.QueryRowContext(ctx, `SELECT COUNT(*),
			COUNT(*) FILTER (WHERE status='filed' AND updated_at >= $1 AND updated_at < $2)
			FROM aml_sars WHERE created_at >= $1 AND created_at < $2`, start, end).
			Scan(&report.SARsGenerated, &report.SARsFiled)
	}()
	go func() {
		defer wg.Done()
		errs[2] = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM aml_patterns WHERE detected_at >= $1 AND detected_at < $2`, start, end).Scan(&report.PatternsDetected)
	}()
	go func() {
		defer wg.Done()
		errs[3] = r.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_sanctioned) FROM aml_sanctions_checks WHERE checked_at >= $1 AND checked_at < $2`, start, end).Scan(&report.SanctionsChecks, &report.SanctionsMatches)
	}()
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return report, nil
}

// GetFlaggedTransactions lists flagged analyses with an optional risk filter.
func (r *AMLRepository) GetFlaggedTransactions(riskLevel string, limit, offset int) ([]*models.TransactionAnalysis, int, error) {
	if err := r.requireDB(); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 50
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	where := `WHERE flagged=TRUE`
	args := []interface{}{}
	if riskLevel != "" {
		where += ` AND risk_level=$1`
		args = append(args, riskLevel)
	}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM aml_transaction_analyses `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, transaction_id, user_id, risk_score, risk_level, flagged,
		sar_required, risk_factors, recommendation, created_at FROM aml_transaction_analyses `+where+
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d OFFSET %d`, limit, offset), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	transactions := []*models.TransactionAnalysis{}
	for rows.Next() {
		a := &models.TransactionAnalysis{}
		var factors []byte
		if err := rows.Scan(&a.ID, &a.TransactionID, &a.UserID, &a.RiskScore, &a.RiskLevel, &a.Flagged, &a.SARRequired, &factors, &a.Recommendation, &a.CreatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(factors, &a.RiskFactors)
		transactions = append(transactions, a)
	}
	return transactions, total, rows.Err()
}
