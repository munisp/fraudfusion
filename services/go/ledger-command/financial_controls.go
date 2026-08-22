package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

const maxStatementEntries = 10000

type reconciliationRequest struct {
	Provider      string                   `json:"provider" binding:"required,max=80"`
	StatementAsOf string                   `json:"statement_as_of" binding:"required"`
	Entries       []providerStatementEntry `json:"entries" binding:"required,min=1,max=10000"`
}

type providerStatementEntry struct {
	ProviderReference string `json:"provider_reference" binding:"required,max=255"`
	Amount            string `json:"amount" binding:"required"`
	Currency          string `json:"currency" binding:"required,len=3"`
	Status            string `json:"status" binding:"required,oneof=accepted settled rejected reversed"`
	OccurredAt        string `json:"occurred_at" binding:"required"`
}

type reconciliationResponse struct {
	RunID       string `json:"run_id"`
	Created     bool   `json:"created"`
	BreakCount  int    `json:"break_count"`
	Matched     int    `json:"matched"`
	StatementID string `json:"statement_sha256"`
}

type reconciliationBreakResponse struct {
	ID         string          `json:"id"`
	Settlement string          `json:"settlement_id,omitempty"`
	Severity   string          `json:"severity"`
	BreakType  string          `json:"break_type"`
	Status     string          `json:"status"`
	Expected   json.RawMessage `json:"expected"`
	Observed   json.RawMessage `json:"observed"`
	CreatedAt  string          `json:"created_at"`
	ResolvedAt string          `json:"resolved_at,omitempty"`
	ResolvedBy string          `json:"resolved_by,omitempty"`
}

type resolveBreakRequest struct {
	Status string `json:"status" binding:"required,oneof=resolved waived"`
	Reason string `json:"reason" binding:"required,min=8,max=1024"`
}

type financialCloseRequest struct {
	PeriodStart string `json:"period_start" binding:"required"`
	PeriodEnd   string `json:"period_end" binding:"required"`
}

type financialCloseResponse struct {
	CloseID        string `json:"close_id"`
	Status         string `json:"status"`
	SnapshotSHA256 string `json:"ledger_snapshot_sha256"`
}

type reopenCloseRequest struct {
	Reason string `json:"reason" binding:"required,min=8,max=1024"`
}

func (s *service) createReconciliationRun(c *gin.Context) {
	if s.dispatcher == nil || s.dispatcher.provider == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "settlement provider control unavailable"})
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBytes))
	if err != nil {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "statement exceeds size limit"})
		return
	}
	if !verifyProviderSignature(s.dispatcher.provider.callbackKey, c.GetHeader("X-Provider-Statement-Timestamp"), c.GetHeader("X-Provider-Statement-Signature"), raw, time.Now().UTC()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "provider statement signature invalid"})
		return
	}
	var request reconciliationRequest
	if err = json.Unmarshal(raw, &request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reconciliation statement"})
		return
	}
	if request.Provider != s.dispatcher.provider.name || len(request.Entries) == 0 || len(request.Entries) > maxStatementEntries {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider or statement entries invalid"})
		return
	}
	statementDate, err := time.Parse("2006-01-02", request.StatementAsOf)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "statement_as_of must be YYYY-MM-DD"})
		return
	}
	for index := range request.Entries {
		request.Entries[index].Currency = strings.ToUpper(request.Entries[index].Currency)
		if !validAmount(request.Entries[index].Amount) || request.Entries[index].ProviderReference == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "statement entry amount or provider reference invalid"})
			return
		}
		if _, err = time.Parse(time.RFC3339, request.Entries[index].OccurredAt); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "statement entry occurred_at must be RFC3339"})
			return
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	response, err := s.reconcile(ctx, requestPrincipal(c), request, statementDate, raw)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reconciliation persistence unavailable"})
		return
	}
	status := http.StatusCreated
	if !response.Created {
		status = http.StatusOK
	}
	c.JSON(status, response)
}

func (s *service) reconcile(ctx context.Context, actor principal, request reconciliationRequest, statementDate time.Time, rawStatement []byte) (reconciliationResponse, error) {
	statementHashRaw := sha256.Sum256(rawStatement)
	statementHash := hex.EncodeToString(statementHashRaw[:])
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return reconciliationResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	runID, err := randomUUID()
	if err != nil {
		return reconciliationResponse{}, err
	}
	var persistedRunID string
	err = tx.QueryRow(ctx, `INSERT INTO reconciliation_runs (id,tenant_id,provider,statement_sha256,statement_as_of,actor_id) VALUES ($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,provider,statement_sha256) DO NOTHING RETURNING id::text`, runID, actor.TenantID, request.Provider, statementHash, statementDate, actor.ActorID).Scan(&persistedRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		var breakCount int
		if err = tx.QueryRow(ctx, `SELECT id::text FROM reconciliation_runs WHERE tenant_id=$1 AND provider=$2 AND statement_sha256=$3 FOR KEY SHARE`, actor.TenantID, request.Provider, statementHash).Scan(&persistedRunID); err != nil {
			return reconciliationResponse{}, err
		}
		if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM reconciliation_breaks WHERE tenant_id=$1 AND reconciliation_run_id=$2::uuid`, actor.TenantID, persistedRunID).Scan(&breakCount); err != nil {
			return reconciliationResponse{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return reconciliationResponse{}, err
		}
		return reconciliationResponse{RunID: persistedRunID, Created: false, BreakCount: breakCount, StatementID: statementHash}, nil
	}
	if err != nil {
		return reconciliationResponse{}, err
	}

	entriesByReference := make(map[string]providerStatementEntry, len(request.Entries))
	for _, entry := range request.Entries {
		if _, exists := entriesByReference[entry.ProviderReference]; exists {
			return reconciliationResponse{}, errors.New("provider statement contains duplicate reference")
		}
		entriesByReference[entry.ProviderReference] = entry
	}

	rows, err := tx.Query(ctx, `SELECT id::text,COALESCE(provider_reference,''),amount::text,currency,status,updated_at FROM settlement_items WHERE tenant_id=$1 AND provider=$2 FOR UPDATE`, actor.TenantID, request.Provider)
	if err != nil {
		return reconciliationResponse{}, err
	}
	defer rows.Close()
	type internalSettlement struct {
		id, reference, amount, currency, status string
		updatedAt                               time.Time
	}
	type breakCandidate struct {
		settlementID, severity, breakType string
		expected, observed                any
	}
	settlements := make([]internalSettlement, 0)
	for rows.Next() {
		var item internalSettlement
		if err = rows.Scan(&item.id, &item.reference, &item.amount, &item.currency, &item.status, &item.updatedAt); err != nil {
			return reconciliationResponse{}, err
		}
		settlements = append(settlements, item)
	}
	if err = rows.Err(); err != nil {
		return reconciliationResponse{}, err
	}
	rows.Close()

	matched := 0
	candidates := make([]breakCandidate, 0)
	for _, item := range settlements {
		entry, exists := entriesByReference[item.reference]
		if !exists {
			if item.reference != "" && item.status != "pending" && item.status != "submitted" {
				candidates = append(candidates, breakCandidate{item.id, "high", "missing_provider", settlementPayload(item.id, item.reference, item.amount, item.currency, item.status, item.updatedAt), gin.H{"provider_reference": item.reference}})
			}
			continue
		}
		matched++
		delete(entriesByReference, item.reference)
		expected := settlementPayload(item.id, item.reference, item.amount, item.currency, item.status, item.updatedAt)
		observed := providerPayload(entry)
		if item.amount != entry.Amount {
			candidates = append(candidates, breakCandidate{item.id, "critical", "amount_mismatch", expected, observed})
		}
		if item.currency != entry.Currency {
			candidates = append(candidates, breakCandidate{item.id, "critical", "currency_mismatch", expected, observed})
		}
		if item.status != entry.Status {
			candidates = append(candidates, breakCandidate{item.id, "high", "state_mismatch", expected, observed})
		}
	}
	remainingReferences := make([]string, 0, len(entriesByReference))
	for providerReference := range entriesByReference {
		remainingReferences = append(remainingReferences, providerReference)
	}
	sort.Strings(remainingReferences)
	for _, providerReference := range remainingReferences {
		entry := entriesByReference[providerReference]
		candidates = append(candidates, breakCandidate{"", "high", "missing_internal", gin.H{"provider_reference": providerReference}, providerPayload(entry)})
	}
	for _, candidate := range candidates {
		if err = insertReconciliationBreak(ctx, tx, actor.TenantID, persistedRunID, candidate.settlementID, candidate.severity, candidate.breakType, candidate.expected, candidate.observed); err != nil {
			return reconciliationResponse{}, err
		}
	}
	breakCount := len(candidates)
	if _, err = tx.Exec(ctx, `UPDATE reconciliation_runs SET completed_at=NOW() WHERE tenant_id=$1 AND id=$2::uuid`, actor.TenantID, persistedRunID); err != nil {
		return reconciliationResponse{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return reconciliationResponse{}, err
	}
	return reconciliationResponse{RunID: persistedRunID, Created: true, BreakCount: breakCount, Matched: matched, StatementID: statementHash}, nil
}

func insertReconciliationBreak(ctx context.Context, tx pgx.Tx, tenantID, runID, settlementID, severity, breakType string, expected, observed any) error {
	id, err := randomUUID()
	if err != nil {
		return err
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	observedJSON, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO reconciliation_breaks (id,tenant_id,reconciliation_run_id,settlement_id,severity,break_type,expected_payload,observed_payload) VALUES ($1::uuid,$2,$3::uuid,NULLIF($4,'')::uuid,$5,$6,$7::jsonb,$8::jsonb)`, id, tenantID, runID, settlementID, severity, breakType, string(expectedJSON), string(observedJSON))
	return err
}

func settlementPayload(id, reference, amount, currency, status string, updatedAt time.Time) gin.H {
	return gin.H{"settlement_id": id, "provider_reference": reference, "amount": amount, "currency": currency, "status": status, "updated_at": updatedAt.UTC().Format(time.RFC3339Nano)}
}

func providerPayload(entry providerStatementEntry) gin.H {
	return gin.H{"provider_reference": entry.ProviderReference, "amount": entry.Amount, "currency": entry.Currency, "status": entry.Status, "occurred_at": entry.OccurredAt}
}

func (s *service) listReconciliationBreaks(c *gin.Context) {
	principal := requestPrincipal(c)
	status := c.DefaultQuery("status", "open")
	if status != "open" && status != "investigating" && status != "resolved" && status != "waived" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reconciliation break status"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT id::text,COALESCE(settlement_id::text,''),severity,break_type,status,expected_payload::text,observed_payload::text,created_at,COALESCE(resolved_at,'epoch'::timestamptz),COALESCE(resolved_by,'') FROM reconciliation_breaks WHERE tenant_id=$1 AND status=$2 ORDER BY created_at DESC,id DESC LIMIT 200`, principal.TenantID, status)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reconciliation queue unavailable"})
		return
	}
	defer rows.Close()
	result := make([]reconciliationBreakResponse, 0)
	for rows.Next() {
		var item reconciliationBreakResponse
		var expected, observed string
		var createdAt, resolvedAt time.Time
		if err = rows.Scan(&item.ID, &item.Settlement, &item.Severity, &item.BreakType, &item.Status, &expected, &observed, &createdAt, &resolvedAt, &item.ResolvedBy); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reconciliation queue unavailable"})
			return
		}
		item.Expected, item.Observed = json.RawMessage(expected), json.RawMessage(observed)
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		if !resolvedAt.Equal(time.Unix(0, 0).UTC()) {
			item.ResolvedAt = resolvedAt.UTC().Format(time.RFC3339Nano)
		}
		result = append(result, item)
	}
	if err = rows.Err(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reconciliation queue unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"breaks": result})
}

func (s *service) resolveReconciliationBreak(c *gin.Context) {
	var request resolveBreakRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reconciliation resolution"})
		return
	}
	principal := requestPrincipal(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	commandTag, err := s.db.Exec(ctx, `UPDATE reconciliation_breaks rb SET status=$4,resolved_at=NOW(),resolver_id=$3,resolved_by=$3,resolution_reason=$5 FROM reconciliation_runs rr WHERE rb.tenant_id=$1 AND rb.id=$2::uuid AND rr.tenant_id=rb.tenant_id AND rr.id=rb.reconciliation_run_id AND rr.actor_id <> $3 AND rb.status IN ('open','investigating')`, principal.TenantID, c.Param("id"), principal.ActorID, request.Status, strings.TrimSpace(request.Reason))
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reconciliation resolution unavailable"})
		return
	}
	if commandTag.RowsAffected() != 1 {
		c.JSON(http.StatusConflict, gin.H{"error": "break is absent, already resolved, or requires an independent resolver"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": request.Status})
}

func (s *service) createFinancialClose(c *gin.Context) {
	var request financialCloseRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid financial close request"})
		return
	}
	periodStart, err := time.Parse("2006-01-02", request.PeriodStart)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "period_start must be YYYY-MM-DD"})
		return
	}
	periodEnd, err := time.Parse("2006-01-02", request.PeriodEnd)
	if err != nil || periodEnd.Before(periodStart) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "period_end must be YYYY-MM-DD and not precede period_start"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	response, err := s.openFinancialClose(ctx, requestPrincipal(c), periodStart, periodEnd)
	if err != nil {
		if errors.Is(err, errCloseAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": "financial close period already exists"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "financial close unavailable"})
		return
	}
	c.JSON(http.StatusCreated, response)
}

var errCloseAlreadyExists = errors.New("financial close exists")

func (s *service) openFinancialClose(ctx context.Context, actor principal, periodStart, periodEnd time.Time) (financialCloseResponse, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return financialCloseResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snapshot, err := ledgerSnapshotHash(ctx, tx, actor.TenantID, periodStart, periodEnd)
	if err != nil {
		return financialCloseResponse{}, err
	}
	closeID, err := randomUUID()
	if err != nil {
		return financialCloseResponse{}, err
	}
	var persistedID string
	err = tx.QueryRow(ctx, `INSERT INTO financial_close_periods (id,tenant_id,period_start,period_end,requested_by,ledger_snapshot_sha256) VALUES ($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,period_start,period_end) DO NOTHING RETURNING id::text`, closeID, actor.TenantID, periodStart, periodEnd, actor.ActorID, snapshot).Scan(&persistedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return financialCloseResponse{}, errCloseAlreadyExists
	}
	if err != nil {
		return financialCloseResponse{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return financialCloseResponse{}, err
	}
	return financialCloseResponse{CloseID: persistedID, Status: "open", SnapshotSHA256: snapshot}, nil
}

func ledgerSnapshotHash(ctx context.Context, tx pgx.Tx, tenantID string, periodStart, periodEnd time.Time) (string, error) {
	endExclusive := periodEnd.AddDate(0, 0, 1)
	rows, err := tx.Query(ctx, `SELECT j.id::text,j.command_sha256,j.journal_type,j.actor_id,COALESCE(j.external_reference,''),j.created_at,p.id::text,p.account_id::text,p.direction,p.amount::text,p.currency FROM ledger_journals j JOIN ledger_postings p ON p.tenant_id=j.tenant_id AND p.journal_id=j.id WHERE j.tenant_id=$1 AND j.created_at >= $2 AND j.created_at < $3 ORDER BY j.id,p.id`, tenantID, periodStart, endExclusive)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	hash := sha256.New()
	for rows.Next() {
		values := make([]string, 11)
		var createdAt time.Time
		if err = rows.Scan(&values[0], &values[1], &values[2], &values[3], &values[4], &createdAt, &values[6], &values[7], &values[8], &values[9], &values[10]); err != nil {
			return "", err
		}
		values[5] = createdAt.UTC().Format(time.RFC3339Nano)
		for _, value := range values {
			_, _ = hash.Write([]byte(fmt.Sprintf("%d:%s|", len(value), value)))
		}
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *service) submitFinancialClose(c *gin.Context) {
	principal := requestPrincipal(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	response, err := s.moveCloseToReview(ctx, principal, c.Param("id"))
	if err != nil {
		if errors.Is(err, errCloseNotRequester) {
			c.JSON(http.StatusForbidden, gin.H{"error": "only the requester may submit this close for review"})
			return
		}
		c.JSON(http.StatusConflict, gin.H{"error": "financial close cannot enter review"})
		return
	}
	c.JSON(http.StatusOK, response)
}

var errCloseNotRequester = errors.New("close requester mismatch")

func (s *service) moveCloseToReview(ctx context.Context, actor principal, closeID string) (financialCloseResponse, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return financialCloseResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var snapshot, requester string
	err = tx.QueryRow(ctx, `UPDATE financial_close_periods SET status='review' WHERE tenant_id=$1 AND id=$2::uuid AND status IN ('open','reopened') RETURNING ledger_snapshot_sha256,requested_by`, actor.TenantID, closeID).Scan(&snapshot, &requester)
	if errors.Is(err, pgx.ErrNoRows) {
		return financialCloseResponse{}, errCloseNotRequester
	}
	if err != nil || requester != actor.ActorID {
		return financialCloseResponse{}, errCloseNotRequester
	}
	if err = insertCloseEvent(ctx, tx, actor.TenantID, closeID, "requested", actor.ActorID, gin.H{"snapshot_sha256": snapshot}); err != nil {
		return financialCloseResponse{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return financialCloseResponse{}, err
	}
	return financialCloseResponse{CloseID: closeID, Status: "review", SnapshotSHA256: snapshot}, nil
}

func (s *service) approveFinancialClose(c *gin.Context) {
	principal := requestPrincipal(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	response, err := s.approveClose(ctx, principal, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "financial close approval blocked by separation or reconciliation controls"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (s *service) approveClose(ctx context.Context, actor principal, closeID string) (financialCloseResponse, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return financialCloseResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var snapshot string
	err = tx.QueryRow(ctx, `UPDATE financial_close_periods SET approved_by=$3,status='closed' WHERE tenant_id=$1 AND id=$2::uuid AND status='review' RETURNING ledger_snapshot_sha256`, actor.TenantID, closeID, actor.ActorID).Scan(&snapshot)
	if err != nil {
		return financialCloseResponse{}, err
	}
	if err = insertCloseEvent(ctx, tx, actor.TenantID, closeID, "approved", actor.ActorID, gin.H{"snapshot_sha256": snapshot}); err != nil {
		return financialCloseResponse{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return financialCloseResponse{}, err
	}
	return financialCloseResponse{CloseID: closeID, Status: "closed", SnapshotSHA256: snapshot}, nil
}

func (s *service) reopenFinancialClose(c *gin.Context) {
	var request reopenCloseRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid close reopen request"})
		return
	}
	principal := requestPrincipal(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "financial close unavailable"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	commandTag, err := tx.Exec(ctx, `UPDATE financial_close_periods SET status='reopened',reopened_by=$3,reopen_reason=$4 WHERE tenant_id=$1 AND id=$2::uuid AND status='closed'`, principal.TenantID, c.Param("id"), principal.ActorID, strings.TrimSpace(request.Reason))
	if err != nil || commandTag.RowsAffected() != 1 {
		c.JSON(http.StatusConflict, gin.H{"error": "financial close cannot be reopened"})
		return
	}
	if err = insertCloseEvent(ctx, tx, principal.TenantID, c.Param("id"), "reopened", principal.ActorID, gin.H{"reason": strings.TrimSpace(request.Reason)}); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "financial close audit unavailable"})
		return
	}
	if err = tx.Commit(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "financial close unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"close_id": c.Param("id"), "status": "reopened"})
}

func insertCloseEvent(ctx context.Context, tx pgx.Tx, tenantID, closeID, eventType, actorID string, details any) error {
	id, err := randomUUID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO financial_close_events (id,tenant_id,close_id,event_type,actor_id,details) VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6::jsonb)`, id, tenantID, closeID, eventType, actorID, string(payload))
	return err
}

func sortStatementEntries(entries []providerStatementEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].ProviderReference < entries[j].ProviderReference })
}
