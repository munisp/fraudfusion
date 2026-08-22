package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	outboxLeaseDuration    = 30 * time.Second
	outboxPollInterval     = 500 * time.Millisecond
	outboxBatchSize        = 32
	outboxMaxAttempts      = 8
	callbackClockSkew      = 5 * time.Minute
	providerRequestTimeout = 8 * time.Second
)

type settlementProvider struct {
	name        string
	submitURL   string
	callbackKey []byte
	httpClient  *http.Client
	maxAttempts int
}

type settlementDispatcher struct {
	db       *pgxpool.Pool
	provider *settlementProvider
	workerID string
}

type leasedOutboxEvent struct {
	ID             string
	TenantID       string
	JournalID      string
	IdempotencyKey string
	Payload        []byte
	Attempts       int
}

type providerSubmission struct {
	SettlementID string `json:"settlement_id"`
	Provider     string `json:"provider"`
	JournalID    string `json:"journal_id"`
	TenantID     string `json:"tenant_id"`
}

type providerCallback struct {
	TenantID          string `json:"tenant_id" binding:"required,max=255"`
	ProviderEventID   string `json:"provider_event_id" binding:"required,max=255"`
	SettlementID      string `json:"settlement_id" binding:"required,uuid"`
	ProviderReference string `json:"provider_reference" binding:"max=255"`
	EventType         string `json:"event_type" binding:"required,oneof=accepted settled rejected reversed"`
	OccurredAt        string `json:"occurred_at" binding:"required"`
}

type callbackResult struct {
	Status string `json:"status"`
}

func newSettlementProviderFromEnv() (*settlementProvider, error) {
	name := requiredEnv("SETTLEMENT_PROVIDER_NAME")
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("SETTLEMENT_PROVIDER_NAME is empty")
	}
	submitURL := requiredEnv("SETTLEMENT_PROVIDER_SUBMIT_URL")
	parsedURL, err := url.ParseRequestURI(submitURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
		return nil, errors.New("SETTLEMENT_PROVIDER_SUBMIT_URL must be an https URL")
	}
	callbackKey := []byte(requiredEnv("SETTLEMENT_PROVIDER_CALLBACK_HMAC_SECRET"))
	if len(callbackKey) < 32 {
		return nil, errors.New("SETTLEMENT_PROVIDER_CALLBACK_HMAC_SECRET must contain at least 32 bytes")
	}
	return &settlementProvider{name: name, submitURL: submitURL, callbackKey: callbackKey, httpClient: &http.Client{Timeout: providerRequestTimeout}, maxAttempts: outboxMaxAttempts}, nil
}

func newSettlementDispatcher(db *pgxpool.Pool, provider *settlementProvider) (*settlementDispatcher, error) {
	workerID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	return &settlementDispatcher{db: db, provider: provider, workerID: workerID}, nil
}

func (d *settlementDispatcher) run(ctx context.Context) {
	ticker := time.NewTicker(outboxPollInterval)
	defer ticker.Stop()
	for {
		if err := d.dispatchOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			// The persisted outbox state is the operational record; failures are retried or dead-lettered.
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *settlementDispatcher) dispatchOnce(ctx context.Context) error {
	leaseCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	events, err := d.leaseEvents(leaseCtx)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := d.submitEvent(leaseCtx, event); err != nil {
			_ = d.recordDispatchFailure(leaseCtx, event, err)
		}
	}
	return nil
}

func (d *settlementDispatcher) leaseEvents(ctx context.Context) ([]leasedOutboxEvent, error) {
	rows, err := d.db.Query(ctx, `
WITH candidates AS (
    SELECT id
      FROM ledger_outbox
     WHERE ((status IN ('pending','failed') AND available_at <= NOW())
        OR (status = 'leased' AND lease_expires_at <= NOW()))
       AND payload->>'provider' = $4
     ORDER BY available_at, created_at
     FOR UPDATE SKIP LOCKED
     LIMIT $1
)
UPDATE ledger_outbox o
   SET status='leased', leased_by=$2, lease_expires_at=NOW()+$3::interval,
       attempts=o.attempts+1, last_error=NULL, updated_at=NOW()
  FROM candidates c
 WHERE o.id=c.id
 RETURNING o.id::text, o.tenant_id, o.journal_id::text, o.idempotency_key, o.payload::text, o.attempts`, outboxBatchSize, d.workerID, durationInterval(outboxLeaseDuration), d.provider.name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]leasedOutboxEvent, 0, outboxBatchSize)
	for rows.Next() {
		var event leasedOutboxEvent
		if err = rows.Scan(&event.ID, &event.TenantID, &event.JournalID, &event.IdempotencyKey, &event.Payload, &event.Attempts); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (d *settlementDispatcher) submitEvent(ctx context.Context, event leasedOutboxEvent) error {
	var submission providerSubmission
	if err := json.Unmarshal(event.Payload, &submission); err != nil {
		return permanentDispatchError{err: fmt.Errorf("invalid committed outbox payload: %w", err)}
	}
	if submission.SettlementID == "" || submission.Provider != d.provider.name || submission.JournalID == "" || submission.TenantID != event.TenantID {
		return permanentDispatchError{err: errors.New("outbox payload does not match configured provider or tenant")}
	}
	body, err := json.Marshal(submission)
	if err != nil {
		return permanentDispatchError{err: err}
	}
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.provider.submitURL, strings.NewReader(string(body)))
	if err != nil {
		return permanentDispatchError{err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", event.IdempotencyKey)
	req.Header.Set("X-FraudFusion-Timestamp", timestamp)
	req.Header.Set("X-FraudFusion-Signature", signProviderPayload(d.provider.callbackKey, timestamp, body))
	response, err := d.provider.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode >= http.StatusBadRequest && response.StatusCode < http.StatusInternalServerError && response.StatusCode != http.StatusTooManyRequests {
			return permanentDispatchError{err: fmt.Errorf("provider rejected settlement submission with status %d", response.StatusCode)}
		}
		return fmt.Errorf("provider submission unavailable with status %d", response.StatusCode)
	}
	return d.markPublished(ctx, event, submission)
}

func (d *settlementDispatcher) markPublished(ctx context.Context, event leasedOutboxEvent, submission providerSubmission) error {
	tx, err := d.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	commandTag, err := tx.Exec(ctx, `
UPDATE settlement_items
   SET status='submitted'
 WHERE id=$1::uuid AND tenant_id=$2 AND provider=$3 AND status='pending'`, submission.SettlementID, event.TenantID, d.provider.name)
	if err != nil || commandTag.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return errors.New("settlement was not pending when provider acknowledgement arrived")
	}
	commandTag, err = tx.Exec(ctx, `
UPDATE ledger_outbox
   SET status='published', published_at=NOW(), lease_expires_at=NULL, leased_by=NULL, updated_at=NOW()
 WHERE id=$1::uuid AND status='leased' AND leased_by=$2`, event.ID, d.workerID)
	if err != nil || commandTag.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return errors.New("outbox lease was lost before provider acknowledgement")
	}
	return tx.Commit(ctx)
}

type permanentDispatchError struct{ err error }

func (e permanentDispatchError) Error() string { return e.err.Error() }

func (d *settlementDispatcher) recordDispatchFailure(ctx context.Context, event leasedOutboxEvent, dispatchErr error) error {
	status := "failed"
	if _, permanent := dispatchErr.(permanentDispatchError); permanent || event.Attempts >= d.provider.maxAttempts {
		status = "dead_letter"
	}
	delay := retryDelay(event.Attempts)
	_, err := d.db.Exec(ctx, `
UPDATE ledger_outbox
   SET status=$3, available_at=NOW()+$4::interval, lease_expires_at=NULL, leased_by=NULL,
       last_error=LEFT($5,512), updated_at=NOW()
 WHERE id=$1::uuid AND status='leased' AND leased_by=$2`, event.ID, d.workerID, status, durationInterval(delay), dispatchErr.Error())
	return err
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return time.Duration(1<<uint(attempt-1)) * time.Second
}

func durationInterval(duration time.Duration) string {
	return fmt.Sprintf("%f seconds", duration.Seconds())
}

func (s *service) providerCallback(c *gin.Context) {
	if s.dispatcher == nil || s.dispatcher.provider == nil || c.Param("provider") != s.dispatcher.provider.name {
		c.JSON(http.StatusNotFound, gin.H{"error": "settlement provider not configured"})
		return
	}
	rawBody, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBytes))
	if err != nil {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "provider callback exceeds size limit"})
		return
	}
	if !verifyProviderSignature(s.dispatcher.provider.callbackKey, c.GetHeader("X-Provider-Timestamp"), c.GetHeader("X-Provider-Signature"), rawBody, time.Now().UTC()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "provider callback signature invalid"})
		return
	}
	var callback providerCallback
	if err = json.Unmarshal(rawBody, &callback); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider callback"})
		return
	}
	occurredAt, err := time.Parse(time.RFC3339, callback.OccurredAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "callback occurred_at must be RFC3339"})
		return
	}
	if callback.TenantID == "" || callback.ProviderEventID == "" || callback.SettlementID == "" || callback.EventType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider callback required fields missing"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	result, err := s.dispatcher.applyCallback(ctx, callback, rawBody, occurredAt.UTC())
	if err != nil {
		switch {
		case errors.Is(err, errCallbackHashMismatch):
			c.JSON(http.StatusConflict, gin.H{"error": "provider event identifier reused with a different payload"})
		case errors.Is(err, errUnknownSettlement), errors.Is(err, errProviderReferenceMismatch), errors.Is(err, errInvalidSettlementTransition):
			c.JSON(http.StatusConflict, gin.H{"error": "provider callback violates settlement controls"})
		default:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "provider callback persistence unavailable"})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

var (
	errCallbackHashMismatch        = errors.New("provider callback payload hash mismatch")
	errUnknownSettlement           = errors.New("unknown settlement")
	errProviderReferenceMismatch   = errors.New("provider reference mismatch")
	errInvalidSettlementTransition = errors.New("invalid settlement transition")
)

func (d *settlementDispatcher) applyCallback(ctx context.Context, callback providerCallback, rawPayload []byte, occurredAt time.Time) (callbackResult, error) {
	hash := sha256.Sum256(rawPayload)
	payloadHash := hex.EncodeToString(hash[:])
	tx, err := d.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return callbackResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	eventID, err := randomUUID()
	if err != nil {
		return callbackResult{}, err
	}
	var inserted string
	err = tx.QueryRow(ctx, `
INSERT INTO provider_settlement_events (id,tenant_id,provider,provider_event_id,settlement_id,payload_sha256,occurred_at,event_type,provider_reference,payload)
VALUES ($1::uuid,$2,$3,$4,$5::uuid,$6,$7,$8,NULLIF($9,''),$10::jsonb)
ON CONFLICT (tenant_id,provider,provider_event_id) DO NOTHING
RETURNING id::text`, eventID, callback.TenantID, d.provider.name, callback.ProviderEventID, callback.SettlementID, payloadHash, occurredAt, callback.EventType, callback.ProviderReference, string(rawPayload)).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingHash string
		if err = tx.QueryRow(ctx, `SELECT payload_sha256 FROM provider_settlement_events WHERE tenant_id=$1 AND provider=$2 AND provider_event_id=$3 FOR KEY SHARE`, callback.TenantID, d.provider.name, callback.ProviderEventID).Scan(&existingHash); err != nil {
			return callbackResult{}, err
		}
		if subtle.ConstantTimeCompare([]byte(existingHash), []byte(payloadHash)) != 1 {
			if err = d.insertCallbackAlert(ctx, tx, callback, "payload_hash_mismatch", existingHash, payloadHash, gin.H{"settlement_id": callback.SettlementID}); err != nil {
				return callbackResult{}, err
			}
			if err = tx.Commit(ctx); err != nil {
				return callbackResult{}, err
			}
			return callbackResult{}, errCallbackHashMismatch
		}
		if err = tx.Commit(ctx); err != nil {
			return callbackResult{}, err
		}
		return callbackResult{Status: "replayed"}, nil
	}
	if err != nil {
		return callbackResult{}, err
	}

	var storedReference, status string
	err = tx.QueryRow(ctx, `SELECT COALESCE(provider_reference,''),status FROM settlement_items WHERE id=$1::uuid AND tenant_id=$2 AND provider=$3 FOR UPDATE`, callback.SettlementID, callback.TenantID, d.provider.name).Scan(&storedReference, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		if err = d.insertCallbackAlert(ctx, tx, callback, "unknown_settlement", "", payloadHash, gin.H{"settlement_id": callback.SettlementID}); err != nil {
			return callbackResult{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return callbackResult{}, err
		}
		return callbackResult{}, errUnknownSettlement
	}
	if err != nil {
		return callbackResult{}, err
	}
	if storedReference != "" && callback.ProviderReference != "" && storedReference != callback.ProviderReference {
		if err = d.insertCallbackAlert(ctx, tx, callback, "provider_reference_mismatch", "", payloadHash, gin.H{"expected_reference": storedReference, "observed_reference": callback.ProviderReference}); err != nil {
			return callbackResult{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return callbackResult{}, err
		}
		return callbackResult{}, errProviderReferenceMismatch
	}
	commandTag, err := tx.Exec(ctx, `UPDATE settlement_items SET status=$4 WHERE id=$1::uuid AND tenant_id=$2 AND provider=$3 AND status=$5`, callback.SettlementID, callback.TenantID, d.provider.name, callback.EventType, status)
	if err != nil || commandTag.RowsAffected() != 1 {
		if err = d.insertCallbackAlert(ctx, tx, callback, "invalid_state_transition", "", payloadHash, gin.H{"current_status": status, "target_status": callback.EventType}); err != nil {
			return callbackResult{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return callbackResult{}, err
		}
		return callbackResult{}, errInvalidSettlementTransition
	}
	if err = tx.Commit(ctx); err != nil {
		return callbackResult{}, err
	}
	return callbackResult{Status: "processed"}, nil
}

func (d *settlementDispatcher) insertCallbackAlert(ctx context.Context, tx pgx.Tx, callback providerCallback, alertType, expectedHash, observedHash string, details any) error {
	id, err := randomUUID()
	if err != nil {
		return err
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO provider_callback_alerts (id,tenant_id,provider,provider_event_id,alert_type,expected_payload_sha256,observed_payload_sha256,details) VALUES ($1::uuid,$2,$3,$4,$5,NULLIF($6,''),$7,$8::jsonb)`, id, callback.TenantID, d.provider.name, callback.ProviderEventID, alertType, expectedHash, observedHash, detailsJSON)
	return err
}

func signProviderPayload(key []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyProviderSignature(key []byte, timestamp, signature string, body []byte, now time.Time) bool {
	if len(key) < 32 || timestamp == "" || signature == "" {
		return false
	}
	unixTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Unix(unixTimestamp, 0).UTC().Sub(now).Abs() > callbackClockSkew {
		return false
	}
	expected, err := hex.DecodeString(signProviderPayload(key, timestamp, body))
	observed, err2 := hex.DecodeString(signature)
	if err != nil || err2 != nil || len(expected) != len(observed) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, observed) == 1
}
