package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

var (
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// commandHashFor hashes a canonical command string for idempotency checks.
func commandHashFor(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// ratToFixed6 renders a rational as a decimal string with 6 fractional
// digits, rounding half-up (matching NUMERIC(20,6) posting semantics).
func ratToFixed6(r *big.Rat) string {
	scaled := new(big.Rat).Mul(r, big.NewRat(1000000, 1))
	num := new(big.Int).Set(scaled.Num())
	den := new(big.Int).Set(scaled.Denom())
	q, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	// half-up rounding: round up when 2*|rem| >= |den|.
	twice := new(big.Int).Lsh(new(big.Int).Abs(rem), 1)
	if twice.Cmp(new(big.Int).Abs(den)) >= 0 && rem.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	intPart, frac := new(big.Int).QuoRem(q, big.NewInt(1000000), new(big.Int))
	return fmt.Sprintf("%s.%06d", intPart.String(), frac.Int64())
}

var (
	errJournalNotFound      = errors.New("journal not found")
	errJournalNotReversible = errors.New("journal is not reversible")
	errCrossCurrency        = errors.New("cross-currency journal requires fx_rate and fx_quote_id")
	errJournalCurrency      = errors.New("journal currency must match the debit account currency")
)

// --- Multicurrency journal validation ---------------------------------------

// accountCurrencies loads both accounts' currencies, tenant-scoped. A missing
// account is errForeignKey (mapped to 400 by the handler).
func (s *service) accountCurrencies(ctx context.Context, tenantID, debitID, creditID string) (debitCurrency, creditCurrency string, err error) {
	rows, err := s.db.Query(ctx, `SELECT id::text, currency FROM ledger_accounts WHERE tenant_id=$1 AND id IN ($2::uuid,$3::uuid)`, tenantID, debitID, creditID)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var id, currency string
		if err := rows.Scan(&id, &currency); err != nil {
			return "", "", err
		}
		found[id] = currency
	}
	debitCurrency, okD := found[debitID]
	creditCurrency, okC := found[creditID]
	if !okD || !okC {
		return "", "", errForeignKey
	}
	return debitCurrency, creditCurrency, nil
}

// fxSpec is the validated FX leg of a cross-currency journal.
type fxSpec struct {
	rate           string // decimal string, > 0
	quoteID        string
	creditAmount   string // amount * rate, 6dp half-up, in credit currency
	creditCurrency string
}

// resolveCurrencyLegs enforces the currency policy:
//   - both accounts share the request currency: same-currency journal, no fx
//   - debit account currency == request currency, credit differs: allowed
//     ONLY with explicit fx_rate + fx_quote_id (else 422); the credit leg is
//     converted at the quoted rate
//   - anything else (debit account currency mismatch): 422, the service will
//     not invent a conversion for the base leg
//
// Balance checks remain per-currency: the DB trigger validates each leg in
// its own account currency and the fx equation across legs.
func resolveCurrencyLegs(request journalRequest, debitCurrency, creditCurrency string) (*fxSpec, error) {
	if !currencyPattern.MatchString(request.Currency) {
		return nil, errJournalCurrency
	}
	if debitCurrency == request.Currency && creditCurrency == request.Currency {
		return nil, nil // same-currency fast path
	}
	if debitCurrency != request.Currency {
		return nil, errJournalCurrency
	}
	// creditCurrency != request.Currency: cross-currency requires an explicit quote.
	if !validAmount(request.FxRate) || request.FxQuoteID == "" {
		return nil, errCrossCurrency
	}
	rate, _ := new(big.Rat).SetString(request.FxRate)
	amount, _ := new(big.Rat).SetString(request.Amount) // validAmount checked by handler
	credit := new(big.Rat).Mul(amount, rate)
	return &fxSpec{
		rate:           request.FxRate,
		quoteID:        request.FxQuoteID,
		creditAmount:   ratToFixed6(credit),
		creditCurrency: creditCurrency,
	}, nil
}

// --- Reversal state machine -------------------------------------------------

type reverseRequest struct {
	IdempotencyKey string `json:"idempotency_key" binding:"required,max=255"`
}

// reverseJournal reverses a posted journal. State machine (also enforced by
// the ledger_journal_status_transition DB trigger): only a 'posted' journal
// may move to 'reversed', and reversal journals cannot themselves be
// reversed (a second reversal is a new journal, never a flip of the first).
func (s *service) reverseJournal(c *gin.Context) {
	targetID := c.Param("id")
	if ok := uuidPattern.MatchString(targetID); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "journal id must be a UUID"})
		return
	}
	var req reverseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key is required"})
		return
	}
	principal := requestPrincipal(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	response, err := s.postReversal(ctx, principal, targetID, req.IdempotencyKey)
	if err != nil {
		switch {
		case errors.Is(err, errJournalNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "journal not found"})
		case errors.Is(err, errJournalNotReversible):
			c.JSON(http.StatusConflict, gin.H{"error": "journal already reversed or is itself a reversal"})
		case errors.Is(err, errIdempotencyConflict):
			c.JSON(http.StatusConflict, gin.H{"error": "idempotency key was already used for a different command"})
		default:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ledger command unavailable"})
		}
		return
	}
	status := http.StatusCreated
	if !response.Created {
		status = http.StatusOK
	}
	c.JSON(status, response)
}

func (s *service) postReversal(ctx context.Context, principal principal, targetID, idempotencyKey string) (journalResponse, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return journalResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the target journal and enforce the state machine against the DB,
	// not against anything cached.
	var status, journalType, currency string
	err = tx.QueryRow(ctx, `SELECT status, journal_type, currency FROM ledger_journals WHERE tenant_id=$1 AND id=$2::uuid FOR UPDATE`, principal.TenantID, targetID).Scan(&status, &journalType, &currency)
	if errors.Is(err, pgx.ErrNoRows) {
		return journalResponse{}, errJournalNotFound
	}
	if err != nil {
		return journalResponse{}, err
	}
	if status != "posted" || journalType == "reversal" {
		return journalResponse{}, errJournalNotReversible
	}

	// Idempotent reversal insert: same key + same target returns the original
	// reversal journal; same key + different target is a conflict.
	reversalID, err := randomUUID()
	if err != nil {
		return journalResponse{}, err
	}
	commandHash := commandHashFor("reversal:" + targetID)
	var insertedID string
	err = tx.QueryRow(ctx, `INSERT INTO ledger_journals (id, tenant_id, idempotency_key, command_sha256, journal_type, actor_id, external_reference, currency, fx_rate, fx_quote_id, reverses_journal_id)
		SELECT $1::uuid, $2, $3, $4, 'reversal', $5, j.external_reference, j.currency, j.fx_rate, j.fx_quote_id, j.id
		FROM ledger_journals j WHERE j.tenant_id=$2 AND j.id=$6::uuid
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING id::text`,
		reversalID, principal.TenantID, idempotencyKey, commandHash, principal.ActorID, targetID).Scan(&insertedID)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingID, existingHash string
		if err = tx.QueryRow(ctx, `SELECT id::text, command_sha256 FROM ledger_journals WHERE tenant_id=$1 AND idempotency_key=$2 FOR KEY SHARE`, principal.TenantID, idempotencyKey).Scan(&existingID, &existingHash); err != nil {
			return journalResponse{}, err
		}
		if existingHash != commandHash {
			return journalResponse{}, errIdempotencyConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return journalResponse{}, err
		}
		return journalResponse{JournalID: existingID, Created: false, Status: "posted"}, nil
	}
	if err != nil {
		return journalResponse{}, err
	}

	// Mirror the original postings with swapped directions (same currencies
	// and amounts, so the per-currency balance nets to zero).
	if _, err = tx.Exec(ctx, `INSERT INTO ledger_postings (id, tenant_id, journal_id, account_id, direction, amount, currency)
		SELECT gen_random_uuid(), tenant_id, $2::uuid, account_id, CASE direction WHEN 'D' THEN 'C' ELSE 'D' END, amount, currency
		FROM ledger_postings WHERE tenant_id=$1 AND journal_id=$3::uuid`, principal.TenantID, insertedID, targetID); err != nil {
		return journalResponse{}, err
	}

	// The DB trigger allows exactly this one transition; anything else raises.
	tag, err := tx.Exec(ctx, `UPDATE ledger_journals SET status='reversed' WHERE tenant_id=$1 AND id=$2::uuid AND status='posted'`, principal.TenantID, targetID)
	if err != nil {
		return journalResponse{}, err
	}
	if tag.RowsAffected() != 1 {
		return journalResponse{}, errJournalNotReversible
	}
	if err = tx.Commit(ctx); err != nil {
		return journalResponse{}, err
	}
	return journalResponse{JournalID: insertedID, Created: true, Status: "posted"}, nil
}

// --- Balance inquiry + keyset-paginated transactions ------------------------

type balanceResult struct {
	AccountID string `json:"account_id"`
	Currency  string `json:"currency"`
	Current   string `json:"current_balance"`
	Available string `json:"available_balance"`
	AsOf      string `json:"as_of"`
}

// balanceCacheEntry caches a computed balance for at most 5 seconds.
type balanceCacheEntry struct {
	result    balanceResult
	expiresAt time.Time
}

var (
	balanceCache   = make(map[string]balanceCacheEntry)
	balanceCacheMu sync.Mutex
)

const balanceCacheTTL = 5 * time.Second

func (s *service) getAccountBalance(c *gin.Context) {
	principal := requestPrincipal(c)
	accountID := c.Param("id")
	if !uuidPattern.MatchString(accountID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account id must be a UUID"})
		return
	}
	cacheKey := principal.TenantID + ":" + accountID
	balanceCacheMu.Lock()
	if entry, ok := balanceCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		balanceCacheMu.Unlock()
		c.JSON(http.StatusOK, entry.result)
		return
	}
	balanceCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	// Balance is per-currency: the account carries exactly one currency and
	// postings are validated against it, so the net is a single-currency sum.
	var currency string
	var current string
	err := s.db.QueryRow(ctx, `
		SELECT a.currency,
		       COALESCE(SUM(CASE p.direction WHEN 'D' THEN p.amount ELSE -p.amount END), 0)::text
		  FROM ledger_accounts a
		  LEFT JOIN ledger_postings p ON p.tenant_id = a.tenant_id AND p.account_id = a.id
		 WHERE a.tenant_id = $1 AND a.id = $2::uuid
		 GROUP BY a.currency`, principal.TenantID, accountID).Scan(&currency, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "balance query unavailable"})
		return
	}
	result := balanceResult{
		AccountID: accountID,
		Currency:  currency,
		Current:   current,
		// No holds/reservations subsystem exists yet, so available == current.
		Available: current,
		AsOf:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	balanceCacheMu.Lock()
	if len(balanceCache) > 10000 {
		balanceCache = make(map[string]balanceCacheEntry)
	}
	balanceCache[cacheKey] = balanceCacheEntry{result: result, expiresAt: time.Now().Add(balanceCacheTTL)}
	balanceCacheMu.Unlock()
	c.JSON(http.StatusOK, result)
}

const (
	defaultTransactionLimit = 50
	maxTransactionLimit     = 200
)

func (s *service) listAccountTransactions(c *gin.Context) {
	principal := requestPrincipal(c)
	accountID := c.Param("id")
	if !uuidPattern.MatchString(accountID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account id must be a UUID"})
		return
	}
	limit := defaultTransactionLimit
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxTransactionLimit {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("limit must be 1-%d", maxTransactionLimit)})
			return
		}
		limit = parsed
	}
	// Keyset pagination on (created_at, id): cursor is the entry (posting) id
	// of the last row from the previous page. No OFFSET — stable under
	// concurrent inserts.
	cursor := c.Query("cursor")
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()

	var cursorCreatedAt time.Time
	var cursorID string
	if cursor != "" {
		if !uuidPattern.MatchString(cursor) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cursor must be a posting id from a previous page"})
			return
		}
		err := s.db.QueryRow(ctx, `SELECT id::text, created_at FROM ledger_postings WHERE tenant_id=$1 AND account_id=$2::uuid AND id=$3::uuid`, principal.TenantID, accountID, cursor).Scan(&cursorID, &cursorCreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown cursor"})
			return
		}
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "transaction query unavailable"})
			return
		}
	}

	query := `SELECT id::text, journal_id::text, direction, amount::text, currency, created_at
	          FROM ledger_postings
	          WHERE tenant_id=$1 AND account_id=$2::uuid`
	args := []interface{}{principal.TenantID, accountID}
	if cursor != "" {
		query += ` AND (created_at, id) > ($3, $4::uuid)`
		args = append(args, cursorCreatedAt, cursorID)
	}
	query += fmt.Sprintf(` ORDER BY created_at, id LIMIT %d`, limit+1) // limit is validated int
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "transaction query unavailable"})
		return
	}
	defer rows.Close()
	type entry struct {
		EntryID   string `json:"entry_id"`
		JournalID string `json:"journal_id"`
		Direction string `json:"direction"`
		Amount    string `json:"amount"`
		Currency  string `json:"currency"`
		CreatedAt string `json:"created_at"`
	}
	entries := make([]entry, 0, limit)
	for rows.Next() {
		var e entry
		var createdAt time.Time
		if err := rows.Scan(&e.EntryID, &e.JournalID, &e.Direction, &e.Amount, &e.Currency, &createdAt); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "transaction query unavailable"})
			return
		}
		e.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		entries = append(entries, e)
	}
	nextCursor := ""
	if len(entries) > limit {
		entries = entries[:limit]
		nextCursor = entries[len(entries)-1].EntryID
	}
	c.JSON(http.StatusOK, gin.H{
		"account_id":  accountID,
		"entries":     entries,
		"next_cursor": nextCursor,
		"limit":       limit,
	})
}
