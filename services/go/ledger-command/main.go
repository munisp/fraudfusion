package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	serviceName     = "ledger-command-service"
	requestTimeout  = 10 * time.Second
	maxRequestBytes = 1 << 20
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type principal struct {
	TenantID string
	ActorID  string
	Roles    map[string]struct{}
}

type keycloakClient struct {
	introspectionURL string
	clientID         string
	clientSecret     string
	httpClient       *http.Client
}

type service struct {
	db         *pgxpool.Pool
	keycloak   *keycloakClient
	dispatcher *settlementDispatcher
}

type journalRequest struct {
	IdempotencyKey  string                 `json:"idempotency_key" binding:"required,max=255"`
	JournalType     string                 `json:"journal_type" binding:"required,oneof=authorization capture settlement reversal fee adjustment"`
	DebitAccountID  string                 `json:"debit_account_id" binding:"required,uuid"`
	CreditAccountID string                 `json:"credit_account_id" binding:"required,uuid"`
	Amount          string                 `json:"amount" binding:"required"`
	Currency        string                 `json:"currency" binding:"required,len=3"`
	ExternalRef     string                 `json:"external_reference" binding:"max=255"`
	Settlement      *settlementInstruction `json:"settlement"`
}

type settlementInstruction struct {
	Provider          string `json:"provider" binding:"required,max=80"`
	ProviderReference string `json:"provider_reference" binding:"max=255"`
	Direction         string `json:"direction" binding:"required,oneof=inbound outbound"`
}

type journalResponse struct {
	JournalID string `json:"journal_id"`
	Created   bool   `json:"created"`
	Status    string `json:"status"`
}

func main() {
	runtimeCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startupCtx, cancel := context.WithTimeout(runtimeCtx, requestTimeout)
	defer cancel()
	pool, err := pgxpool.New(startupCtx, requiredEnv("DATABASE_URL"))
	if err != nil {
		panic(fmt.Sprintf("connect PostgreSQL: %v", err))
	}
	defer pool.Close()
	if err := pool.Ping(startupCtx); err != nil {
		panic(fmt.Sprintf("ping PostgreSQL: %v", err))
	}
	keycloak, err := newKeycloakClient()
	if err != nil {
		panic(err)
	}
	provider, err := newSettlementProviderFromEnv()
	if err != nil {
		panic(err)
	}
	dispatcher, err := newSettlementDispatcher(pool, provider)
	if err != nil {
		panic(err)
	}
	application := &service{db: pool, keycloak: keycloak, dispatcher: dispatcher}
	router := gin.New()
	router.Use(gin.Recovery(), bodyLimit(maxRequestBytes))
	router.GET("/api/v1/ledger/health", application.health)
	router.POST("/api/v1/ledger/provider-events/:provider", application.providerCallback)
	ledgerAPI := router.Group("/api/v1/ledger")
	ledgerAPI.Use(application.authenticate("ledger:write"))
	ledgerAPI.POST("/journals", application.createJournal)
	ledgerAPI.GET("/journals/:id", application.getJournal)
	reconciliationAPI := router.Group("/api/v1/ledger")
	reconciliationAPI.Use(application.authenticate("finance:reconcile"))
	reconciliationAPI.POST("/reconciliation-runs", application.createReconciliationRun)
	reconciliationAPI.GET("/reconciliation-breaks", application.listReconciliationBreaks)
	reconciliationAPI.POST("/reconciliation-breaks/:id/resolve", application.resolveReconciliationBreak)
	closeRequestAPI := router.Group("/api/v1/ledger")
	closeRequestAPI.Use(application.authenticate("finance:close_request"))
	closeRequestAPI.POST("/financial-closes", application.createFinancialClose)
	closeRequestAPI.POST("/financial-closes/:id/submit", application.submitFinancialClose)
	closeApprovalAPI := router.Group("/api/v1/ledger")
	closeApprovalAPI.Use(application.authenticate("finance:close_approve"))
	closeApprovalAPI.POST("/financial-closes/:id/approve", application.approveFinancialClose)
	closeAdminAPI := router.Group("/api/v1/ledger")
	closeAdminAPI.Use(application.authenticate("finance:close_admin"))
	closeAdminAPI.POST("/financial-closes/:id/reopen", application.reopenFinancialClose)
	server := &http.Server{Addr: envOr("LISTEN_ADDR", ":8098"), Handler: router, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go dispatcher.run(runtimeCtx)
	go func() {
		<-runtimeCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func (s *service) health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "service": serviceName})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": serviceName})
}

func (s *service) createJournal(c *gin.Context) {
	var request journalRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid journal command"})
		return
	}
	request.Currency = strings.ToUpper(request.Currency)
	if !validAmount(request.Amount) || request.DebitAccountID == request.CreditAccountID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount must be positive and accounts must differ"})
		return
	}
	principal := requestPrincipal(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	response, err := s.postJournal(ctx, principal, request)
	if err != nil {
		switch {
		case errors.Is(err, errIdempotencyConflict):
			c.JSON(http.StatusConflict, gin.H{"error": "idempotency key was already used for a different command"})
		case errors.Is(err, errForeignKey):
			c.JSON(http.StatusBadRequest, gin.H{"error": "ledger account does not exist for authenticated tenant"})
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

func (s *service) getJournal(c *gin.Context) {
	principal := requestPrincipal(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
	defer cancel()
	var journalID, journalType, status, externalRef string
	var createdAt time.Time
	err := s.db.QueryRow(ctx, `SELECT id::text, journal_type, status, COALESCE(external_reference,''), created_at FROM ledger_journals WHERE tenant_id=$1 AND id=$2::uuid`, principal.TenantID, c.Param("id")).Scan(&journalID, &journalType, &status, &externalRef, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "journal not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ledger query unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"journal_id": journalID, "journal_type": journalType, "status": status, "external_reference": externalRef, "created_at": createdAt.UTC().Format(time.RFC3339Nano)})
}

var (
	errIdempotencyConflict = errors.New("idempotency conflict")
	errForeignKey          = errors.New("foreign key")
)

func (s *service) postJournal(ctx context.Context, principal principal, request journalRequest) (journalResponse, error) {
	canonical, err := json.Marshal(struct {
		JournalType string                 `json:"journal_type"`
		Debit       string                 `json:"debit_account_id"`
		Credit      string                 `json:"credit_account_id"`
		Amount      string                 `json:"amount"`
		Currency    string                 `json:"currency"`
		ExternalRef string                 `json:"external_reference"`
		Settlement  *settlementInstruction `json:"settlement,omitempty"`
	}{request.JournalType, request.DebitAccountID, request.CreditAccountID, request.Amount, request.Currency, request.ExternalRef, request.Settlement})
	if err != nil {
		return journalResponse{}, err
	}
	hash := sha256.Sum256(canonical)
	commandHash := hex.EncodeToString(hash[:])

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return journalResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var journalID string
	newJournalID, err := randomUUID()
	if err != nil {
		return journalResponse{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO ledger_journals (id, tenant_id, idempotency_key, command_sha256, journal_type, actor_id, external_reference) VALUES ($1::uuid,$2,$3,$4,$5,$6,NULLIF($7,'')) ON CONFLICT (tenant_id,idempotency_key) DO NOTHING RETURNING id::text`, newJournalID, principal.TenantID, request.IdempotencyKey, commandHash, request.JournalType, principal.ActorID, request.ExternalRef).Scan(&journalID)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingHash string
		if err = tx.QueryRow(ctx, `SELECT id::text, command_sha256 FROM ledger_journals WHERE tenant_id=$1 AND idempotency_key=$2 FOR KEY SHARE`, principal.TenantID, request.IdempotencyKey).Scan(&journalID, &existingHash); err != nil {
			return journalResponse{}, err
		}
		if subtle.ConstantTimeCompare([]byte(existingHash), []byte(commandHash)) != 1 {
			return journalResponse{}, errIdempotencyConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return journalResponse{}, err
		}
		return journalResponse{JournalID: journalID, Created: false, Status: "posted"}, nil
	}
	if err != nil {
		return journalResponse{}, err
	}
	debitPostingID, err := randomUUID()
	if err != nil {
		return journalResponse{}, err
	}
	creditPostingID, err := randomUUID()
	if err != nil {
		return journalResponse{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ledger_postings (id,tenant_id,journal_id,account_id,direction,amount,currency) VALUES ($1::uuid,$2,$3::uuid,$4::uuid,'D',$5::numeric,$6),($7::uuid,$2,$3::uuid,$8::uuid,'C',$5::numeric,$6)`, debitPostingID, principal.TenantID, journalID, request.DebitAccountID, request.Amount, request.Currency, creditPostingID, request.CreditAccountID)
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			return journalResponse{}, errForeignKey
		}
		return journalResponse{}, err
	}
	if request.Settlement != nil {
		settlementID := fmt.Sprintf("%x", sha256.Sum256([]byte(principal.TenantID+":"+journalID+":settlement")))
		_, err = tx.Exec(ctx, `INSERT INTO settlement_items (id,tenant_id,journal_id,provider,provider_reference,direction,amount,currency,status) VALUES ($1::uuid,$2,$3::uuid,$4,NULLIF($5,''),$6,$7::numeric,$8,'pending')`, uuidFromDigest(settlementID), principal.TenantID, journalID, request.Settlement.Provider, request.Settlement.ProviderReference, request.Settlement.Direction, request.Amount, request.Currency)
		if err != nil {
			return journalResponse{}, err
		}
		payload, _ := json.Marshal(gin.H{"settlement_id": uuidFromDigest(settlementID), "provider": request.Settlement.Provider, "journal_id": journalID, "tenant_id": principal.TenantID})
		outboxID, randomErr := randomUUID()
		if randomErr != nil {
			return journalResponse{}, randomErr
		}
		_, err = tx.Exec(ctx, `INSERT INTO ledger_outbox (id,tenant_id,journal_id,event_type,idempotency_key,payload) VALUES ($1::uuid,$2,$3::uuid,'settlement.submit',$4,$5::jsonb)`, outboxID, principal.TenantID, journalID, request.IdempotencyKey, payload)
		if err != nil {
			return journalResponse{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return journalResponse{}, err
	}
	return journalResponse{JournalID: journalID, Created: true, Status: "posted"}, nil
}

func (s *service) authenticate(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bearer token required"})
			return
		}
		principal, err := s.keycloak.introspect(c.Request.Context(), strings.TrimPrefix(header, "Bearer "))
		if err != nil || !hasRole(principal.Roles, requiredRole) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "ledger authorization denied"})
			return
		}
		c.Set("principal", principal)
		c.Next()
	}
}

func newKeycloakClient() (*keycloakClient, error) {
	url := requiredEnv("KEYCLOAK_INTROSPECTION_URL")
	clientID := requiredEnv("KEYCLOAK_CLIENT_ID")
	secret := requiredEnv("KEYCLOAK_CLIENT_SECRET")
	return &keycloakClient{introspectionURL: url, clientID: clientID, clientSecret: secret, httpClient: &http.Client{Timeout: 5 * time.Second}}, nil
}

func (k *keycloakClient) introspect(ctx context.Context, token string) (principal, error) {
	form := url.Values{"token": {token}, "client_id": {k.clientID}, "client_secret": {k.clientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return principal{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := k.httpClient.Do(req)
	if err != nil {
		return principal{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return principal{}, errors.New("introspection unavailable")
	}
	var claims struct {
		Active      bool   `json:"active"`
		Sub         string `json:"sub"`
		TenantID    string `json:"tenant_id"`
		Tenant      string `json:"tenant"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes)).Decode(&claims); err != nil || !claims.Active || claims.Sub == "" {
		return principal{}, errors.New("inactive token")
	}
	tenant := claims.TenantID
	if tenant == "" {
		tenant = claims.Tenant
	}
	if tenant == "" {
		return principal{}, errors.New("tenant claim absent")
	}
	roles := make(map[string]struct{}, len(claims.RealmAccess.Roles))
	for _, role := range claims.RealmAccess.Roles {
		roles[role] = struct{}{}
	}
	return principal{TenantID: tenant, ActorID: claims.Sub, Roles: roles}, nil
}

func bodyLimit(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) { c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit); c.Next() }
}
func requestPrincipal(c *gin.Context) principal           { return c.MustGet("principal").(principal) }
func hasRole(roles map[string]struct{}, role string) bool { _, ok := roles[role]; return ok }
func requiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("missing required environment variable: " + key)
	}
	return value
}
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func validAmount(value string) bool {
	if !regexp.MustCompile(`^[0-9]+(\.[0-9]{1,6})?$`).MatchString(value) {
		return false
	}
	rat, ok := new(big.Rat).SetString(value)
	return ok && rat.Sign() > 0
}
func uuidFromDigest(value string) string {
	value = value[:32]
	return value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
}
func randomUUID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
