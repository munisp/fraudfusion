package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

var (
	db          *sql.DB
	redisClient *redis.Client
	ctx         = context.Background()
)

// Message represents an email or message to analyze
type Message struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	SenderEmail string    `json:"sender_email"`
	SenderName  string    `json:"sender_name"`
	Subject     string    `json:"subject"`
	Content     string    `json:"content"`
	Timestamp   time.Time `json:"timestamp"`
}

// RiskAnalysis represents the fraud analysis result
type RiskAnalysis struct {
	MessageID       string          `json:"message_id"`
	RiskScore       int             `json:"risk_score"`
	RiskLevel       string          `json:"risk_level"`
	ScamType        string          `json:"scam_type"`
	Is419Scam       bool            `json:"is_419_scam"`
	RedFlags        []string        `json:"red_flags"`
	Recommendation  string          `json:"recommendation"`
	LanguageAnomaly LanguageAnomaly `json:"language_anomaly"`
	LureSignals     LureSignals     `json:"lure_signals"`
}

// LureSignals reports the smishing / data-harvest lure detectors (NIN/BVN
// identity-theft patterns: fake paid surveys, palliative-queue extortion,
// government-impersonation smishing links). Added as a NEW field so the
// response schema stays backward-compatible (no existing field renamed).
type LureSignals struct {
	DataHarvest      bool     `json:"data_harvest"`
	SurveyLure       bool     `json:"survey_lure"`
	PalliativeLure   bool     `json:"palliative_lure"`
	GovImpersonation bool     `json:"gov_impersonation"`
	LinkRiskScore    int      `json:"link_risk_score"` // 0-25, capped
	RedFlags         []string `json:"red_flags"`
}

// LanguageAnomaly reports the language_anomaly_score. It is an explicit,
// measurable-signal HEURISTIC (heuristic: true) — it is NOT a linguistic or
// grammar model and makes no such claim.
type LanguageAnomaly struct {
	Score              float64 `json:"score"` // 0.0-1.0
	Heuristic          bool    `json:"heuristic"`
	MisspellingDensity float64 `json:"misspelling_density"`
	CapsRatio          float64 `json:"caps_ratio"`
	UrgentKeywordHits  int     `json:"urgent_payment_keyword_hits"`
}

// FeeRequest represents a detected fee request
type FeeRequest struct {
	MessageID  string    `json:"message_id"`
	Amount     float64   `json:"amount"`
	Currency   string    `json:"currency"`
	Purpose    string    `json:"purpose"`
	DetectedAt time.Time `json:"detected_at"`
}

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Initialize Redis
	initRedis()
	defer redisClient.Close()

	// Setup Gin router
	router := gin.Default()

	// All routes require a valid Keycloak token (fail-closed introspection);
	// mutating actions additionally require fraud_analyst/admin.
	router.Use(authMiddleware())
	router.Use(tenantBindingMiddleware())

	// API routes
	v1 := router.Group("/api/v1/advance-fee-fraud")
	{
		v1.POST("/analyze-message", requireRole("fraud_analyst", "admin"), analyzeMessage)
		v1.POST("/detect-419", requireRole("fraud_analyst", "admin"), detect419)
		v1.POST("/detect-inheritance-scam", requireRole("fraud_analyst", "admin"), detectInheritanceScam)
		v1.POST("/detect-lottery-scam", requireRole("fraud_analyst", "admin"), detectLotteryScam)
		v1.POST("/detect-lures", requireRole("fraud_analyst", "admin"), detectLures)
		v1.POST("/verify-sender", verifySender)
		v1.POST("/track-fee-requests", requireRole("fraud_analyst", "admin"), trackFeeRequests)
		v1.GET("/risk/:message_id", getMessageRisk)
		v1.GET("/known-patterns", getKnownPatterns)
		v1.GET("/reports/daily", getDailyReport)
		v1.GET("/health", healthCheck)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8087"
	}

	log.Printf("Advance Fee Fraud Detector starting on port %s", port)
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Failed to start server:", err)
	}

}

func initDB() {
	sslMode := getEnv("DB_SSLMODE", "require")
	if sslMode == "disable" && !strings.EqualFold(os.Getenv("DB_ALLOW_INSECURE"), "true") {
		log.Fatal("DB_SSLMODE=disable requires DB_ALLOW_INSECURE=true (local development only)")
	}
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", ""),
		getEnv("DB_NAME", "fraudfusion"),
		sslMode,
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Bound the pool: unlimited connections can exhaust PG max_connections,
	// and the default of 2 idle connections forces a TLS handshake per query.
	db.SetMaxOpenConns(getEnvInt("DB_MAX_OPEN_CONNS", 25))
	db.SetMaxIdleConns(getEnvInt("DB_MAX_IDLE_CONNS", 25))
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err = withBackoff(func() error { return db.Ping() }); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Database connected successfully")
}

func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", getEnv("REDIS_HOST", "localhost"), getEnv("REDIS_PORT", "6379")),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
	})

	if err := withBackoff(func() error { return redisClient.Ping(ctx).Err() }); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Redis connected successfully")
}

func analyzeMessage(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analysis := performAnalysis(message)

	// Store analysis in database
	if err := storeAnalysis(message, analysis); err != nil {
		log.Printf("Error storing analysis: %v", err)
	}

	c.JSON(http.StatusOK, analysis)
}

func performAnalysis(message Message) RiskAnalysis {
	riskScore := 0
	redFlags := []string{}
	scamTypes := []string{}

	rawText := message.Subject + " " + message.Content
	combinedText := strings.ToLower(rawText)

	// Check for Nigerian prince / 419 patterns
	if is419, flags := detect419Pattern(combinedText); is419 {
		riskScore += 50
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "419_scam")
	}

	// Check for inheritance scam
	if isInheritance, flags := detectInheritancePattern(combinedText); isInheritance {
		riskScore += 45
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "inheritance_scam")
	}

	// Check for lottery scam
	if isLottery, flags := detectLotteryPattern(combinedText); isLottery {
		riskScore += 40
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "lottery_scam")
	}

	// Check for business proposal scam
	if isBusiness, flags := detectBusinessProposalPattern(combinedText); isBusiness {
		riskScore += 35
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "business_proposal")
	}

	// Check for upfront fee requests
	if feeRequests := detectFeeRequests(combinedText); len(feeRequests) > 0 {
		riskScore += 30
		redFlags = append(redFlags, fmt.Sprintf("%d upfront fee request(s) detected", len(feeRequests)))
	}

	// Check for urgency and secrecy
	if urgencyScore := detectUrgencyAndSecrecy(combinedText); urgencyScore > 0 {
		riskScore += urgencyScore
		redFlags = append(redFlags, "Urgency and secrecy tactics detected")
	}

	// Smishing / data-harvest lures (NIN/BVN identity-theft patterns seen in
	// Nigerian smishing campaigns: fake paid surveys, palliative-queue
	// extortion, government-impersonation links).
	lure := LureSignals{RedFlags: []string{}}
	if isHarvest, flags := detectDataHarvestPattern(combinedText); isHarvest {
		riskScore += 35
		lure.DataHarvest = true
		lure.RedFlags = append(lure.RedFlags, flags...)
		scamTypes = append(scamTypes, "data_harvest")
	}
	if isSurvey, flags := detectSurveyLurePattern(combinedText); isSurvey {
		riskScore += 25
		lure.SurveyLure = true
		lure.RedFlags = append(lure.RedFlags, flags...)
		scamTypes = append(scamTypes, "survey_lure")
	}
	if isPalliative, flags := detectPalliativeLurePattern(combinedText); isPalliative {
		riskScore += 35
		lure.PalliativeLure = true
		lure.RedFlags = append(lure.RedFlags, flags...)
		scamTypes = append(scamTypes, "palliative_extortion")
	}
	if isGov, flags := detectGovImpersonationPattern(combinedText); isGov {
		riskScore += 30
		lure.GovImpersonation = true
		lure.RedFlags = append(lure.RedFlags, flags...)
		scamTypes = append(scamTypes, "gov_impersonation")
	}
	if linkScore, flags := linkRiskScore(combinedText); linkScore > 0 {
		lure.LinkRiskScore = min(linkScore, 25)
		riskScore += lure.LinkRiskScore
		lure.RedFlags = append(lure.RedFlags, flags...)
	}
	redFlags = append(redFlags, lure.RedFlags...)

	// Check sender legitimacy (disposable-looking local part only)
	if !verifySenderLegitimacy(message.SenderEmail) {
		riskScore += 20
		redFlags = append(redFlags, "Suspicious sender email pattern")
	}

	// Language anomaly heuristic: measurable signals only (out-of-vocabulary
	// density against a small embedded wordlist, excessive-caps ratio,
	// urgent-payment keyword hits). This replaced a fake "grammar check"
	// that matched greeting phrases and claimed to detect grammar issues.
	anomaly := languageAnomalyScore(rawText, combinedText)
	if anomaly.Score >= 0.5 {
		riskScore += 15
		redFlags = append(redFlags, "Language anomalies detected (misspellings/caps/urgent-payment keywords)")
	}

	// Free webmail is never a standalone signal (it is the norm in Nigeria);
	// it only mildly amplifies risk when the CONTENT already flagged.
	if len(redFlags) > 0 && isFreeWebmailProvider(message.SenderEmail) {
		riskScore += 5
		redFlags = append(redFlags, "Free webmail sender combined with other fraud indicators")
	}

	// Determine primary scam type
	scamType := "unknown"
	if len(scamTypes) > 0 {
		scamType = scamTypes[0]
	}

	// Determine risk level
	riskLevel := getRiskLevel(riskScore)

	// Generate recommendation
	recommendation := generateRecommendation(riskScore, scamType)

	return RiskAnalysis{
		MessageID:       message.ID,
		RiskScore:       min(riskScore, 100),
		RiskLevel:       riskLevel,
		ScamType:        scamType,
		Is419Scam:       riskScore >= 60,
		RedFlags:        redFlags,
		Recommendation:  recommendation,
		LanguageAnomaly: anomaly,
		LureSignals:     lure,
	}
}

func detect419Pattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(nigerian|african)\s+(prince|princess|king|royal)`, "Nigerian royalty mentioned", 30},
		{`(million|billion)\s+(dollars|pounds|euros|usd|gbp|eur)`, "Large sum of money mentioned", 25},
		{`(transfer|move)\s+(funds|money)\s+out\s+of`, "Money transfer out of country", 20},
		{`(deceased|late)\s+(relative|husband|wife|father|mother)`, "Deceased relative mentioned", 20},
		{`(confidential|private|secret)\s+(transaction|deal|business)`, "Confidential transaction", 15},
		{`(business\s+proposal|investment\s+opportunity)`, "Business proposal", 15},
		{`(urgent|immediate)\s+(attention|response|reply)`, "Urgent response required", 10},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

func detectInheritancePattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(inherit|inheritance|estate|will)`, "Inheritance mentioned", 25},
		{`(next\s+of\s+kin|beneficiary|heir)`, "Next of kin/beneficiary", 20},
		{`(unclaimed|dormant)\s+(funds|account)`, "Unclaimed funds", 20},
		{`(lawyer|attorney|solicitor|barrister)`, "Legal representative", 15},
		{`(bank|financial\s+institution)`, "Bank mentioned", 10},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

func detectLotteryPattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(lottery|sweepstakes|raffle)\s+(winner|won)`, "Lottery winner claim", 30},
		{`(congratulations|congrats).*won`, "Congratulations message", 20},
		{`(claim|collect)\s+(prize|winnings)`, "Prize claim request", 20},
		{`(processing\s+fee|handling\s+fee|tax)`, "Processing fee mentioned", 25},
		{`never\s+(entered|participated)`, "Never entered lottery", 15},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

func detectBusinessProposalPattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`business\s+(proposal|opportunity|partnership)`, "Business proposal", 20},
		{`(lucrative|profitable)\s+(deal|venture)`, "Lucrative deal", 15},
		{`(commission|percentage)\s+for\s+your\s+(assistance|help)`, "Commission offer", 20},
		{`(confidential|discreet)\s+(transaction|deal)`, "Confidential deal", 15},
		{`(foreign|overseas)\s+(investment|contract)`, "Foreign investment", 15},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 25, flags
}

func detectFeeRequests(text string) []string {
	requests := []string{}

	patterns := []string{
		`(processing|handling|transfer|legal|administrative)\s+fee`,
		`(pay|send|wire|transfer)\s+.*\s+(fee|charge|cost)`,
		`upfront\s+(payment|fee|cost)`,
		`(advance|initial)\s+(payment|deposit)`,
		`(tax|duty|customs)\s+(payment|fee)`,
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, text)
		if matched {
			requests = append(requests, pattern)
		}
	}

	return requests
}

func detectUrgencyAndSecrecy(text string) int {
	score := 0

	urgencyKeywords := []string{"urgent", "immediate", "quickly", "asap", "time sensitive", "deadline"}
	secrecyKeywords := []string{"confidential", "secret", "private", "discreet", "do not tell", "keep quiet"}

	for _, keyword := range urgencyKeywords {
		if strings.Contains(text, keyword) {
			score += 5
		}
	}

	for _, keyword := range secrecyKeywords {
		if strings.Contains(text, keyword) {
			score += 5
		}
	}

	return min(score, 20)
}

// ---------------------------------------------------------------------------
// Smishing / data-harvest lure detectors (NIN/BVN identity-theft patterns).
// Heuristic behind all five: a data request is suspicious when the requesting
// entity has NO legitimate need for that field ("if FRSC asks for your plate
// number that makes sense; your BVN, not so much") — and when sensitive
// identity fields are solicited via forms, replies, or links.
//
// All detectors take the already-lowercased subject+content, return
// (matched, flags) and are wired into the composite score in performAnalysis
// exactly like detect419Pattern & friends.
// ---------------------------------------------------------------------------

// sensitiveFieldRe matches the Nigerian identity fields harvested in NIN/BVN
// identity-theft campaigns. Word boundaries are deliberate so "nin" does not
// match "remaining"/"nineteen".
var sensitiveFieldRe = regexp.MustCompile(
	`\b(bvn|bank verification number|nin|national identification number|ninn?c slip|otp|one[\s-]?time (password|pin|code)|passcode|pvc|permanent voters? card|voter'?s? card|date of birth|dob|atm pin|card pin|bvn number|nin number)\b`)

// solicitationRe matches verbs used to harvest data via forms or replies.
var solicitationRe = regexp.MustCompile(
	`\b(provide|send|submit|enter|fill|supply|disclose|input|share|reply with|respond with|type in|key in|confirm your|verify your|validate your|update your|re-?validate)\b`)

// advisoryRe matches anti-fraud advisories ("never share your BVN...") which
// mention sensitive fields and share/send verbs but are NOT harvest attempts.
var advisoryRe = regexp.MustCompile(
	`\b(never|do not|don't|not to)\s+(share|give|send|disclose|provide)\s+(your\s+)?(bvn|nin|otp|pin|password|voter'?s? card|pvc)`)

// imperativeRe matches AFFIRMATIVE requests for data. When a text matches
// advisoryRe but no imperative, the solicitation match is treated as an
// advisory, not a harvest attempt.
var imperativeRe = regexp.MustCompile(
	`\b(reply with|respond with|send (us|me|back|your|ur)\b|submit|fill|enter|provide|supply|input|type in|key in|confirm your|verify your|validate your|update your|re-?validate|click (the |this |that )?link)\b`)

// detectDataHarvestPattern fires when sensitive identity fields (BVN, NIN,
// DOB, OTP, voter's card) are being SOLICITED via a form, reply, or link —
// not merely mentioned (a bank warning you to "never share your BVN" is not
// a harvest attempt).
func detectDataHarvestPattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	fieldMentions := len(sensitiveFieldRe.FindAllString(text, -1))
	solicits := solicitationRe.MatchString(text)
	if solicits && advisoryRe.MatchString(text) && !imperativeRe.MatchString(text) {
		// "never share your BVN" style advisory — not a harvest attempt.
		solicits = false
	}

	if fieldMentions > 0 && solicits {
		score += 25
		flags = append(flags, "Sensitive identity data (BVN/NIN/DOB/OTP/voter's card) solicited via reply or form")
	}
	if fieldMentions >= 2 {
		score += 10
		flags = append(flags, "Multiple sensitive identity fields requested together")
	}
	if matched, _ := regexp.MatchString(
		`(reply|respond|send)\s+(back\s+)?with\s+(your\s+)?(full\s+)?(name|details|bvn|nin|otp|date of birth|voter)`, text); matched {
		score += 15
		flags = append(flags, "Reply-with-personal-data instruction")
	}
	if matched, _ := regexp.MatchString(
		`(fill|complete|submit)\s+(out\s+)?(this|the|a|our)\s+(short\s+)?(form|questionnaire|survey|registration)`, text); matched && fieldMentions > 0 {
		score += 10
		flags = append(flags, "Form-based personal data collection")
	}

	return score >= 25, flags
}

// detectSurveyLurePattern fires on the "we're doing a survey, we'll pay you
// ₦2k/₦5k" lure: an unsolicited survey/registration tied to a promised SMALL
// naira payment — the bait used to harvest BVN/NIN/DOB.
func detectSurveyLurePattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(conducting|running|doing|carrying out)\s+a\s+(short\s+|brief\s+|simple\s+)?(survey|questionnaire|poll|registration)`, "Unsolicited survey/registration claim", 20},
		{`(survey|questionnaire|poll)\s+(for|and|that|to)\s+(get|be paid|earn|receive)`, "Survey tied to payment", 15},
		{`(get paid|be paid|earn|pay you|paid|reward(ed)?|compensat\w+|cash\s*out)\s*(of|up to|about)?\s*(₦|ngn|n)?\s*\d{1,3}(,\d{3})?\s*(naira|k\b)?`, "Small promised payment (₦2k/₦5k bait)", 20},
		{`\b\d{1,2}k\b\s*(naira|cash|reward|for you|each)?`, "Colloquial small-cash bait ('2k', '5k')", 10},
		{`(fill|complete|answer)\s+(out\s+)?(this|the|a|our)\s+(short\s+|brief\s+|simple\s+)?(survey|form|questionnaire)`, "Fill-this-form instruction", 10},
		{`(few\s+minutes?|2\s+minutes?|5\s+minutes?)\s+(of\s+)?(your\s+)?time`, "Minimal-effort framing", 10},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

// detectPalliativeLurePattern fires when access to palliatives / relief
// materials / empowerment queues is made CONDITIONAL on surrendering NIN,
// BVN, or voter's card details (queue-jump extortion).
func detectPalliativeLurePattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(palliative|relief (materials?|package|items?|fund)|food\s*relief|empowerment\s*(programme|program|scheme)|subsidy removal (palliative|relief)|conditional cash transfer)`, "Palliative/relief/empowerment theme", 20},
		{`(palliative|relief|empowerment|grant|stipend|cash transfer|shortlist)[\s\S]{0,80}(nin|bvn|voter'?s? card|pvc|national identification)`, "Palliative access conditioned on identity data", 20},
		{`(submit|provide|present|bring|drop|send|come with)\s+(your\s+)?(nin|bvn|voter'?s? card|pvc|national identification)`, "Surrender-of-identity-document demand", 15},
		{`(secure|reserve|book|confirm|jump)\s+(your\s+)?(spot|slot|place|position|queue)`, "Queue/slot pressure tactic", 10},
		{`(queue|wait in line|join the (line|queue)|limited slots?|first come)`, "Queue scarcity framing", 10},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

// govEntityRe matches Nigerian government / regulatory bodies impersonated in
// smishing (FRSC-lite bodies included). Full names and abbreviations both.
var govEntityRe = regexp.MustCompile(
	`\b(frsc|federal road safety( corps)?|nimc|national identity management commission|nibss|cbn|central bank of nigeria|efcc|nigeria immigration( service)?|nis\b|nigerian police( force)?|npf\b|inec|firs\b|national population commission|npc\b|ndic|ministry of (interior|finance|humanitarian affairs))\b`)

// threatRe matches the coercion language used in gov-impersonation smishing
// (stronger than ordinary urgency so legitimate renewal reminders don't fire).
var threatRe = regexp.MustCompile(
	`(will be (blocked|suspended|deactivated|impounded|arrested|prosecuted)|has been (blocked|suspended|deactivated|flagged)|failure to comply|within 24 hours|or face (arrest|prosecution|suspension)|final notice|last warning)`)

// detectGovImpersonationPattern fires when a message CLAIMS to be a
// government/regulatory entity AND compounds that claim with a link, a
// sensitive-data demand, or a coercion threat. A bare entity mention (e.g. a
// legitimate FRSC plate-number renewal reminder) is NOT enough — that is the
// legitimacy heuristic from the field guidance.
func detectGovImpersonationPattern(text string) (bool, []string) {
	flags := []string{}
	if !govEntityRe.MatchString(text) {
		return false, flags
	}
	score := 15
	flags = append(flags, "Claims government/regulatory entity identity")

	if urlPattern.MatchString(text) {
		score += 10
		flags = append(flags, "Government claim combined with a link")
	}
	if sensitiveFieldRe.MatchString(text) && solicitationRe.MatchString(text) {
		score += 15
		flags = append(flags, "Government entity demanding sensitive identity data it has no legitimate need for")
	}
	if threatRe.MatchString(text) {
		score += 10
		flags = append(flags, "Coercion/threat language (suspension, arrest, 24-hour deadline)")
	}

	return score >= 30, flags
}

// ---------------------------------------------------------------------------
// linkRiskScore: URL risk helper for smishing.
// Signals: suspicious TLDs, URL shorteners, IP-literal hosts, look-alike
// domains containing government entity names off official *.gov.ng domains,
// and compounding when any URL co-occurs with data-harvest keywords.
// Returns (score, flags); score is capped at 25 by the caller.
// ---------------------------------------------------------------------------

var urlPattern = regexp.MustCompile(
	`(?i)\b(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s]*)?`)

var ipHostPattern = regexp.MustCompile(
	`\bhttps?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|\b)`)

// suspiciousTLDs: cheap/abuse-heavy TLDs disproportionately used in Nigerian
// smishing links. .ng/.com/.org/.net are NOT listed — they are normal.
var suspiciousTLDs = map[string]bool{
	"tk": true, "ml": true, "ga": true, "cf": true, "gq": true, // free Freenom TLDs
	"xyz": true, "top": true, "click": true, "link": true, "buzz": true,
	"icu": true, "pw": true, "cam": true, "quest": true, "live": true,
	"online": true, "site": true, "website": true, "shop": true, "rest": true,
}

// urlShorteners: short links hide the true destination from the victim.
var urlShorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true,
	"is.gd": true, "cutt.ly": true, "rb.gy": true, "ow.ly": true,
	"buff.ly": true, "rebrand.ly": true, "shorturl.at": true, "tiny.cc": true,
}

// govLookalikeNames: entity names whose presence inside a NON-official domain
// is a look-alike signal (e.g. frsc-verify.xyz). Official *.gov.ng domains are
// explicitly excluded.
var govLookalikeNames = []string{
	"frsc", "nimc", "nibss", "cbn", "efcc", "inec", "immigration", "firs", "npf", "ndic",
}

// harvestKeywordRe is the compounding trigger: any URL in a message that also
// solicits identity data.
var harvestKeywordRe = regexp.MustCompile(
	`\b(bvn|nin|otp|pvc|date of birth|voter'?s? card|bank verification number|national identification number|password|atm pin|card pin)\b`)

func linkRiskScore(text string) (int, []string) {
	flags := []string{}
	urls := urlPattern.FindAllString(text, -1)
	ipURLs := ipHostPattern.FindAllString(text, -1)
	if len(urls) == 0 && len(ipURLs) == 0 {
		return 0, flags
	}

	score := 0
	seenTLD, seenShortener, seenLookalike := false, false, false

	if len(ipURLs) > 0 {
		score += 10
		flags = append(flags, "Link uses a raw IP address instead of a domain name")
	}

	for _, u := range urls {
		host := u
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))

		labels := strings.Split(host, ".")
		tld := labels[len(labels)-1]
		if !seenTLD && suspiciousTLDs[tld] {
			seenTLD = true
			score += 8
			flags = append(flags, fmt.Sprintf("Suspicious top-level domain (.%s)", tld))
		}
		if !seenShortener && urlShorteners[host] {
			seenShortener = true
			score += 10
			flags = append(flags, "URL shortener hides the true destination")
		}
		if !seenLookalike && !strings.HasSuffix(host, ".gov.ng") && host != "gov.ng" {
			for _, name := range govLookalikeNames {
				if strings.Contains(host, name) {
					seenLookalike = true
					score += 12
					flags = append(flags, fmt.Sprintf("Look-alike domain impersonating '%s' outside official *.gov.ng", name))
					break
				}
			}
		}
	}

	if harvestKeywordRe.MatchString(text) {
		score += 8
		flags = append(flags, "Link combined with request for sensitive identity data (compounding)")
	}

	return min(score, 25), flags
}

// detectLures is the standalone HTTP endpoint for the smishing/data-harvest
// lure detectors (composite wiring lives in performAnalysis).
func detectLures(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	isHarvest, harvestFlags := detectDataHarvestPattern(combinedText)
	isSurvey, surveyFlags := detectSurveyLurePattern(combinedText)
	isPalliative, palliativeFlags := detectPalliativeLurePattern(combinedText)
	isGov, govFlags := detectGovImpersonationPattern(combinedText)
	linkScore, linkFlags := linkRiskScore(combinedText)

	any := isHarvest || isSurvey || isPalliative || isGov || linkScore > 0
	c.JSON(http.StatusOK, gin.H{
		"message_id":        message.ID,
		"lure_detected":     any,
		"data_harvest":      gin.H{"matched": isHarvest, "red_flags": harvestFlags},
		"survey_lure":       gin.H{"matched": isSurvey, "red_flags": surveyFlags},
		"palliative_lure":   gin.H{"matched": isPalliative, "red_flags": palliativeFlags},
		"gov_impersonation": gin.H{"matched": isGov, "red_flags": govFlags},
		"link_risk":         gin.H{"score": linkScore, "red_flags": linkFlags},
		"recommendation": func() string {
			if any {
				return "WARNING - Smishing/data-harvest lure detected. Do not click links or share BVN/NIN/OTP; navigate directly to the organisation's official site."
			}
			return "No smishing/data-harvest lure pattern detected"
		}(),
	})
}

// freeWebmailProviders are the dominant consumer mail providers in Nigeria;
// using one is normal and must never be a standalone fraud signal.
var freeWebmailProviders = []string{"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}

// isFreeWebmailProvider reports whether the email is hosted on a common free
// webmail provider.
func isFreeWebmailProvider(email string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return false
	}
	for _, provider := range freeWebmailProviders {
		if parts[1] == provider {
			return true
		}
	}
	return false
}

// suspiciousLocalPart matches disposable-looking local parts (5+ digit runs),
// e.g. "agent78342@...". Checked against the local part only.
var suspiciousLocalPart = regexp.MustCompile(`^[^@]*\d{5,}[^@]*@`)

func verifySenderLegitimacy(email string) bool {
	// Only genuinely suspicious sender patterns flag here — free webmail
	// providers (Gmail/Yahoo/Hotmail/Outlook) are the norm in Nigeria and are
	// handled as a mild combined signal in performAnalysis instead.
	return !suspiciousLocalPart.MatchString(strings.ToLower(email))
}

// embeddedCommonWords is a small wordlist of frequent English words plus
// legitimate finance vocabulary. It is deliberately small: the
// misspelling_density signal is an out-of-vocabulary RATIO, not a
// spellchecker, and is only one of three weighted signals.
var embeddedCommonWords = func() map[string]struct{} {
	words := []string{
		"the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "for", "with", "is", "are", "was", "were",
		"be", "been", "being", "i", "you", "he", "she", "it", "we", "they", "them", "his", "her", "its", "our",
		"your", "my", "me", "him", "us", "this", "that", "these", "those", "there", "here", "as", "at", "by",
		"from", "into", "about", "after", "before", "over", "under", "again", "once", "just", "also", "very",
		"can", "could", "will", "would", "shall", "should", "may", "might", "must", "do", "does", "did", "done",
		"have", "has", "had", "not", "no", "yes", "if", "then", "than", "so", "such", "when", "while", "where",
		"which", "who", "whom", "what", "how", "why", "all", "any", "both", "each", "few", "more", "most",
		"other", "some", "only", "own", "same", "too", "now", "out", "off", "up", "down", "dear", "sir", "madam",
		"friend", "hello", "greetings", "mr", "mrs", "ms", "dr", "am", "pm", "please", "thank", "thanks",
		"regards", "sincerely", "yours", "faithfully", "reply", "response", "email", "mail", "message", "write",
		"writing", "contact", "contacting", "inform", "tell", "know", "let", "need", "want", "like", "help",
		"give", "get", "got", "send", "sent", "receive", "received", "call", "phone", "name", "address", "date",
		"time", "day", "days", "week", "month", "year", "today", "tomorrow", "soon", "new", "good", "great",
		"well", "much", "many", "first", "last", "next", "kind", "information", "details", "account", "bank",
		"banking", "transfer", "payment", "pay", "paid", "fund", "funds", "money", "amount", "sum", "balance",
		"deposit", "withdraw", "credit", "debit", "transaction", "wire", "check", "cheque", "cash", "usd",
		"dollar", "dollars", "naira", "euro", "euros", "pounds", "currency", "fee", "fees", "charge", "cost",
		"price", "total", "percent", "number", "card", "code", "document", "documents", "form", "id",
		"passport", "license", "company", "business", "office", "manager", "director", "president", "minister",
		"government", "official", "legal", "lawyer", "attorney", "contract", "agreement", "proposal", "offer",
		"deal", "partner", "client", "customer", "service", "security", "secure", "safe", "confidential",
		"private", "personal", "urgent", "immediate", "immediately", "attention", "important", "verify",
		"confirm", "confirmation", "process", "processing", "release", "claim", "claims", "winner", "winning",
		"lottery", "prize", "award", "fund", "inheritance", "estate", "beneficiary", "heir", "kin", "relative",
		"late", "deceased", "death", "died", "will", "left", "behalf", "sincerely", "await", "waiting",
		"hearing", "hope", "hoping", "able", "enable", "necessary", "required", "require", "upon", "above",
		"below", "between", "through", "during", "without", "within", "per", "via", "etc", "re", "ref",
	}
	set := make(map[string]struct{}, len(words))
	for _, w := range words {
		set[w] = struct{}{}
	}
	return set
}()

// urgentPaymentKeywords are multi/single-word urgent-payment phrases whose
// presence is a measurable scam signal (counted as hits).
var urgentPaymentKeywords = []string{
	"urgent payment", "urgent transfer", "act now", "act immediately", "immediately transfer",
	"wire the", "send the fee", "pay the fee", "processing fee", "advance fee", "upfront fee",
	"western union", "moneygram", "gift card", "itunes card", "within 24 hours", "within 48 hours",
	"expire", "expires soon", "last chance", "final notice", "do not delay", "without delay",
}

var wordTokenPattern = regexp.MustCompile(`[a-zA-Z]{3,}`)

// languageAnomalyScore computes an HONEST heuristic from three measurable
// signals only. It makes no grammar/linguistic claims:
//  1. misspelling_density: fraction of >=3-letter tokens absent from the
//     small embedded wordlist (a crude out-of-vocabulary ratio — names and
//     jargon count, which is why it is only weighted 0.4 and labeled
//     heuristic).
//  2. caps_ratio: fraction of >=3-letter tokens that are ALL CAPS in the
//     original (un-lowercased) text; sustained SHOUTING is a scam tell.
//  3. urgent_payment_keyword_hits: count of urgent-payment phrase hits.
func languageAnomalyScore(rawText, lowerText string) LanguageAnomaly {
	result := LanguageAnomaly{Heuristic: true}

	tokens := wordTokenPattern.FindAllString(rawText, -1)
	if len(tokens) > 0 {
		unknown := 0
		caps := 0
		for _, tok := range tokens {
			if len(tok) >= 3 && tok == strings.ToUpper(tok) {
				caps++
			}
			if _, ok := embeddedCommonWords[strings.ToLower(tok)]; !ok {
				unknown++
			}
		}
		result.MisspellingDensity = float64(unknown) / float64(len(tokens))
		result.CapsRatio = float64(caps) / float64(len(tokens))
	}
	for _, kw := range urgentPaymentKeywords {
		result.UrgentKeywordHits += strings.Count(lowerText, kw)
	}

	// Weighted blend, capped at 1.0. Caps only count when the message is long
	// enough for a ratio to be meaningful; keyword hits saturate at 3.
	densityScore := math.Min(result.MisspellingDensity/0.6, 1.0) * 0.4
	capsScore := 0.0
	if len(tokens) >= 8 {
		capsScore = math.Min(result.CapsRatio/0.25, 1.0) * 0.3
	}
	keywordScore := math.Min(float64(result.UrgentKeywordHits)/3.0, 1.0) * 0.3
	result.Score = math.Round(math.Min(densityScore+capsScore+keywordScore, 1.0)*1000) / 1000
	return result
}

func getRiskLevel(score int) string {
	if score >= 80 {
		return "critical"
	} else if score >= 60 {
		return "high"
	} else if score >= 40 {
		return "medium"
	}
	return "low"
}

func generateRecommendation(score int, scamType string) string {
	if score >= 80 {
		return fmt.Sprintf("BLOCK - Confirmed %s detected. Delete immediately and report as spam.", scamType)
	} else if score >= 60 {
		return fmt.Sprintf("HIGH RISK - Likely %s. Do not respond or send any money.", scamType)
	} else if score >= 40 {
		return fmt.Sprintf("CAUTION - Potential %s indicators. Verify sender before responding.", scamType)
	}
	return "LOW RISK - Standard email precautions apply."
}

func storeAnalysis(message Message, analysis RiskAnalysis) error {
	query := `
		INSERT INTO advance_fee_messages
		(message_id, user_id, sender_email, sender_name, subject, content,
		 risk_score, risk_level, scam_type, is_419_scam, red_flags, recommendation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	redFlagsJSON, _ := json.Marshal(analysis.RedFlags)

	_, err := db.Exec(query,
		analysis.MessageID,
		message.UserID,
		message.SenderEmail,
		message.SenderName,
		message.Subject,
		message.Content,
		analysis.RiskScore,
		analysis.RiskLevel,
		analysis.ScamType,
		analysis.Is419Scam,
		redFlagsJSON,
		analysis.Recommendation,
	)

	return err
}

func detect419(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	is419, flags := detect419Pattern(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":  message.ID,
		"is_419_scam": is419,
		"red_flags":   flags,
		"recommendation": func() string {
			if is419 {
				return "BLOCK - Nigerian 419 scam detected"
			}
			return "No 419 pattern detected"
		}(),
	})
}

func detectInheritanceScam(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	isInheritance, flags := detectInheritancePattern(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":          message.ID,
		"is_inheritance_scam": isInheritance,
		"red_flags":           flags,
		"recommendation": func() string {
			if isInheritance {
				return "BLOCK - Inheritance scam detected"
			}
			return "No inheritance scam pattern detected"
		}(),
	})
}

func detectLotteryScam(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	isLottery, flags := detectLotteryPattern(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":      message.ID,
		"is_lottery_scam": isLottery,
		"red_flags":       flags,
		"recommendation": func() string {
			if isLottery {
				return "BLOCK - Lottery scam detected"
			}
			return "No lottery scam pattern detected"
		}(),
	})
}

func verifySender(c *gin.Context) {
	var req struct {
		SenderEmail string `json:"sender_email"`
		SenderName  string `json:"sender_name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	isLegit := verifySenderLegitimacy(req.SenderEmail)

	c.JSON(http.StatusOK, gin.H{
		"sender_email":  req.SenderEmail,
		"is_legitimate": isLegit,
		"recommendation": func() string {
			if !isLegit {
				return "Suspicious sender - verify through official channels"
			}
			return "Sender appears legitimate"
		}(),
	})
}

func trackFeeRequests(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	feeRequests := detectFeeRequests(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":            message.ID,
		"fee_requests_detected": len(feeRequests) > 0,
		"request_count":         len(feeRequests),
		"requests":              feeRequests,
		"recommendation": func() string {
			if len(feeRequests) > 0 {
				return "WARNING - Upfront fee request detected. Do not send money."
			}
			return "No fee requests detected"
		}(),
	})
}

func getMessageRisk(c *gin.Context) {
	messageID := c.Param("message_id")

	var analysis RiskAnalysis
	var redFlagsJSON []byte

	query := `
		SELECT message_id, risk_score, risk_level, scam_type, is_419_scam, red_flags, recommendation
		FROM advance_fee_messages
		WHERE message_id = $1
	`

	err := db.QueryRow(query, messageID).Scan(
		&analysis.MessageID,
		&analysis.RiskScore,
		&analysis.RiskLevel,
		&analysis.ScamType,
		&analysis.Is419Scam,
		&redFlagsJSON,
		&analysis.Recommendation,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Message not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	json.Unmarshal(redFlagsJSON, &analysis.RedFlags)

	c.JSON(http.StatusOK, analysis)
}

func getKnownPatterns(c *gin.Context) {
	patterns := []gin.H{
		{"type": "419_scam", "description": "Nigerian prince / inheritance scam"},
		{"type": "lottery_scam", "description": "Fake lottery winnings"},
		{"type": "inheritance_scam", "description": "Unclaimed inheritance"},
		{"type": "business_proposal", "description": "Fake business opportunity"},
		{"type": "overpayment", "description": "Overpayment scam"},
		{"type": "employment", "description": "Fake job offer"},
		{"type": "data_harvest", "description": "Solicitation of BVN/NIN/DOB/OTP/voter's card via forms or replies"},
		{"type": "survey_lure", "description": "Fake paid survey (₦2k/₦5k bait) harvesting identity data"},
		{"type": "palliative_extortion", "description": "Palliative/relief queue access conditioned on NIN/BVN/voter's card"},
		{"type": "gov_impersonation", "description": "FRSC/NIMC/NIBSS/CBN/EFCC/immigration impersonation with links or data demands"},
	}

	c.JSON(http.StatusOK, gin.H{
		"patterns": patterns,
		"count":    len(patterns),
	})
}

func getDailyReport(c *gin.Context) {
	query := `
		SELECT
			COUNT(*) as total_analyzed,
			SUM(CASE WHEN is_419_scam THEN 1 ELSE 0 END) as scams_detected,
			AVG(risk_score) as avg_risk_score
		FROM advance_fee_messages
		WHERE DATE(created_at) = CURRENT_DATE
	`

	var totalAnalyzed, scamsDetected int
	var avgRiskScore float64

	err := db.QueryRow(query).Scan(&totalAnalyzed, &scamsDetected, &avgRiskScore)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"date":           time.Now().Format("2006-01-02"),
		"total_analyzed": totalAnalyzed,
		"scams_detected": scamsDetected,
		"avg_risk_score": avgRiskScore,
	})
}

func healthCheck(c *gin.Context) {
	dbHealthy := true
	if err := db.Ping(); err != nil {
		dbHealthy = false
	}

	redisHealthy := true
	if err := redisClient.Ping(ctx).Err(); err != nil {
		redisHealthy = false
	}

	status := "healthy"
	if !dbHealthy || !redisHealthy {
		status = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    status,
		"database":  dbHealthy,
		"redis":     redisHealthy,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
