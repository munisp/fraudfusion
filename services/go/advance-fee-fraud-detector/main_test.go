package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestFreeWebmailNotStandaloneSignal is the regression test for the Gmail/
// Yahoo blanket +20 defect: a clean message from Gmail must score zero
// sender risk, and webmail only mildly amplifies an already-flagged message.
func TestFreeWebmailNotStandaloneSignal(t *testing.T) {
	if !verifySenderLegitimacy("john.doe@gmail.com") {
		t.Fatal("gmail.com must not be flagged as suspicious")
	}
	if !verifySenderLegitimacy("amina@yahoo.com") {
		t.Fatal("yahoo.com must not be flagged as suspicious")
	}
	if verifySenderLegitimacy("agent78342@gmail.com") {
		t.Fatal("disposable-looking numeric local part must still flag")
	}

	clean := performAnalysis(Message{
		ID:          "m1",
		SenderEmail: "john.doe@gmail.com",
		Subject:     "Meeting schedule",
		Content:     "Can we move our project sync to Tuesday afternoon?",
	})
	for _, flag := range clean.RedFlags {
		if strings.Contains(flag, "webmail") || strings.Contains(flag, "sender email") {
			t.Fatalf("clean gmail message must not carry sender flags: %v", clean.RedFlags)
		}
	}

	scam := performAnalysis(Message{
		ID:          "m2",
		SenderEmail: "prince.consultant@gmail.com",
		Subject:     "URGENT: inheritance transfer",
		Content:     "I am a prince. You have inherited $5,000,000. Send a processing fee and keep this confidential and secret. Act now, urgent.",
	})
	foundCombined := false
	for _, flag := range scam.RedFlags {
		if strings.Contains(flag, "Free webmail") {
			foundCombined = true
		}
	}
	if !foundCombined {
		t.Fatalf("webmail must appear as a mild combined signal when content flags exist: %v", scam.RedFlags)
	}
}

// TestIsFreeWebmailProvider covers the provider detection helper.
func TestIsFreeWebmailProvider(t *testing.T) {
	if !isFreeWebmailProvider("a@GMAIL.com") {
		t.Fatal("case-insensitive gmail match")
	}
	if isFreeWebmailProvider("a@firstbank.ng") {
		t.Fatal("corporate domain is not free webmail")
	}
	if isFreeWebmailProvider("not-an-email") {
		t.Fatal("malformed email is not free webmail")
	}
}

func TestLanguageAnomalyScoreHeuristic(t *testing.T) {
	// Clean, professional text: low anomaly.
	cleanRaw := "Dear Customer, Please find attached the monthly account statement for your review. Regards, Bank Support"
	clean := languageAnomalyScore(cleanRaw, strings.ToLower(cleanRaw))
	if !clean.Heuristic {
		t.Fatal("language anomaly output must be labeled heuristic: true")
	}
	if clean.Score >= 0.5 {
		t.Fatalf("clean text scored %.3f, want < 0.5", clean.Score)
	}

	// Scammy text: ALL CAPS SHOUTING + urgent-payment keywords + gibberish.
	scamRaw := "URGENT PAYMENT REQUIRED ACT NOW. SEND THE PROCESSING FEE VIA WESTERN UNION WITHIN 24 HOURS. xqzplm vwkjdr bnmgty FOREVERMORE"
	scam := languageAnomalyScore(scamRaw, strings.ToLower(scamRaw))
	if scam.Score < 0.5 {
		t.Fatalf("scam text scored %.3f, want >= 0.5 (caps=%.2f density=%.2f hits=%d)", scam.Score, scam.CapsRatio, scam.MisspellingDensity, scam.UrgentKeywordHits)
	}
	if scam.UrgentKeywordHits < 3 {
		t.Fatalf("urgent keyword hits = %d, want >= 3", scam.UrgentKeywordHits)
	}
	if scam.CapsRatio <= 0 {
		t.Fatal("caps ratio should be positive for all-caps text")
	}
	if scam.Score > 1.0 {
		t.Fatalf("score must be capped at 1.0, got %.3f", scam.Score)
	}
}

func TestLanguageAnomalyScoreEmpty(t *testing.T) {
	got := languageAnomalyScore("", "")
	if got.Score != 0 || !got.Heuristic {
		t.Fatalf("empty text: score=%.3f heuristic=%t, want 0/true", got.Score, got.Heuristic)
	}
}

// ---------------------------------------------------------------------------
// Smishing / data-harvest lure detector tests (NIN/BVN identity-theft
// patterns: fake paid surveys, palliative-queue extortion, FRSC-style
// government-impersonation smishing links).
// ---------------------------------------------------------------------------

// TestDetectDataHarvestPattern: solicitation of BVN/NIN/DOB/OTP/voter's card
// via forms or replies fires; a bank warning you NOT to share your BVN does
// not (no solicitation verb + field pairing... here: advisory, not harvest).
func TestDetectDataHarvestPattern(t *testing.T) {
	harvest := "to complete your registration, reply with your bvn, nin and date of birth"
	if ok, flags := detectDataHarvestPattern(harvest); !ok || len(flags) == 0 {
		t.Fatalf("harvest reply lure must fire: ok=%t flags=%v", ok, flags)
	}
	form := "please fill this form and submit your bvn and voter's card number"
	if ok, _ := detectDataHarvestPattern(form); !ok {
		t.Fatal("form-based harvest must fire")
	}
	advisory := "security tip: never share your bvn or otp with anyone, we will never ask for it"
	if ok, flags := detectDataHarvestPattern(advisory); ok {
		t.Fatalf("anti-fraud advisory must not fire (no solicitation): %v", flags)
	}
	// 'nin' inside an ordinary word must not match (word-boundary check).
	inno := "the remaining nineteen minutes of the meeting are for planning"
	if ok, flags := detectDataHarvestPattern(inno); ok {
		t.Fatalf("innocent text with 'nin' substrings must not fire: %v", flags)
	}
}

// TestDetectSurveyLurePattern: the "we're doing a survey, we'll pay you
// ₦2k/₦5k" bait.
func TestDetectSurveyLurePattern(t *testing.T) {
	survey := "hello! we are conducting a short survey and we'll pay you ₦5,000 for 5 minutes of your time. just fill this form to participate."
	if ok, flags := detectSurveyLurePattern(survey); !ok || len(flags) == 0 {
		t.Fatalf("survey-for-₦5k lure must fire: ok=%t flags=%v", ok, flags)
	}
	pidgin := "we dey do one small survey, you go earn 2k cash if you answer am"
	if ok, flags := detectSurveyLurePattern(pidgin); !ok {
		t.Fatalf("colloquial '2k' survey bait must fire: flags=%v", flags)
	}
	// a genuine market-research invite without payment bait or form push is
	// below threshold
	genuine := "thank you for attending our webinar; the optional feedback survey is now open on your dashboard"
	if ok, flags := detectSurveyLurePattern(genuine); ok {
		t.Fatalf("genuine feedback survey must not fire: %v", flags)
	}
}

// TestDetectPalliativeLurePattern: queue/palliative/relief access conditioned
// on surrendering NIN/BVN/voter's card.
func TestDetectPalliativeLurePattern(t *testing.T) {
	palliative := "fg palliative distribution: to secure your slot in the relief materials queue, submit your nin and voter's card number to the coordinator now. limited slots available."
	if ok, flags := detectPalliativeLurePattern(palliative); !ok || len(flags) == 0 {
		t.Fatalf("palliative queue lure must fire: ok=%t flags=%v", ok, flags)
	}
	empowerment := "the empowerment programme shortlist is out; come with your bvn to collect your grant"
	if ok, flags := detectPalliativeLurePattern(empowerment); !ok {
		t.Fatalf("empowerment/BVN lure must fire: flags=%v", flags)
	}
	// a real food-drive announcement with no identity-data condition must not fire
	real := "community food relief distribution holds saturday 9am at the primary school field. come one come all."
	if ok, flags := detectPalliativeLurePattern(real); ok {
		t.Fatalf("genuine relief announcement must not fire: %v", flags)
	}
}

// TestDetectGovImpersonationPattern: entity claim alone is NOT enough; it
// must compound with a link, a sensitive-data demand, or a threat.
func TestDetectGovImpersonationPattern(t *testing.T) {
	smish := "frsc notice: your driver's license has been flagged. verify your bvn and date of birth immediately at http://frsc-verify.xyz/login or it will be suspended within 24 hours."
	if ok, flags := detectGovImpersonationPattern(smish); !ok || len(flags) == 0 {
		t.Fatalf("FRSC smishing must fire: ok=%t flags=%v", ok, flags)
	}
	cbn := "cbn alert: your account has been blocked. send your bvn and otp to reactivate or face suspension."
	if ok, _ := detectGovImpersonationPattern(cbn); !ok {
		t.Fatal("fake CBN data demand must fire")
	}
	// legitimate FRSC plate-number inquiry: plate numbers ARE FRSC's business;
	// official .gov.ng domain; no sensitive-data demand, no threat.
	legit := "dear motorist, this is a reminder from frsc that your vehicle plate number abc-123-xy registration expires soon. kindly visit frsc.gov.ng or any frsc office to renew."
	if ok, flags := detectGovImpersonationPattern(legit); ok {
		t.Fatalf("legitimate FRSC plate-number reminder must not fire: %v", flags)
	}
	// no entity at all -> never fires
	if ok, _ := detectGovImpersonationPattern("verify your bvn at http://totally-random.xyz now"); ok {
		t.Fatal("no government entity claim -> gov impersonation must not fire")
	}
}

// TestLinkRiskScore: suspicious TLDs, shorteners, IP literals, look-alikes,
// and the URL + harvest-keyword compounding signal.
func TestLinkRiskScore(t *testing.T) {
	if score, _ := linkRiskScore("no links here at all"); score != 0 {
		t.Fatalf("no URL must score 0, got %d", score)
	}
	if score, flags := linkRiskScore("check http://bit.ly/3xabc for details"); score < 10 {
		t.Fatalf("shortener must score >= 10, got %d (%v)", score, flags)
	}
	if score, flags := linkRiskScore("login at http://192.168.4.1/verify"); score < 10 {
		t.Fatalf("IP-literal host must score >= 10, got %d (%v)", score, flags)
	}
	lookalike := "enter your bvn at http://frsc-verify.xyz/login"
	score, flags := linkRiskScore(lookalike)
	if score < 20 {
		t.Fatalf("look-alike + suspicious TLD + harvest compounding must score >= 20, got %d (%v)", score, flags)
	}
	if score > 25 {
		t.Fatalf("link risk must be capped at 25, got %d", score)
	}
	// official domain with no harvest keywords: zero risk
	if score, flags := linkRiskScore("visit frsc.gov.ng for renewal information"); score != 0 {
		t.Fatalf("official .gov.ng link must score 0, got %d (%v)", score, flags)
	}
}

// TestPerformAnalysisSmishingLures: end-to-end composite scoring for the
// transcript's canonical lure messages.
func TestPerformAnalysisSmishingLures(t *testing.T) {
	// 1. FRSC fake-link SMS demanding BVN/DOB with a threat.
	frsc := performAnalysis(Message{
		ID:          "s1",
		SenderEmail: "frsc-alert@gmail.com",
		Subject:     "FRSC NOTICE",
		Content:     "Your driver's license has been flagged. Verify your BVN and date of birth immediately at http://frsc-verify.xyz/login or it will be suspended within 24 hours.",
	})
	if !frsc.LureSignals.GovImpersonation || !frsc.LureSignals.DataHarvest {
		t.Fatalf("FRSC smishing must flag gov_impersonation and data_harvest: %+v", frsc.LureSignals)
	}
	if frsc.LureSignals.LinkRiskScore < 20 {
		t.Fatalf("look-alike link must carry high link risk, got %d", frsc.LureSignals.LinkRiskScore)
	}
	if frsc.RiskScore < 60 || frsc.RiskLevel == "low" || frsc.RiskLevel == "medium" {
		t.Fatalf("FRSC smishing must be high/critical, got %d (%s)", frsc.RiskScore, frsc.RiskLevel)
	}

	// 2. Survey-for-₦5k harvesting BVN/DOB via a short link.
	survey := performAnalysis(Message{
		ID:      "s2",
		Subject: "Paid survey",
		Content: "Hello dear, we are conducting a short survey and we'll pay you ₦5,000 cash for 5 minutes of your time. Just fill this form with your name, BVN, date of birth and phone number: http://bit.ly/survey5k",
	})
	if !survey.LureSignals.SurveyLure || !survey.LureSignals.DataHarvest {
		t.Fatalf("survey lure must flag survey_lure and data_harvest: %+v", survey.LureSignals)
	}
	if survey.LureSignals.LinkRiskScore < 10 {
		t.Fatal("short link + harvest keywords must raise link risk")
	}

	// 3. Palliative queue conditioned on NIN/voter's card.
	palliative := performAnalysis(Message{
		ID:      "s3",
		Subject: "FG palliative distribution",
		Content: "To secure your slot in the relief materials queue, submit your NIN and voter's card number to the ward coordinator now. Limited slots available.",
	})
	if !palliative.LureSignals.PalliativeLure || !palliative.LureSignals.DataHarvest {
		t.Fatalf("palliative lure must flag palliative_lure and data_harvest: %+v", palliative.LureSignals)
	}
	if palliative.RiskScore < 60 {
		t.Fatalf("palliative extortion must score >= 60, got %d", palliative.RiskScore)
	}
}

// TestPerformAnalysisLegitimateNegatives: a legitimate bank alert and a
// legitimate FRSC plate-number inquiry must carry no lure signals.
func TestPerformAnalysisLegitimateNegatives(t *testing.T) {
	bankAlert := performAnalysis(Message{
		ID:          "n1",
		SenderEmail: "alerts@firstbank.ng",
		Subject:     "Credit alert",
		Content:     "Acct: 012****567 Amt: NGN 50,000.00 CR Desc: Salary payment. Avail Bal: NGN 120,340.00. Thank you for banking with us.",
	})
	if bankAlert.LureSignals.DataHarvest || bankAlert.LureSignals.SurveyLure ||
		bankAlert.LureSignals.PalliativeLure || bankAlert.LureSignals.GovImpersonation ||
		bankAlert.LureSignals.LinkRiskScore != 0 {
		t.Fatalf("legitimate bank alert must have zero lure signals: %+v", bankAlert.LureSignals)
	}
	if bankAlert.Is419Scam || bankAlert.RiskLevel == "critical" || bankAlert.RiskLevel == "high" {
		t.Fatalf("legitimate bank alert must not be high risk: %d (%s)", bankAlert.RiskScore, bankAlert.RiskLevel)
	}

	plate := performAnalysis(Message{
		ID:          "n2",
		SenderEmail: "no-reply@frsc.gov.ng",
		Subject:     "Vehicle registration renewal reminder",
		Content:     "Dear motorist, your vehicle with plate number ABC-123-XY is due for registration renewal. Kindly visit frsc.gov.ng or any FRSC office near you to renew.",
	})
	if plate.LureSignals.DataHarvest || plate.LureSignals.SurveyLure ||
		plate.LureSignals.PalliativeLure || plate.LureSignals.GovImpersonation ||
		plate.LureSignals.LinkRiskScore != 0 {
		t.Fatalf("legitimate FRSC plate-number inquiry must have zero lure signals: %+v", plate.LureSignals)
	}
}

// TestBackwardCompat419Fixtures: the classic 419 fixtures must score exactly
// as before — the new lure detectors must not fire on them.
func TestBackwardCompat419Fixtures(t *testing.T) {
	classic := performAnalysis(Message{
		ID:          "b1",
		SenderEmail: "prince.consultant@gmail.com",
		Subject:     "URGENT: inheritance transfer",
		Content:     "I am a prince. You have inherited $5,000,000. Send a processing fee and keep this confidential and secret. Act now, urgent.",
	})
	if classic.RiskScore != 50 {
		t.Fatalf("classic fixture score changed: got %d, want 50 (flags=%v)", classic.RiskScore, classic.RedFlags)
	}
	if classic.LureSignals.DataHarvest || classic.LureSignals.SurveyLure ||
		classic.LureSignals.PalliativeLure || classic.LureSignals.GovImpersonation ||
		classic.LureSignals.LinkRiskScore != 0 {
		t.Fatalf("classic 419 fixture must not trigger lure detectors: %+v", classic.LureSignals)
	}

	prince := performAnalysis(Message{
		ID:          "b2",
		SenderEmail: "barrister.john@consultant.com",
		Subject:     "Confidential business proposal",
		Content:     "Dear friend, I am a Nigerian prince seeking your assistance to transfer funds out of my country. I have 25 million dollars in a dormant account and I need a foreign partner for this confidential transaction. Your urgent response is awaited.",
	})
	if prince.ScamType != "419_scam" || !prince.Is419Scam {
		t.Fatalf("classic Nigerian-prince fixture must remain 419_scam: type=%s score=%d is419=%t",
			prince.ScamType, prince.RiskScore, prince.Is419Scam)
	}
	if prince.LureSignals.DataHarvest || prince.LureSignals.SurveyLure ||
		prince.LureSignals.PalliativeLure || prince.LureSignals.GovImpersonation {
		t.Fatalf("Nigerian-prince fixture must not trigger lure detectors: %+v", prince.LureSignals)
	}
}

// TestDetectLuresEndpoint exercises the standalone /detect-lures handler with
// gin + httptest on a bare engine (auth middleware requires Keycloak and is
// covered separately by authcommon tests; existing service tests exercise the
// detection functions directly, so this mounts the handler without auth).
func TestDetectLuresEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/detect-lures", detectLures)

	body := `{"id":"e1","subject":"FRSC NOTICE","content":"Verify your BVN now at http://frsc-verify.xyz or your license will be suspended."}`
	req := httptest.NewRequest(http.MethodPost, "/detect-lures", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		LureDetected     bool `json:"lure_detected"`
		GovImpersonation struct {
			Matched bool `json:"matched"`
		} `json:"gov_impersonation"`
		LinkRisk struct {
			Score int `json:"score"`
		} `json:"link_risk"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if !resp.LureDetected || !resp.GovImpersonation.Matched || resp.LinkRisk.Score < 20 {
		t.Fatalf("endpoint must report the FRSC lure: %+v", resp)
	}

	// validation: malformed JSON -> 400
	bad := httptest.NewRequest(http.MethodPost, "/detect-lures", strings.NewReader(`{`))
	bad.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	engine.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d, want 400", badRec.Code)
	}
}
