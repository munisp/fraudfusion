package main

import (
	"strings"
	"testing"
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
