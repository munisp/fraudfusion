package handlers

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Nigerian AML regulatory rules (MLPPA 2022 / NFIU guidance):
//
//   - CTR: currency transactions at or above ₦10,000,000 (individual) must be
//     reported to the NFIU. The threshold is configurable via
//     CTR_THRESHOLD_NGN.
//   - STR/SAR: suspicious transaction reports must reach the NFIU within 72
//     hours of detection. The SLA is configurable via STR_SLA_HOURS; breaches
//     increment the strSLABreaches counter (surfaced on the compliance
//     metrics endpoint) and are logged as alerts.

const (
	defaultCTRThresholdNGN = 10_000_000.0
	defaultSTRSLAHours     = 72
)

// strSLABreaches counts STR filing SLA breaches (filed late or overdue).
// Read via STRSLABreaches; surfaced as a compliance breach alert metric.
var strSLABreaches atomic.Int64

// STRSLABreaches returns the number of STR SLA breaches observed by this
// process since boot.
func STRSLABreaches() int64 {
	return strSLABreaches.Load()
}

// ctrThresholdNGN resolves the CTR threshold (NGN) from the environment.
func ctrThresholdNGN() float64 {
	if raw := strings.TrimSpace(os.Getenv("CTR_THRESHOLD_NGN")); raw != "" {
		if value, err := strconv.ParseFloat(raw, 64); err == nil && value > 0 {
			return value
		}
	}
	return defaultCTRThresholdNGN
}

// strSLA resolves the STR filing deadline from the environment.
func strSLA() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("STR_SLA_HOURS")); raw != "" {
		if hours, err := strconv.Atoi(raw); err == nil && hours > 0 {
			return time.Duration(hours) * time.Hour
		}
	}
	return defaultSTRSLAHours * time.Hour
}

// requiresCTR reports whether a transaction crosses the Nigerian CTR
// reporting threshold (₦10M default, NGN-denominated transactions).
func requiresCTR(currency string, amount float64) bool {
	return strings.EqualFold(strings.TrimSpace(currency), "NGN") && amount >= ctrThresholdNGN()
}

// filedWithinSLA reports whether a report detected at detectedAt was filed at
// filedAt inside the STR SLA window.
func filedWithinSLA(detectedAt, filedAt time.Time) bool {
	return filedAt.Sub(detectedAt) <= strSLA()
}

// sarFilingOutcome is the pure decision function for SAR filing:
// only a successful regulator filing may transition a SAR to "filed".
// Anything else keeps the SAR unfiled under "filing_failed" so compliance
// can retry, and the caller must alert.
func sarFilingOutcome(success bool) string {
	if success {
		return "filed"
	}
	return "filing_failed"
}

// recordSTRSLAOutcome updates the breach metric for a filing attempt. Late
// filings still count as breaches (the deadline was missed); unfiled SARs
// past the deadline are counted by the overdue metric query.
func recordSTRSLAOutcome(detectedAt, filedAt time.Time) bool {
	within := filedWithinSLA(detectedAt, filedAt)
	if !within {
		strSLABreaches.Add(1)
	}
	return within
}
