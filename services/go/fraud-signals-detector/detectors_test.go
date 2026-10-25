// Parity contract test: the Go detectors must reproduce the Python reference
// scores/verdicts/factor-codes in detector_cases.json exactly.
package detectors

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type fixtureCase struct {
	Detector string         `json:"detector"`
	Payload  Payload        `json:"payload"`
	History  []HistoryEvent `json:"history"`
	Expected struct {
		Score       float64  `json:"score"`
		Verdict     string   `json:"verdict"`
		FactorCodes []string `json:"factor_codes"`
	} `json:"expected"`
}

type fixture struct {
	GeneratedAt string        `json:"generated_at"`
	Cases       []fixtureCase `json:"cases"`
}

func loadFixture(t *testing.T) (fixture, time.Time) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "python",
		"fraud-signals", "fixtures", "detector_cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx fixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	now, err := time.Parse(time.RFC3339, fx.GeneratedAt)
	if err != nil {
		t.Fatalf("parse generated_at: %v", err)
	}
	return fx, now
}

func TestParityWithPythonReference(t *testing.T) {
	fx, now := loadFixture(t)
	for i, c := range fx.Cases {
		det, ok := Detectors[c.Detector]
		if !ok {
			t.Fatalf("case %d: unknown detector %q", i, c.Detector)
		}
		r := det(c.Payload, c.History, now)
		if r.Score != c.Expected.Score {
			t.Errorf("case %d (%s): score %v, want %v", i, c.Detector, r.Score, c.Expected.Score)
		}
		if r.Verdict != c.Expected.Verdict {
			t.Errorf("case %d (%s): verdict %q, want %q", i, c.Detector, r.Verdict, c.Expected.Verdict)
		}
		if len(r.Factors) != len(c.Expected.FactorCodes) {
			t.Errorf("case %d (%s): %d factors, want %d", i, c.Detector, len(r.Factors), len(c.Expected.FactorCodes))
			continue
		}
		for j, f := range r.Factors {
			if f.Code != c.Expected.FactorCodes[j] {
				t.Errorf("case %d (%s): factor %d code %q, want %q",
					i, c.Detector, j, f.Code, c.Expected.FactorCodes[j])
			}
		}
	}
}
