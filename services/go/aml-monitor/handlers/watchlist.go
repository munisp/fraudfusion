package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// WatchlistEntry is one designated party on a named sanctions list.
type WatchlistEntry struct {
	Name      string   `json:"name"`
	ListName  string   `json:"list_name"`
	Program   string   `json:"program,omitempty"`
	Reference string   `json:"reference,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
}

// Watchlist is the local sanctions list used as the primary screening source
// (the ML service only augments it).
type Watchlist struct {
	Version string           `json:"version"`
	Entries []WatchlistEntry `json:"entries"`
}

// WatchlistMatch describes a screening hit with real list provenance.
type WatchlistMatch struct {
	ListName   string  `json:"list_name"`
	EntryName  string  `json:"entry_name"`
	Reference  string  `json:"reference,omitempty"`
	MatchType  string  `json:"match_type"` // exact, alias, fuzzy
	MatchScore float64 `json:"match_score"`
}

// LoadWatchlist reads and validates the JSON watchlist. Malformed or empty
// lists are errors so the service fails fast at boot rather than screening
// against nothing.
func LoadWatchlist(path string) (*Watchlist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sanctions watchlist %s: %w", path, err)
	}
	var list Watchlist
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse sanctions watchlist %s: %w", path, err)
	}
	if len(list.Entries) == 0 {
		return nil, fmt.Errorf("sanctions watchlist %s contains no entries", path)
	}
	for i, entry := range list.Entries {
		if entry.Name == "" || entry.ListName == "" {
			return nil, fmt.Errorf("sanctions watchlist %s entry %d lacks name/list_name", path, i)
		}
	}
	return &list, nil
}

// normalizeName lowercases and strips non-alphanumeric characters so
// punctuation/case variants of the same party compare equal.
func normalizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else if unicode.IsSpace(r) {
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// levenshtein computes the edit distance between two strings (bounded
// two-row DP).
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// tokenOverlap is the Jaccard similarity of the token sets of two names.
func tokenOverlap(a, b string) float64 {
	set := func(s string) map[string]struct{} {
		out := map[string]struct{}{}
		for _, tok := range strings.Fields(s) {
			out[tok] = struct{}{}
		}
		return out
	}
	sa, sb := set(a), set(b)
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	intersection := 0
	for tok := range sa {
		if _, ok := sb[tok]; ok {
			intersection++
		}
	}
	return float64(intersection) / float64(len(sa)+len(sb)-intersection)
}

// fuzzyNameScore returns a 0..1 similarity for a candidate pair: 1.0 exact,
// token-set overlap for reordered/partial names, and edit-distance similarity
// for near-spellings of short single-token names.
func fuzzyNameScore(query, candidate string) float64 {
	if query == candidate {
		return 1.0
	}
	if score := tokenOverlap(query, candidate); score >= 0.8 {
		return score
	}
	distance := levenshtein(strings.ReplaceAll(query, " ", ""), strings.ReplaceAll(candidate, " ", ""))
	longest := len(query)
	if len(candidate) > longest {
		longest = len(candidate)
	}
	if longest < 6 {
		return 0 // too short for fuzzy matching without false positives
	}
	similarity := 1.0 - float64(distance)/float64(longest)
	if similarity < 0.85 {
		return 0
	}
	return similarity
}

// fuzzyMatchThreshold is the minimum similarity for a fuzzy hit.
const fuzzyMatchThreshold = 0.85

// Match screens an entity name against the local watchlist, returning hits
// with real list provenance (exact, alias, or fuzzy).
func (w *Watchlist) Match(entityName string) []WatchlistMatch {
	if w == nil {
		return nil
	}
	query := normalizeName(entityName)
	if query == "" {
		return nil
	}
	matches := []WatchlistMatch{}
	seen := map[string]bool{}
	add := func(entry WatchlistEntry, matchType string, score float64) {
		key := entry.ListName + "|" + entry.Name
		if seen[key] {
			return
		}
		seen[key] = true
		matches = append(matches, WatchlistMatch{
			ListName: entry.ListName, EntryName: entry.Name, Reference: entry.Reference,
			MatchType: matchType, MatchScore: score,
		})
	}
	for _, entry := range w.Entries {
		if normalizeName(entry.Name) == query {
			add(entry, "exact", 1.0)
			continue
		}
		aliasHit := false
		for _, alias := range entry.Aliases {
			if normalizeName(alias) == query {
				add(entry, "alias", 1.0)
				aliasHit = true
				break
			}
		}
		if aliasHit {
			continue
		}
		best := fuzzyNameScore(query, normalizeName(entry.Name))
		for _, alias := range entry.Aliases {
			if score := fuzzyNameScore(query, normalizeName(alias)); score > best {
				best = score
			}
		}
		if best >= fuzzyMatchThreshold {
			add(entry, "fuzzy", best)
		}
	}
	return matches
}
