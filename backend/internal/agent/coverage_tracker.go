package agent

import (
	"strings"
	"sync"
)

// CoverageEntry records the probe history for a single (category, endpoint,
// param) combination.
type CoverageEntry struct {
	// Tried is the number of times this combination has been probed.
	Tried int
	// Confirmed is true when a probe against this combination produced a
	// verified finding.
	Confirmed bool
	// LastPayload is the most recent payload used.
	LastPayload string
}

// CoverageTracker is a thread-safe ledger of what the reasoning loop has
// already probed. Each entry is keyed by the tuple (category, endpoint, param)
// so the ReasoningIterationAgent can avoid spending budget on combinations that
// have already been exhaustively tested.
type CoverageTracker struct {
	mu      sync.RWMutex
	entries map[string]*CoverageEntry
}

// NewCoverageTracker constructs an empty CoverageTracker.
func NewCoverageTracker() *CoverageTracker {
	return &CoverageTracker{
		entries: make(map[string]*CoverageEntry),
	}
}

func coverageKey(category, endpoint, param string) string {
	return strings.ToLower(strings.TrimSpace(category)) + "|" +
		strings.TrimSpace(endpoint) + "|" +
		strings.ToLower(strings.TrimSpace(param))
}

// RecordTried marks that a probe was attempted for the given combination.
// It is safe to call concurrently.
func (t *CoverageTracker) RecordTried(category, endpoint, param, payload string) {
	key := coverageKey(category, endpoint, param)
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[key]
	if !ok {
		e = &CoverageEntry{}
		t.entries[key] = e
	}
	e.Tried++
	e.LastPayload = payload
}

// RecordConfirmed marks that a probe produced a verified finding.
// It is safe to call concurrently.
func (t *CoverageTracker) RecordConfirmed(category, endpoint, param string) {
	key := coverageKey(category, endpoint, param)
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[key]
	if !ok {
		e = &CoverageEntry{}
		t.entries[key] = e
	}
	e.Confirmed = true
}

// UncoveredCategories returns the subset of wantCategories that have not yet
// been tried in any endpoint. This lets the reasoning loop steer hypothesis
// generation toward unexplored vulnerability classes.
func (t *CoverageTracker) UncoveredCategories(wantCategories []string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	triedCats := map[string]bool{}
	for key := range t.entries {
		parts := strings.SplitN(key, "|", 3)
		if len(parts) > 0 && parts[0] != "" {
			triedCats[parts[0]] = true
		}
	}

	uncovered := make([]string, 0, len(wantCategories))
	for _, cat := range wantCategories {
		cat = strings.ToLower(strings.TrimSpace(cat))
		if cat != "" && !triedCats[cat] {
			uncovered = append(uncovered, cat)
		}
	}
	return uncovered
}

// CoverageSummary returns a snapshot of which endpoints have been probed for
// each category. The returned map is safe to read after the call; it is a copy.
func (t *CoverageTracker) CoverageSummary() map[string][]string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := map[string][]string{}
	for key, e := range t.entries {
		if e.Tried == 0 {
			continue
		}
		parts := strings.SplitN(key, "|", 3)
		if len(parts) < 2 {
			continue
		}
		cat := parts[0]
		ep := parts[1]
		if cat == "" || ep == "" {
			continue
		}
		// Avoid duplicates in the slice for this category.
		already := false
		for _, existing := range out[cat] {
			if existing == ep {
				already = true
				break
			}
		}
		if !already {
			out[cat] = append(out[cat], ep)
		}
	}
	return out
}

// TotalTried returns the total number of probe attempts recorded across all
// (category, endpoint, param) combinations.
func (t *CoverageTracker) TotalTried() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := 0
	for _, e := range t.entries {
		total += e.Tried
	}
	return total
}

// TotalConfirmed returns the number of combinations that produced a verified
// finding.
func (t *CoverageTracker) TotalConfirmed() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	count := 0
	for _, e := range t.entries {
		if e.Confirmed {
			count++
		}
	}
	return count
}
