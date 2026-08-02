package scanner

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// fpSignalKey identifies a probe firing on a normalised URL pattern.
type fpSignalKey struct {
	ProbeName  string
	URLPattern string
}

// fpSignalEntry accumulates fired/suppressed counts for one key.
type fpSignalEntry struct {
	fired      int
	suppressed int
	lastSeen   time.Time
}

// FPSignalStore accumulates per-probe, per-URL-pattern false-positive signals
// for a single scan run. Every call to SubmitVerifiedFinding records a signal
// here when a ProbeCorrection is present in the request context.
// FPSignalStore is safe for concurrent use.
type FPSignalStore struct {
	mu      sync.Mutex
	entries map[fpSignalKey]*fpSignalEntry
}

// NewFPSignalStore returns an empty FPSignalStore.
func NewFPSignalStore() *FPSignalStore {
	return &FPSignalStore{entries: make(map[fpSignalKey]*fpSignalEntry)}
}

// Record updates the signal for (probeName, affectedURL). suppressed is true
// when the probe firing was suppressed by proof-policy, PoC replay failure, or
// a prior FP correction pass.
func (s *FPSignalStore) Record(probeName, affectedURL string, suppressed bool) {
	key := fpSignalKey{
		ProbeName:  strings.TrimSpace(probeName),
		URLPattern: urlPattern(affectedURL),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		e = &fpSignalEntry{}
		s.entries[key] = e
	}
	e.fired++
	if suppressed {
		e.suppressed++
	}
	e.lastSeen = time.Now()
}

// FPRate returns the suppressed/fired ratio for (probeName, affectedURL) and
// the total number of samples. Returns (0, 0) when there are fewer than
// minSamples firings.
func (s *FPSignalStore) FPRate(probeName, affectedURL string, minSamples int) (rate float64, samples int) {
	key := fpSignalKey{
		ProbeName:  strings.TrimSpace(probeName),
		URLPattern: urlPattern(affectedURL),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok || e.fired < minSamples {
		return 0, 0
	}
	return float64(e.suppressed) / float64(e.fired), e.fired
}

// FPSignalRecord is an immutable snapshot of one entry from FPSignalStore.
type FPSignalRecord struct {
	ProbeName  string
	URLPattern string
	Fired      int
	Suppressed int
	LastSeen   time.Time
}

// AllRecords returns a snapshot of every tracked (probeName, urlPattern) entry.
// Used at scan end to feed the ML calibration pipeline.
func (s *FPSignalStore) AllRecords() []FPSignalRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FPSignalRecord, 0, len(s.entries))
	for k, e := range s.entries {
		out = append(out, FPSignalRecord{
			ProbeName:  k.ProbeName,
			URLPattern: k.URLPattern,
			Fired:      e.fired,
			Suppressed: e.suppressed,
			LastSeen:   e.lastSeen,
		})
	}
	return out
}

// urlPattern normalises a raw URL to "host + path" (without query string or
// fragment) so minor query-string variations are bucketed together.
func urlPattern(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	return strings.ToLower(u.Host) + u.Path
}
