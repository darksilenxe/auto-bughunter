package scanner

import (
	"sort"
	"sync"
	"time"
)

// ProbeOutcomeLedger is a global, cross-scan rolling ledger of analyst-labelled
// TP/FP/FN outcomes for each probe key. It implements Wave 1 Phase B:
//
//   - Analyst triage actions (accept → TP, reject/suppress → FP) write outcome
//     labels here via RecordOutcome.
//   - Auto-throttle: probes whose FP rate exceeds ThrottleFPThreshold over a
//     rolling window of at least ThrottleMinSamples are soft-throttled. Callers
//     check IsThrottled before running a probe and skip it when true.
//   - The ledger is exposed via the API as a "Probe Health" panel so operators
//     can see per-probe precision stats and trending noisiest checks.
//
// ProbeOutcomeLedger is safe for concurrent use.
type ProbeOutcomeLedger struct {
	mu      sync.RWMutex
	entries map[string]*probeOutcomeEntry

	// ThrottleMinSamples is the minimum number of analyst-labelled outcomes
	// a probe must have before the auto-throttle considers its FP rate.
	// Default: 10.
	ThrottleMinSamples int

	// ThrottleFPThreshold is the FP rate above which a probe is
	// auto-throttled. Default: 0.30 (30% FP over rolling window).
	ThrottleFPThreshold float64

	// ThrottleWindowSize is the maximum number of most-recent outcomes kept
	// in the rolling window per probe. Default: 50.
	ThrottleWindowSize int
}

// probeOutcomeEntry accumulates TP/FP/FN counts and a rolling window of recent
// outcome labels for one probe key.
type probeOutcomeEntry struct {
	// Cumulative lifetime totals.
	TP int
	FP int
	FN int

	// Rolling window of the last ThrottleWindowSize outcomes (true = FP,
	// false = TP).
	window []bool

	// throttled is set by the ledger when FP rate in window exceeds threshold.
	throttled         bool
	throttledAt       time.Time
	throttleReason    string
	throttleDecisions int // count of times this probe was skipped due to throttle

	// lastUpdated records the time of the most recent outcome label.
	lastUpdated time.Time
}

// OutcomeLabel is an analyst verdict on a probe firing.
type OutcomeLabel int

const (
	// OutcomeTP indicates the finding was confirmed as a true positive (accepted).
	OutcomeTP OutcomeLabel = iota
	// OutcomeFP indicates the finding was rejected or suppressed as a false positive.
	OutcomeFP
	// OutcomeFN indicates the probe missed a real vulnerability (false negative,
	// typically from manual annotation during bug-review sessions).
	OutcomeFN
)

// defaultThrottleMinSamples is the minimum samples before throttle kicks in.
const defaultThrottleMinSamples = 10

// defaultThrottleFPThreshold is 30% FP rate triggers throttle.
const defaultThrottleFPThreshold = 0.30

// defaultThrottleWindowSize is the rolling window size.
const defaultThrottleWindowSize = 50

// globalProbeOutcomeLedger is the package-level singleton used by all scan
// runs. It persists for the lifetime of the server process; the storage layer
// (postgres.go) flushes it to the database on shutdown and reloads it on
// startup via LedgerSnapshot/RestoreSnapshot.
var globalProbeOutcomeLedger = NewProbeOutcomeLedger()

// GlobalProbeOutcomeLedger returns the process-global probe outcome ledger.
func GlobalProbeOutcomeLedger() *ProbeOutcomeLedger { return globalProbeOutcomeLedger }

// NewProbeOutcomeLedger creates a new ProbeOutcomeLedger with default thresholds.
func NewProbeOutcomeLedger() *ProbeOutcomeLedger {
	return &ProbeOutcomeLedger{
		entries:             make(map[string]*probeOutcomeEntry),
		ThrottleMinSamples:  defaultThrottleMinSamples,
		ThrottleFPThreshold: defaultThrottleFPThreshold,
		ThrottleWindowSize:  defaultThrottleWindowSize,
	}
}

// RecordOutcome records an analyst-labelled outcome for the given probe key and
// updates the rolling window and throttle state. probeKey is the canonical
// probe name (e.g. "active_xss", "sqli_error").
func (l *ProbeOutcomeLedger) RecordOutcome(probeKey string, label OutcomeLabel) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.getOrCreate(probeKey)
	e.lastUpdated = time.Now()

	switch label {
	case OutcomeTP:
		e.TP++
		e.window = appendWindow(e.window, false, l.ThrottleWindowSize)
	case OutcomeFP:
		e.FP++
		e.window = appendWindow(e.window, true, l.ThrottleWindowSize)
	case OutcomeFN:
		e.FN++
	}

	// Recompute throttle state.
	l.recomputeThrottle(probeKey, e)
}

// IsThrottled returns true when the probe has been auto-throttled due to
// exceeding the FP rate threshold. Callers should skip the probe when true and
// call RecordThrottleDecision to increment the skip counter.
func (l *ProbeOutcomeLedger) IsThrottled(probeKey string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[probeKey]
	if !ok {
		return false
	}
	return e.throttled
}

// RecordThrottleDecision increments the skip counter for a throttled probe.
// This tracks how many times the probe was skipped, enabling ROI analysis.
func (l *ProbeOutcomeLedger) RecordThrottleDecision(probeKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[probeKey]; ok {
		e.throttleDecisions++
	}
}

// ProbeStats returns a snapshot of lifetime TP/FP/FN totals, rolling-window
// precision/recall metrics, and throttle state for one probe key.
func (l *ProbeOutcomeLedger) ProbeStats(probeKey string) (ProbeHealthEntry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[probeKey]
	if !ok {
		return ProbeHealthEntry{}, false
	}
	return entryToHealth(probeKey, e), true
}

// AllProbeHealth returns a snapshot of all probe health entries, sorted by
// descending rolling FP rate (noisiest probes first).
func (l *ProbeOutcomeLedger) AllProbeHealth() []ProbeHealthEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]ProbeHealthEntry, 0, len(l.entries))
	for k, e := range l.entries {
		out = append(out, entryToHealth(k, e))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RollingFPRate > out[j].RollingFPRate
	})
	return out
}

// ProbeHealthEntry is an immutable snapshot of probe health metrics exposed
// via the API.
type ProbeHealthEntry struct {
	ProbeKey          string    `json:"probeKey"`
	TP                int       `json:"tp"`
	FP                int       `json:"fp"`
	FN                int       `json:"fn"`
	TotalLabelled     int       `json:"totalLabelled"`
	LifetimeFPRate    float64   `json:"lifetimeFpRate"`
	LifetimePrecision float64   `json:"lifetimePrecision"`
	// RollingFPRate is the FP rate over the last ThrottleWindowSize outcomes.
	RollingFPRate     float64   `json:"rollingFpRate"`
	RollingWindow     int       `json:"rollingWindow"`
	Throttled         bool      `json:"throttled"`
	ThrottledAt       time.Time `json:"throttledAt,omitempty"`
	ThrottleReason    string    `json:"throttleReason,omitempty"`
	ThrottleDecisions int       `json:"throttleDecisions"`
	LastUpdated       time.Time `json:"lastUpdated,omitempty"`
}

// LedgerSnapshot is a serialisable copy of the ledger used for persistence.
type LedgerSnapshot struct {
	Entries []LedgerSnapshotEntry `json:"entries"`
}

// LedgerSnapshotEntry is one serialisable row for persistence.
type LedgerSnapshotEntry struct {
	ProbeKey          string    `json:"probeKey"`
	TP                int       `json:"tp"`
	FP                int       `json:"fp"`
	FN                int       `json:"fn"`
	Window            []bool    `json:"window"`
	Throttled         bool      `json:"throttled"`
	ThrottledAt       time.Time `json:"throttledAt,omitempty"`
	ThrottleReason    string    `json:"throttleReason,omitempty"`
	ThrottleDecisions int       `json:"throttleDecisions"`
	LastUpdated       time.Time `json:"lastUpdated,omitempty"`
}

// Snapshot returns a serialisable copy of the ledger for persistence. Safe to
// call concurrently; the snapshot captures the state at the moment of the call.
func (l *ProbeOutcomeLedger) Snapshot() LedgerSnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()
	snap := LedgerSnapshot{Entries: make([]LedgerSnapshotEntry, 0, len(l.entries))}
	for k, e := range l.entries {
		window := make([]bool, len(e.window))
		copy(window, e.window)
		snap.Entries = append(snap.Entries, LedgerSnapshotEntry{
			ProbeKey:          k,
			TP:                e.TP,
			FP:                e.FP,
			FN:                e.FN,
			Window:            window,
			Throttled:         e.throttled,
			ThrottledAt:       e.throttledAt,
			ThrottleReason:    e.throttleReason,
			ThrottleDecisions: e.throttleDecisions,
			LastUpdated:       e.lastUpdated,
		})
	}
	return snap
}

// RestoreSnapshot loads a previously persisted snapshot into the ledger.
// Existing entries are overwritten.
func (l *ProbeOutcomeLedger) RestoreSnapshot(snap LedgerSnapshot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, row := range snap.Entries {
		window := make([]bool, len(row.Window))
		copy(window, row.Window)
		l.entries[row.ProbeKey] = &probeOutcomeEntry{
			TP:                row.TP,
			FP:                row.FP,
			FN:                row.FN,
			window:            window,
			throttled:         row.Throttled,
			throttledAt:       row.ThrottledAt,
			throttleReason:    row.ThrottleReason,
			throttleDecisions: row.ThrottleDecisions,
			lastUpdated:       row.LastUpdated,
		}
	}
}

// OutcomeWeights returns the TP/FP/FN fraction weights for the given probe key
// for feeding into ML agent prompts. Returns equal weights when the probe has
// no labelled data.
func (l *ProbeOutcomeLedger) OutcomeWeights(probeKey string) (tpWeight, fpWeight, fnWeight float64) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[probeKey]
	if !ok || e.TP+e.FP+e.FN == 0 {
		return 0.33, 0.33, 0.33
	}
	total := float64(e.TP + e.FP + e.FN)
	return float64(e.TP) / total, float64(e.FP) / total, float64(e.FN) / total
}

// ---- internal helpers ----

func (l *ProbeOutcomeLedger) getOrCreate(probeKey string) *probeOutcomeEntry {
	e, ok := l.entries[probeKey]
	if !ok {
		e = &probeOutcomeEntry{}
		l.entries[probeKey] = e
	}
	return e
}

func (l *ProbeOutcomeLedger) recomputeThrottle(probeKey string, e *probeOutcomeEntry) {
	if len(e.window) < l.ThrottleMinSamples {
		// Not enough data to make a throttle decision.
		e.throttled = false
		return
	}
	fpCount := 0
	for _, fp := range e.window {
		if fp {
			fpCount++
		}
	}
	rate := float64(fpCount) / float64(len(e.window))
	if rate > l.ThrottleFPThreshold {
		if !e.throttled {
			e.throttled = true
			e.throttledAt = time.Now()
			e.throttleReason = "rolling-fp-rate-exceeded"
		}
	} else {
		// Rate has dropped back below threshold — un-throttle.
		e.throttled = false
		e.throttleReason = ""
	}
}

// appendWindow appends a value to the rolling window, trimming to maxSize.
func appendWindow(w []bool, v bool, maxSize int) []bool {
	w = append(w, v)
	if len(w) > maxSize {
		w = w[len(w)-maxSize:]
	}
	return w
}

func entryToHealth(key string, e *probeOutcomeEntry) ProbeHealthEntry {
	total := e.TP + e.FP + e.FN
	var lifetimeFP, lifetimePrec float64
	if e.TP+e.FP > 0 {
		lifetimeFP = float64(e.FP) / float64(e.TP+e.FP)
		lifetimePrec = float64(e.TP) / float64(e.TP+e.FP)
	}
	fpInWindow := 0
	for _, fp := range e.window {
		if fp {
			fpInWindow++
		}
	}
	var rollingFP float64
	if len(e.window) > 0 {
		rollingFP = float64(fpInWindow) / float64(len(e.window))
	}
	return ProbeHealthEntry{
		ProbeKey:          key,
		TP:                e.TP,
		FP:                e.FP,
		FN:                e.FN,
		TotalLabelled:     total,
		LifetimeFPRate:    lifetimeFP,
		LifetimePrecision: lifetimePrec,
		RollingFPRate:     rollingFP,
		RollingWindow:     len(e.window),
		Throttled:         e.throttled,
		ThrottledAt:       e.throttledAt,
		ThrottleReason:    e.throttleReason,
		ThrottleDecisions: e.throttleDecisions,
		LastUpdated:       e.lastUpdated,
	}
}
