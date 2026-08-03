package scanner

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// surface_gap_detector compares the canonical SurfaceInventory against
// the set of keys actually exercised by probes in the current scan and
// records a SurfaceGap for every entry that went unprobed.
//
// The detector is intentionally decoupled from the probes: probes push
// the keys they exercised into a ProbedKeys set (via RecordProbedKey),
// then, at end-of-scan, DetectSurfaceGaps folds inventory keys minus
// probed keys into a per-reason list of gaps.
//
// The output feeds two things:
//
//  1. Metrics (surfaceCoverageRatio, surfaceGap* on AutomationMetrics).
//  2. The hidden-endpoint probe re-queue, which walks the highest-ROI
//     gaps and pushes them back into the active probe pipeline
//     (bounded by policy budget).

// SurfaceGapReason enumerates why an inventory entry was not covered.
type SurfaceGapReason string

const (
	// SurfaceGapUnprobed — the endpoint was in the inventory but no
	// probe issued a request against its (method, host, normalized
	// path) key.
	SurfaceGapUnprobed SurfaceGapReason = "not_probed"
	// SurfaceGapParamNotFuzzed — the endpoint was probed but at least
	// one known parameter on that endpoint was not exercised.
	SurfaceGapParamNotFuzzed SurfaceGapReason = "param_not_fuzzed"
	// SurfaceGapMethodNotTested — the endpoint was probed with a
	// subset of methods (e.g. GET only) and the inventory has
	// observations for other methods (POST, PUT, DELETE).
	SurfaceGapMethodNotTested SurfaceGapReason = "method_not_tested"
)

// SurfaceGap records a single coverage gap.
type SurfaceGap struct {
	Reason      SurfaceGapReason
	Entry       SurfaceEntry
	MissingItem string // populated for param / method reasons (parameter name or HTTP method)
}

// probedKeyRegistry tracks the set of surface keys and (key, param)
// tuples probes have exercised in the current process. Reset per scan
// is intentionally not exposed — like the other Phase 1 counters, this
// is a rolling process-wide view surfaced to AutomationMetrics.Extra.
type probedKeyRegistry struct {
	keys     sync.Map // string -> struct{}, dedup of NormalizeSurfaceKey
	params   sync.Map // "<key>|<param>" -> struct{}
	gapsMu   sync.Mutex
	lastGaps []SurfaceGap
	// probedTotal counts every RecordProbedKey call for a coverage
	// KPI that surfaces "probes issued" independent of dedup.
	probedTotal atomic.Uint64
	// gapCounters snapshot the last DetectSurfaceGaps output so the
	// metrics handler can read gap totals without recomputing.
	lastUnprobed        atomic.Uint64
	lastParamNotFuzzed  atomic.Uint64
	lastMethodNotTested atomic.Uint64
	lastInventoryTotal  atomic.Uint64
	lastProbedUnique    atomic.Uint64
}

var globalProbedKeys = &probedKeyRegistry{}

// RecordProbedKey marks a (method, url, param) as exercised so the gap
// detector can subtract it from the inventory. Probes should call this
// once per request they issue against a real target endpoint. Calls
// against synthetic control baselines (see pre_report_verify) should
// not be counted.
//
// It is safe to call from any goroutine.
func RecordProbedKey(method, rawURL, param string) {
	if rawURL == "" {
		return
	}
	key := NormalizeSurfaceKey(method, rawURL, nil)
	globalProbedKeys.keys.Store(key, struct{}{})
	globalProbedKeys.probedTotal.Add(1)
	p := strings.ToLower(strings.TrimSpace(param))
	if p != "" {
		globalProbedKeys.params.Store(key+"|"+p, struct{}{})
	}
}

// SurfaceCoverageMetrics is the snapshot exposed to
// AutomationMetrics.Extra so operators can see recall risk directly.
type SurfaceCoverageMetrics struct {
	InventoryTotal   uint64  `json:"inventoryTotal"`
	ProbedUnique     uint64  `json:"probedUnique"`
	ProbedTotal      uint64  `json:"probedTotal"`
	CoverageRatio    float64 `json:"coverageRatio"`
	GapUnprobed      uint64  `json:"gapUnprobed"`
	GapParamMissing  uint64  `json:"gapParamMissing"`
	GapMethodMissing uint64  `json:"gapMethodMissing"`
}

// GetSurfaceCoverageMetrics returns the most recently observed coverage
// snapshot for AutomationMetrics.Extra. Values reflect the state after
// the most recent DetectSurfaceGaps call in the process.
func GetSurfaceCoverageMetrics() SurfaceCoverageMetrics {
	total := globalProbedKeys.lastInventoryTotal.Load()
	unique := globalProbedKeys.lastProbedUnique.Load()
	var ratio float64
	if total > 0 {
		if unique > total {
			ratio = 1.0
		} else {
			ratio = float64(unique) / float64(total)
		}
	}
	return SurfaceCoverageMetrics{
		InventoryTotal:   total,
		ProbedUnique:     unique,
		ProbedTotal:      globalProbedKeys.probedTotal.Load(),
		CoverageRatio:    ratio,
		GapUnprobed:      globalProbedKeys.lastUnprobed.Load(),
		GapParamMissing:  globalProbedKeys.lastParamNotFuzzed.Load(),
		GapMethodMissing: globalProbedKeys.lastMethodNotTested.Load(),
	}
}

// ResetSurfaceCoverageMetrics resets the process-wide counters.
// Intended for tests.
func ResetSurfaceCoverageMetrics() {
	globalProbedKeys.keys = sync.Map{}
	globalProbedKeys.params = sync.Map{}
	globalProbedKeys.gapsMu.Lock()
	globalProbedKeys.lastGaps = nil
	globalProbedKeys.gapsMu.Unlock()
	globalProbedKeys.probedTotal.Store(0)
	globalProbedKeys.lastInventoryTotal.Store(0)
	globalProbedKeys.lastProbedUnique.Store(0)
	globalProbedKeys.lastUnprobed.Store(0)
	globalProbedKeys.lastParamNotFuzzed.Store(0)
	globalProbedKeys.lastMethodNotTested.Store(0)
}

// LatestSurfaceGaps returns a copy of the most recently detected gap list.
// Like the other surface-coverage metrics, this is a rolling process-wide
// snapshot intended for immediate post-scan consumers such as the
// post_scan_validator agent.
func LatestSurfaceGaps() []SurfaceGap {
	globalProbedKeys.gapsMu.Lock()
	defer globalProbedKeys.gapsMu.Unlock()
	return cloneSurfaceGaps(globalProbedKeys.lastGaps)
}

// DetectSurfaceGaps compares the inventory with the process-wide
// probed-keys registry and returns a per-reason list of gaps. Ordering
// is deterministic (inventory order → alphabetical param/method) to
// keep operator-facing output stable.
//
// The function also updates the SurfaceCoverageMetrics snapshot so the
// metrics endpoint can be read without re-scanning the inventory.
func DetectSurfaceGaps(inv *SurfaceInventory) []SurfaceGap {
	if inv == nil {
		globalProbedKeys.lastInventoryTotal.Store(0)
		globalProbedKeys.lastProbedUnique.Store(0)
		globalProbedKeys.lastUnprobed.Store(0)
		globalProbedKeys.lastParamNotFuzzed.Store(0)
		globalProbedKeys.lastMethodNotTested.Store(0)
		return nil
	}
	entries := inv.Snapshot()
	// Group inventory entries by (host, path) so we can spot missing
	// methods across observations.
	byHostPath := map[string][]SurfaceEntry{}
	for _, e := range entries {
		byHostPath[e.Host+"|"+e.Path] = append(byHostPath[e.Host+"|"+e.Path], e)
	}

	var gaps []SurfaceGap
	var unprobed, paramMissing, methodMissing uint64
	probedUnique := uint64(0)
	for _, e := range entries {
		key := e.Key()
		if _, ok := globalProbedKeys.keys.Load(key); !ok {
			gaps = append(gaps, SurfaceGap{Reason: SurfaceGapUnprobed, Entry: e})
			unprobed++
			continue
		}
		probedUnique++
		// Check each known parameter for coverage.
		for _, p := range e.Params {
			if _, ok := globalProbedKeys.params.Load(key + "|" + p); !ok {
				gaps = append(gaps, SurfaceGap{
					Reason:      SurfaceGapParamNotFuzzed,
					Entry:       e,
					MissingItem: p,
				})
				paramMissing++
			}
		}
	}
	// Method-not-tested: for every (host, path) with multiple methods
	// in the inventory, flag any method whose key is unprobed. This
	// overlaps with SurfaceGapUnprobed for those methods; the
	// method-missing reason surfaces the semantic ("this endpoint
	// supports POST but only GET was tested") for operator triage.
	for _, group := range byHostPath {
		if len(group) < 2 {
			continue
		}
		methods := map[string]SurfaceEntry{}
		for _, e := range group {
			methods[e.Method] = e
		}
		if len(methods) < 2 {
			continue
		}
		ms := make([]string, 0, len(methods))
		for m := range methods {
			ms = append(ms, m)
		}
		sort.Strings(ms)
		for _, m := range ms {
			e := methods[m]
			if _, ok := globalProbedKeys.keys.Load(e.Key()); !ok {
				gaps = append(gaps, SurfaceGap{
					Reason:      SurfaceGapMethodNotTested,
					Entry:       e,
					MissingItem: m,
				})
				methodMissing++
			}
		}
	}
	globalProbedKeys.lastInventoryTotal.Store(uint64(len(entries)))
	globalProbedKeys.lastProbedUnique.Store(probedUnique)
	globalProbedKeys.lastUnprobed.Store(unprobed)
	globalProbedKeys.lastParamNotFuzzed.Store(paramMissing)
	globalProbedKeys.lastMethodNotTested.Store(methodMissing)
	globalProbedKeys.gapsMu.Lock()
	globalProbedKeys.lastGaps = cloneSurfaceGaps(gaps)
	globalProbedKeys.gapsMu.Unlock()
	return gaps
}

func cloneSurfaceGaps(in []SurfaceGap) []SurfaceGap {
	if len(in) == 0 {
		return nil
	}
	out := make([]SurfaceGap, len(in))
	copy(out, in)
	return out
}
