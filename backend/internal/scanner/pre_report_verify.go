package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proofpolicy"
)

// VerificationOutcome captures why a candidate finding was accepted,
// downgraded, or suppressed by the shared pre-report verifier. Probes
// receive it back from SubmitVerifiedFinding so they can log/emit agent
// events explaining what happened before the finding reached the aggregator.
type VerificationOutcome struct {
	// Verified is true when the candidate satisfied its proof obligation
	// and (if provided) the PoC replay confirmed the exploit is reproducible.
	Verified bool
	// Suppressed is true when the candidate did not meet the minimum bar
	// and should not be emitted at all.
	Suppressed bool
	// Downgraded is true when the finding was kept but its severity was
	// lowered because evidence is incomplete.
	Downgraded bool
	// Confidence is the calibrated confidence score in [0, 1] the verifier
	// assigned to the candidate before emission.
	Confidence float64
	// Reason is a short human-readable label ("poc-replay-failed",
	// "missing-proof-obligation", "confidence-below-threshold", ...)
	Reason string
	// Policy is the proof-policy evaluation result.
	Policy proofpolicy.Result
	// EvidenceHits records how many "min evidence" checklist entries were
	// satisfied by the candidate (status delta, body delta, timing, sink,
	// OAST hit, ...).
	EvidenceHits int
	// EvidenceRequired is the minimum evidence hits needed to accept.
	EvidenceRequired int
	// PoCReplayed is true if the verifier successfully executed the PoC.
	PoCReplayed bool
	// PoCSuccess is true if the PoC replay reproduced the exploit signal.
	PoCSuccess bool
	// PoCTranscript is a redacted request/response summary attached to the
	// finding when replay succeeds.
	PoCTranscript string
	// EmittedFinding is the (possibly modified) finding that was submitted
	// to the aggregator, or a zero value if Suppressed is true.
	EmittedFinding model.Finding
	// CorrectionHint is a short human-readable explanation provided by the
	// AI false-positive classifier when a finding is suppressed via
	// UseAIFPCorrection. Empty when the standard proof-policy path ran.
	CorrectionHint string
}

// EvidenceSignal enumerates the categories of evidence a probe may attach
// to a candidate finding. The verifier counts hits against a per-category
// minimum threshold ("N-of-M evidences") before accepting the finding.
type EvidenceSignal string

const (
	EvidenceStatusDelta  EvidenceSignal = "status_delta"  // response status differs from baseline
	EvidenceBodyDelta    EvidenceSignal = "body_delta"    // body differs beyond control variance
	EvidenceTimingDelta  EvidenceSignal = "timing_delta"  // response latency differs (blind SQLi, DoS)
	EvidenceSinkObserved EvidenceSignal = "sink_observed" // payload landed in a dangerous sink (attr, script)
	EvidenceOASTHit      EvidenceSignal = "oast_hit"      // out-of-band interaction was collected
	EvidenceReflection   EvidenceSignal = "reflection"    // per-request random marker echoed back
	EvidenceHeaderDelta  EvidenceSignal = "header_delta"  // response header differs from baseline
	EvidenceCookieChange EvidenceSignal = "cookie_change" // Set-Cookie changed post-probe
	EvidenceErrorSignal  EvidenceSignal = "error_signal"  // application error / stack trace surfaced
	EvidenceDOMExecution EvidenceSignal = "dom_execution" // headless browser confirmed sink execution
	EvidenceCrossSubject EvidenceSignal = "cross_subject" // second auth profile observed different data
	// EvidenceCodeChange is added automatically when the browser validation
	// pipeline detects that one or more JS bundles changed after the probe
	// was applied. It indicates the server processed the request differently
	// (delivered different code) rather than returning a static response.
	EvidenceCodeChange EvidenceSignal = "code_change"
)

// PoCReplayFunc is an optional hook a probe can supply to reproduce the
// finding end-to-end before it is emitted. Returning (true, transcript, nil)
// causes the verifier to attach the transcript to the finding evidence.
// Returning (false, _, nil) causes the candidate to be suppressed unless the
// proof obligation is otherwise fully met and confidence is above the
// override threshold.
//
// The returned transcript should be a compact human-readable summary of
// the reproduction (request line, status, timing, response snippet). It
// must not contain secrets.
type PoCReplayFunc func(ctx context.Context) (success bool, transcript string, err error)

// BrowserValidationFunc is an optional hook a probe can supply to drive a
// headless browser session that captures before/after DOM snapshots of the
// affected URL and derives a StateChangeDelta. The verifier automatically
// promotes EvidenceBodyDelta and EvidenceCodeChange signals from the delta
// and attaches screenshots as ProofArtifacts on the emitted finding.
type BrowserValidationFunc func(ctx context.Context) (*model.BrowserValidationResult, error)

// VerifyCandidate is the input to SubmitVerifiedFinding. Probes populate it
// with the candidate finding, the signals they observed, and (optionally) a
// PoC replay function that reproduces the exploit.
type VerifyCandidate struct {
	// Finding is the candidate — will be modified in place (Evidence,
	// EvidenceFields, Confidence, ProofArtifacts) before emission.
	Finding model.Finding
	// Signals is the list of EvidenceSignal hits observed by the probe.
	Signals []EvidenceSignal
	// PoCReplay, if non-nil, is executed by the verifier before emitting
	// the finding. A failed replay causes suppression unless proof-policy
	// coverage is 100% and the probe explicitly set AllowNoReplayEmission.
	PoCReplay PoCReplayFunc
	// BrowserValidation, if non-nil, is executed by the verifier to drive a
	// headless browser session that captures before/after DOM snapshots of
	// the finding's AffectedURL. The verifier automatically:
	//   - adds EvidenceBodyDelta when HTML or visible text changed;
	//   - adds EvidenceCodeChange when JS bundles changed;
	//   - records EvidenceFields["browserValidation.static"] = "true" when
	//     the page looks identical before and after the probe (no signals added).
	//   - attaches before/after screenshots and a state-delta JSON as
	//     ProofArtifacts so human reviewers can inspect the state change.
	BrowserValidation BrowserValidationFunc
	// AllowNoReplayEmission permits emission when PoCReplay is nil (or
	// unavailable due to network policy) as long as the proof obligation
	// is fully met. Probes should set this to true for categories that
	// cannot be safely replayed automatically (e.g. destructive actions).
	AllowNoReplayEmission bool
	// BaselineVariance is the observed control-to-control variance for
	// this candidate (see TwoControlBaseline). When >0, the verifier will
	// require the observed body/timing delta to exceed the control variance
	// by a safety margin before counting the delta as an evidence hit.
	BaselineVariance float64
	// ObservedDelta is the probed-vs-baseline delta the probe measured, in
	// the same units as BaselineVariance (bytes, ms, ...). Only used when
	// BaselineVariance > 0.
	ObservedDelta float64
	// ProbeName identifies the probe for metrics accounting.
	ProbeName string
}

// verificationCounters accumulates per-probe pre-report metrics. Exposed via
// GetVerificationMetrics for AutomationMetrics.
type verificationCounters struct {
	mu               sync.Mutex
	Total            int
	Verified         int
	Suppressed       int
	Downgraded       int
	PoCReplayed      int
	PoCSucceeded     int
	ByProbe          map[string]*probeCounter
	ByCategory       map[string]*probeCounter
	ConfidenceSum    float64
	ConfidenceSample int
	// ExploitValidated tracks how many findings shipped with a
	// PoC/VerificationTrace bundle (Wave 1 Phase A KPI).
	ExploitValidated          int
	ExploitValidationEligible int
}

type probeCounter struct {
	Total        int
	Verified     int
	Suppressed   int
	Downgraded   int
	PoCReplayed  int
	PoCSucceeded int
}

var globalVerificationCounters = &verificationCounters{
	ByProbe:    map[string]*probeCounter{},
	ByCategory: map[string]*probeCounter{},
}

func (c *verificationCounters) record(probe string, category string, o VerificationOutcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Total++
	pc, ok := c.ByProbe[probe]
	if !ok {
		pc = &probeCounter{}
		c.ByProbe[probe] = pc
	}
	pc.Total++
	category = strings.TrimSpace(category)
	if category == "" {
		category = "unknown"
	}
	cc, ok := c.ByCategory[category]
	if !ok {
		cc = &probeCounter{}
		c.ByCategory[category] = cc
	}
	cc.Total++
	if o.Verified {
		c.Verified++
		pc.Verified++
		cc.Verified++
	}
	if o.Suppressed {
		c.Suppressed++
		pc.Suppressed++
		cc.Suppressed++
	}
	if o.Downgraded {
		c.Downgraded++
		pc.Downgraded++
		cc.Downgraded++
	}
	if o.PoCReplayed {
		c.PoCReplayed++
		pc.PoCReplayed++
		cc.PoCReplayed++
		if o.PoCSuccess {
			c.PoCSucceeded++
			pc.PoCSucceeded++
			cc.PoCSucceeded++
		}
	}
	if o.Confidence > 0 {
		c.ConfidenceSum += o.Confidence
		c.ConfidenceSample++
	}
	// Exploit validation rate KPI (Wave 1 Phase A): track whether the emitted
	// finding carries a PoC/VerificationTrace bundle.
	sev := o.EmittedFinding.Severity
	if sev == model.SeverityHigh || sev == model.SeverityCritical {
		c.ExploitValidationEligible++
		if o.PoCSuccess || o.EmittedFinding.VerificationTrace != nil || o.EmittedFinding.SafePoCScript != "" {
			c.ExploitValidated++
		}
	}
}

// IncrementExploitValidated allows agents (e.g. exploit_chain) that generate
// SafePoCScript without going through SubmitVerifiedFinding to register their
// findings as exploit-validated for KPI tracking.
func IncrementExploitValidated(highOrCritical bool) {
	globalVerificationCounters.mu.Lock()
	defer globalVerificationCounters.mu.Unlock()
	if highOrCritical {
		globalVerificationCounters.ExploitValidationEligible++
		globalVerificationCounters.ExploitValidated++
	}
}

// PreReportMetrics is the aggregate view of the pre-report verifier's
// activity across the process. It is included in AutomationMetrics via the
// Extra map so that operators can watch FP-reduction efficacy in real time.
type PreReportMetrics struct {
	Total             int                          `json:"total"`
	Verified          int                          `json:"verified"`
	Suppressed        int                          `json:"suppressed"`
	Downgraded        int                          `json:"downgraded"`
	PoCReplayed       int                          `json:"pocReplayed"`
	PoCSucceeded      int                          `json:"pocSucceeded"`
	AverageConfidence float64                      `json:"averageConfidence"`
	VerifiedRate      float64                      `json:"verifiedRate"`
	SuppressedRate    float64                      `json:"suppressedRate"`
	PoCSuccessRate    float64                      `json:"pocSuccessRate"`
	// ExploitValidationRate is the fraction of high/critical findings that
	// include a machine-readable PoC or VerificationTrace bundle. This is
	// the Wave 1 Phase A "exploit validation rate" Core Product KPI. It is
	// equivalent to PoCSuccessRate when all findings pass through PoC replay;
	// agents that generate SafePoCScript without replay increment it via
	// IncrementExploitValidated.
	ExploitValidationRate float64 `json:"exploitValidationRate"`
	// ExploitValidated is the count of findings that shipped with a
	// machine-readable PoC/VerificationTrace bundle.
	ExploitValidated int `json:"exploitValidated"`
	// ExploitValidationEligible is the total high/critical findings that
	// passed through the verifier and are eligible to carry a PoC bundle.
	ExploitValidationEligible int                          `json:"exploitValidationEligible"`
	ByProbe                   map[string]PreReportProbeAgg `json:"byProbe,omitempty"`
	ByCategory                map[string]PreReportProbeAgg `json:"byCategory,omitempty"`
}

// PreReportProbeAgg summarises verification activity for one probe.
type PreReportProbeAgg struct {
	Total        int `json:"total"`
	Verified     int `json:"verified"`
	Suppressed   int `json:"suppressed"`
	Downgraded   int `json:"downgraded"`
	PoCReplayed  int `json:"pocReplayed"`
	PoCSucceeded int `json:"pocSucceeded"`
}

// GetVerificationMetrics returns a snapshot of the process-wide pre-report
// verification counters. Safe to call concurrently.
func GetVerificationMetrics() PreReportMetrics {
	return globalVerificationCounters.snapshot()
}

// ResetVerificationMetrics resets the process-wide counters. Intended for
// tests; not called from production code.
func ResetVerificationMetrics() {
	globalVerificationCounters.mu.Lock()
	defer globalVerificationCounters.mu.Unlock()
	globalVerificationCounters.Total = 0
	globalVerificationCounters.Verified = 0
	globalVerificationCounters.Suppressed = 0
	globalVerificationCounters.Downgraded = 0
	globalVerificationCounters.PoCReplayed = 0
	globalVerificationCounters.PoCSucceeded = 0
	globalVerificationCounters.ConfidenceSum = 0
	globalVerificationCounters.ConfidenceSample = 0
	globalVerificationCounters.ExploitValidated = 0
	globalVerificationCounters.ExploitValidationEligible = 0
	globalVerificationCounters.ByProbe = map[string]*probeCounter{}
	globalVerificationCounters.ByCategory = map[string]*probeCounter{}
}

func (c *verificationCounters) snapshot() PreReportMetrics {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := PreReportMetrics{
		Total:                     c.Total,
		Verified:                  c.Verified,
		Suppressed:                c.Suppressed,
		Downgraded:                c.Downgraded,
		PoCReplayed:               c.PoCReplayed,
		PoCSucceeded:              c.PoCSucceeded,
		ExploitValidated:          c.ExploitValidated,
		ExploitValidationEligible: c.ExploitValidationEligible,
		ByProbe:                   map[string]PreReportProbeAgg{},
		ByCategory:                map[string]PreReportProbeAgg{},
	}
	if c.ConfidenceSample > 0 {
		m.AverageConfidence = c.ConfidenceSum / float64(c.ConfidenceSample)
	}
	if c.Total > 0 {
		m.VerifiedRate = float64(c.Verified) / float64(c.Total)
		m.SuppressedRate = float64(c.Suppressed) / float64(c.Total)
	}
	if c.PoCReplayed > 0 {
		m.PoCSuccessRate = float64(c.PoCSucceeded) / float64(c.PoCReplayed)
	}
	if c.ExploitValidationEligible > 0 {
		m.ExploitValidationRate = float64(c.ExploitValidated) / float64(c.ExploitValidationEligible)
	}
	for name, pc := range c.ByProbe {
		m.ByProbe[name] = PreReportProbeAgg{
			Total:        pc.Total,
			Verified:     pc.Verified,
			Suppressed:   pc.Suppressed,
			Downgraded:   pc.Downgraded,
			PoCReplayed:  pc.PoCReplayed,
			PoCSucceeded: pc.PoCSucceeded,
		}
	}
	for name, pc := range c.ByCategory {
		m.ByCategory[name] = PreReportProbeAgg{
			Total:        pc.Total,
			Verified:     pc.Verified,
			Suppressed:   pc.Suppressed,
			Downgraded:   pc.Downgraded,
			PoCReplayed:  pc.PoCReplayed,
			PoCSucceeded: pc.PoCSucceeded,
		}
	}
	return m
}

// categoryEvidenceMinimum defines the minimum number of EvidenceSignals a
// candidate must satisfy for the verifier to accept the finding without a
// successful PoC replay. Categories with a hard proof-obligation (SQLi,
// SSRF, XXE, SSTI, NoSQLi) require 3 signals; medium classes 2; low 1.
var categoryEvidenceMinimum = map[string]int{
	"sqli":                3,
	"ssrf":                3,
	"xxe":                 3,
	"ssti":                3,
	"nosqli":              3,
	"xss":                 2,
	"idor":                2,
	"path_traversal":      2,
	"open_redirect":       2,
	"cors":                2,
	"csrf":                2,
	"clickjacking":        2,
	"authentication":      2,
	"prototype_pollution": 2,
	"headers":             1,
	"wordlist":            1,
}

// EvidenceMinimumForCategory returns the min-N-of-M evidence threshold for
// a category. Falls back to 1 for unknown categories.
func EvidenceMinimumForCategory(category string) int {
	c := canonicalCategoryLower(category)
	if n, ok := categoryEvidenceMinimum[c]; ok {
		return n
	}
	return 1
}

// SubmitVerifiedFinding is the entry point probes call in place of pushing
// a candidate finding directly into their return slice. It:
//
//  1. Checks the global ProbeOutcomeLedger: if the probe has been
//     auto-throttled due to exceeding the rolling FP threshold, the
//     candidate is immediately suppressed without running any probes.
//  2. Evaluates proof-policy coverage.
//  3. Counts evidence signals against the per-category minimum.
//  4. If a PoCReplay hook is supplied, executes it and attaches the
//     transcript to Finding.Evidence / EvidenceFields on success.
//  5. Suppresses candidates that fail both the proof obligation and
//     PoC replay; downgrades candidates that meet the proof obligation
//     but only partially satisfy the evidence checklist.
//  6. Records verification metrics for AutomationMetrics.
//
// The returned finding is a zero value when outcome.Suppressed is true.
// Probes should append the returned finding to their result slice only when
// outcome.Suppressed is false.
func SubmitVerifiedFinding(ctx context.Context, cand VerifyCandidate) VerificationOutcome {
	outcome := VerificationOutcome{}

	// 0) Auto-throttle gate (Wave 1 Phase B). Skip the probe entirely if the
	// ledger has throttled it due to a high rolling FP rate.
	probeKeyForLedger := cand.ProbeName
	if probeKeyForLedger == "" {
		probeKeyForLedger = canonicalCategoryLower(cand.Finding.Category)
	}
	if probeKeyForLedger != "" && globalProbeOutcomeLedger.IsThrottled(probeKeyForLedger) {
		globalProbeOutcomeLedger.RecordThrottleDecision(probeKeyForLedger)
		outcome.Suppressed = true
		outcome.Reason = "probe-auto-throttled"
		return outcome
	}

	// 1) Proof-policy evaluation.
	outcome.Policy = proofpolicy.EvaluateFinding(cand.Finding)

	// 2) Count evidence-signal hits with baseline-variance discipline.
	uniq := map[EvidenceSignal]struct{}{}
	for _, s := range cand.Signals {
		if s == "" {
			continue
		}
		// Body / timing deltas are only counted when they exceed the
		// baseline control-to-control variance by a 2x safety margin.
		if (s == EvidenceBodyDelta || s == EvidenceTimingDelta) && cand.BaselineVariance > 0 {
			if !ExceedsControlVariance(cand.ObservedDelta, cand.BaselineVariance) {
				continue
			}
		}
		uniq[s] = struct{}{}
	}
	outcome.EvidenceHits = len(uniq)
	outcome.EvidenceRequired = EvidenceMinimumForCategory(cand.Finding.Category)

	// 3) PoC replay.
	if cand.PoCReplay != nil {
		outcome.PoCReplayed = true
		success, transcript, err := cand.PoCReplay(ctx)
		if err == nil {
			outcome.PoCSuccess = success
		}
		outcome.PoCTranscript = transcript
		if success {
			attachPoCTranscript(&cand.Finding, transcript)
		}
	}

	// 4b) Optionally run browser validation to capture before/after DOM
	// snapshots and automatically promote evidence signals from the delta.
	if cand.BrowserValidation != nil {
		if bvResult, bvErr := cand.BrowserValidation(ctx); bvErr == nil && bvResult != nil {
			delta := bvResult.Delta
			if delta.HTMLChanged || delta.TextChanged {
				// DOM changed after the probe — count as body delta evidence.
				uniq[EvidenceBodyDelta] = struct{}{}
			}
			if delta.JSBundleChanged {
				// JS bundles changed — strong signal of server-side code execution.
				uniq[EvidenceCodeChange] = struct{}{}
			}
			// Re-tally hits after injecting browser-derived signals.
			outcome.EvidenceHits = len(uniq)
			// Attach before/after screenshots and state-delta as ProofArtifacts.
			attachBrowserValidationArtifacts(&cand.Finding, bvResult.Before, bvResult.After, delta)
		}
	}

	// 5) Compute final confidence (includes browser-validation code-change bonus).
	outcome.Confidence = computePreReportConfidence(outcome.Policy, outcome.EvidenceHits, outcome.EvidenceRequired, uniq)

	// 6) Verdict.
	fullyProved := outcome.Policy.Coverage >= outcome.Policy.MinCoverage && outcome.Policy.MinCoverage > 0
	evidenceEnough := outcome.EvidenceHits >= outcome.EvidenceRequired
	switch {
	case outcome.PoCReplayed && outcome.PoCSuccess:
		outcome.Verified = true
		outcome.Reason = "poc-replay-succeeded"
	case outcome.PoCReplayed && !outcome.PoCSuccess:
		outcome.Suppressed = true
		outcome.Reason = "poc-replay-failed"
	case cand.PoCReplay == nil && !cand.AllowNoReplayEmission && strictEmissionRequired(cand.Finding.Category):
		// Category demands PoC replay for confident emission; probe did
		// not supply one → suppress.
		outcome.Suppressed = true
		outcome.Reason = "poc-replay-required-not-supplied"
	case fullyProved && evidenceEnough:
		outcome.Verified = true
		outcome.Reason = "proof-and-evidence-met"
	case fullyProved && !evidenceEnough:
		outcome.Downgraded = true
		outcome.Reason = "insufficient-evidence-hits"
		cand.Finding.Severity = downgradeSeverity(cand.Finding.Severity)
	case !fullyProved && evidenceEnough:
		outcome.Downgraded = true
		outcome.Reason = "proof-obligation-partial"
		cand.Finding.Severity = downgradeSeverity(cand.Finding.Severity)
	default:
		outcome.Suppressed = true
		outcome.Reason = "insufficient-proof-and-evidence"
	}

	// 7) Confidence-threshold override: even a "verified" finding is
	// downgraded if calibrated confidence is very low.
	if outcome.Verified && outcome.Confidence < 0.35 {
		outcome.Verified = false
		outcome.Downgraded = true
		outcome.Reason = "confidence-below-threshold"
		cand.Finding.Severity = downgradeSeverity(cand.Finding.Severity)
	}

	// 8) Persist confidence + verification metadata on the finding for
	// downstream ML calibration and the strict-mode UI toggle.
	if outcome.Confidence > cand.Finding.Confidence {
		cand.Finding.Confidence = outcome.Confidence
	}
	if cand.Finding.EvidenceFields == nil {
		cand.Finding.EvidenceFields = map[string]string{}
	}
	cand.Finding.EvidenceFields["preReport.verified"] = fmt.Sprintf("%v", outcome.Verified)
	cand.Finding.EvidenceFields["preReport.reason"] = outcome.Reason
	cand.Finding.EvidenceFields["preReport.evidenceHits"] = fmt.Sprintf("%d/%d", outcome.EvidenceHits, outcome.EvidenceRequired)
	cand.Finding.EvidenceFields["preReport.policyCoverage"] = fmt.Sprintf("%.2f", outcome.Policy.Coverage)
	// Phase 3: mark the finding with a machine-readable oracle stamp so
	// evidence_normalizer.go can populate EvidenceRecord.VerifiedBy.
	// Findings without a verifier stamp are eligible for downgrade
	// under strict-mode reporting.
	oracle := cand.ProbeName
	if oracle == "" {
		oracle = "unknown"
	}
	cand.Finding.EvidenceFields["preReport.verifiedBy"] = fmt.Sprintf("%s@v1", oracle)
	cand.Finding.EvidenceFields["verifiedBy"] = fmt.Sprintf("%s@v1", oracle)
	if outcome.PoCReplayed {
		cand.Finding.EvidenceFields["preReport.pocReplayed"] = fmt.Sprintf("%v", outcome.PoCSuccess)
	}

	if !outcome.Suppressed {
		outcome.EmittedFinding = cand.Finding
	}

	// 9) AI-guided FP correction (when UseAIFPCorrection is enabled and a
	// ProbeCorrection is present in the request context). Always records the
	// outcome signal into the per-scan FP store; may additionally suppress
	// the finding when the rule-based estimator or AI classifier identifies
	// it as a false positive.
	probeName := cand.ProbeName
	if probeName == "" {
		probeName = "unknown"
	}
	if pc := probeCorrectionFromCtx(ctx); pc != nil {
		if corrected := pc.Evaluate(ctx, cand, probeName, &outcome); corrected {
			// Stamp the (now-suppressed) finding with correction metadata for
			// audit purposes. These fields appear only on the finding snapshot
			// stored inside ProbeCorrection; EmittedFinding is already zeroed.
			cand.Finding.EvidenceFields["fpCorrection.reason"] = outcome.Reason
			cand.Finding.EvidenceFields["fpCorrection.hint"] = outcome.CorrectionHint
		}
	}

	// 10) Metrics.
	globalVerificationCounters.record(probeName, canonicalCategoryLower(cand.Finding.Category), outcome)

	return outcome
}

// strictEmissionRequired returns true when a category should never be
// emitted without a successful PoC replay (destructive or blind classes
// where a positive signal without OAST/PoC confirmation is too noisy).
func strictEmissionRequired(category string) bool {
	switch canonicalCategoryLower(category) {
	case "ssrf", "xxe", "ssti", "sqli", "nosqli":
		return true
	}
	return false
}

// computePreReportConfidence produces a bounded [0, 1] pre-emission
// confidence score derived from proof-policy coverage and the number of
// evidence-signal hits. The optional signals set allows the function to
// apply a +0.05 bonus when EvidenceCodeChange is present — JS bundle drift
// after a probe is a strong signal that the server processed the request
// differently rather than returning a static cached response.
func computePreReportConfidence(policy proofpolicy.Result, hits, required int, signals map[EvidenceSignal]struct{}) float64 {
	base := 0.4 // baseline for any candidate that makes it this far
	if policy.MinCoverage > 0 {
		// Coverage contributes up to 0.4.
		base += 0.4 * math.Min(1.0, policy.Coverage/policy.MinCoverage)
	}
	if required > 0 {
		// Evidence contributes up to 0.2.
		base += 0.2 * math.Min(1.0, float64(hits)/float64(required))
	}
	// Code-change bonus: +0.05 when JS bundles changed after the probe,
	// confirming the server actually executed different code paths.
	if _, ok := signals[EvidenceCodeChange]; ok {
		base += 0.05
	}
	if base > 1.0 {
		base = 1.0
	}
	if base < 0 {
		base = 0
	}
	return base
}

// downgradeSeverity lowers the severity of a candidate finding by one
// notch. Critical→High→Medium→Low→Info.
func downgradeSeverity(s model.Severity) model.Severity {
	switch strings.ToLower(string(s)) {
	case "critical":
		return model.SeverityHigh
	case "high":
		return model.SeverityMedium
	case "medium":
		return model.SeverityLow
	case "low":
		return model.SeverityInfo
	default:
		return s
	}
}

// attachPoCTranscript records a redacted PoC replay transcript on the
// finding's evidence so the UI can show operators exactly why the tool
// believes the bug is real. It also populates Finding.VerificationTrace with
// a structured proof bundle so callers can access the transcript in a
// machine-readable form.
func attachPoCTranscript(f *model.Finding, transcript string) {
	if transcript == "" {
		return
	}
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["preReport.pocTranscript"] = transcript
	if !strings.Contains(f.Evidence, "PoC replay:") {
		if f.Evidence != "" {
			f.Evidence += "\n\n"
		}
		f.Evidence += "PoC replay: " + transcript
	}
	f.ProofArtifacts = append(f.ProofArtifacts, model.ProofArtifact{
		Type:        "poc-transcript",
		Label:       "Pre-report PoC replay",
		Description: "Verifier reproduced the candidate exploit before emission.",
		Value:       transcript,
	})
	// Populate the structured VerificationTrace if not already set.
	if f.VerificationTrace == nil {
		f.VerificationTrace = buildVerificationTraceFromTranscript(transcript)
	}
}

// buildVerificationTraceFromTranscript creates a VerificationTrace from a
// plain-text transcript string produced by a PoCReplayFunc. The transcript
// is stored verbatim as the ResponseSnippet so the structured bundle is
// always populated even when the full HTTP details are not individually
// provided by the probe.
func buildVerificationTraceFromTranscript(transcript string) *model.VerificationTrace {
	if transcript == "" {
		return nil
	}
	// Extract the first line as the request line when the transcript starts
	// with an HTTP method token, otherwise store the whole transcript as the
	// response snippet.
	vt := &model.VerificationTrace{
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
	}
	lines := strings.SplitN(transcript, "\n", 2)
	first := strings.TrimSpace(lines[0])
	httpMethods := []string{"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS "}
	startsWithMethod := false
	for _, m := range httpMethods {
		if strings.HasPrefix(first, m) {
			startsWithMethod = true
			break
		}
	}
	if startsWithMethod {
		vt.RequestLine = first
		if len(lines) > 1 {
			vt.ResponseSnippet = truncate(strings.TrimSpace(lines[1]), 2048)
		}
	} else {
		vt.ResponseSnippet = truncate(transcript, 2048)
	}
	return vt
}

// truncate returns s truncated to at most n bytes with an ellipsis appended
// when truncation occurs.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// canonicalCategoryLower normalises a category label for lookup in the
// evidence-minimum / strict-emission tables. Kept in sync with proofpolicy.
func canonicalCategoryLower(category string) string {
	c := strings.TrimSpace(strings.ToLower(category))
	c = strings.ReplaceAll(c, " ", "_")
	c = strings.ReplaceAll(c, "-", "_")
	switch c {
	case "sql_injection":
		return "sqli"
	case "dom_xss", "reflected_xss", "stored_xss":
		return "xss"
	case "server_side_request_forgery":
		return "ssrf"
	case "xml_external_entity":
		return "xxe"
	case "server_side_template_injection", "template_injection":
		return "ssti"
	case "nosql_injection":
		return "nosqli"
	case "directory_traversal", "lfi":
		return "path_traversal"
	case "unvalidated_redirect", "redirect":
		return "open_redirect"
	case "cors_misconfiguration":
		return "cors"
	case "cross_site_request_forgery":
		return "csrf"
	case "ui_redress", "ui_redressing":
		return "clickjacking"
	case "prototype_pollution", "prototype-pollution", "prototypepollution":
		return "prototype_pollution"
	case "security_headers":
		return "headers"
	case "wordlist_discovery", "content_discovery":
		return "wordlist"
	case "broken_access_control", "access_control", "bola":
		return "idor"
	case "authentication", "auth", "oauth", "oidc", "session_auth":
		return "authentication"
	}
	return c
}

// -----------------------------------------------------------------------------
// TwoControlBaseline — fetch two identical baselines and expose the
// control-to-control variance so a probe can distinguish natural response
// jitter from a probe-induced delta.
// -----------------------------------------------------------------------------

// BaselineSample captures a single control fetch used by TwoControlBaseline.
type BaselineSample struct {
	Status   int
	Header   http.Header
	Body     string
	Duration time.Duration
}

// BaselineControls holds two identical baseline captures and the derived
// variance between them. Probes call ExceedsControlVariance(observed) to
// decide whether a probe-induced delta is real.
type BaselineControls struct {
	First  BaselineSample
	Second BaselineSample
	// BodyByteVariance is |len(Body1)-len(Body2)| after NormalizeResponseBody.
	BodyByteVariance int
	// TimingVarianceMs is the |ms1 - ms2| latency variance.
	TimingVarianceMs float64
	// StatusStable is true when both baselines had the same status code.
	StatusStable bool
}

// BaselineFetcher performs a single control request. Returns a snapshot for
// TwoControlBaseline to compare against a probed response.
type BaselineFetcher func(ctx context.Context) (BaselineSample, error)

// CaptureTwoControlBaselines calls the supplied fetcher twice, back-to-back,
// to establish a natural-variance envelope. Both responses are normalised
// with NormalizeResponseBody before variance is computed so that
// per-request tokens do not inflate the envelope.
//
// A ctx cancellation short-circuits the second fetch; in that case a
// zero-value Second is returned and StatusStable is false.
func CaptureTwoControlBaselines(ctx context.Context, fetch BaselineFetcher) (BaselineControls, error) {
	if fetch == nil {
		return BaselineControls{}, fmt.Errorf("nil fetcher")
	}
	first, err := fetch(ctx)
	if err != nil {
		return BaselineControls{}, fmt.Errorf("first baseline: %w", err)
	}
	if ctx.Err() != nil {
		return BaselineControls{First: first}, ctx.Err()
	}
	second, err := fetch(ctx)
	if err != nil {
		return BaselineControls{First: first}, fmt.Errorf("second baseline: %w", err)
	}
	first.Body = NormalizeResponseBody(first.Body)
	second.Body = NormalizeResponseBody(second.Body)
	bc := BaselineControls{
		First:            first,
		Second:           second,
		BodyByteVariance: absInt(len(first.Body) - len(second.Body)),
		TimingVarianceMs: math.Abs(float64(first.Duration.Milliseconds() - second.Duration.Milliseconds())),
		StatusStable:     first.Status == second.Status,
	}
	return bc, nil
}

// ExceedsControlVariance reports whether an observed probed-vs-baseline
// delta is large enough to exceed natural jitter measured between two
// identical control baselines. Applies a 2x safety margin and a small
// absolute floor so tiny fluctuations never register as evidence.
func ExceedsControlVariance(observedDelta, controlVariance float64) bool {
	if observedDelta <= 0 {
		return false
	}
	const floor = 8.0
	const safetyMargin = 2.0
	threshold := math.Max(floor, safetyMargin*controlVariance)
	return observedDelta > threshold
}

// -----------------------------------------------------------------------------
// RandomMarker — helper for reflection-based probes that need a per-request
// nonce guaranteed not to occur in the baseline.
// -----------------------------------------------------------------------------

// RandomMarker returns a random hex string prefixed with "abh_" that a
// probe can inject into a request and search for in the response. The
// prefix makes it easy to grep and safe to use in HTML attribute contexts.
func RandomMarker() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("abh_%d", time.Now().UnixNano())
	}
	return "abh_" + hex.EncodeToString(b)
}
