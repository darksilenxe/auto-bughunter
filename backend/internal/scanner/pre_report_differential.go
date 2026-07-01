package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"auto-bughunter/backend/internal/model"
)

// pre_report_differential adds the "second-opinion" layer of Phase 1's
// FP-reduction plan. Every High/Critical candidate must be re-tested
// twice before it is allowed to emit:
//
//  1. Payload-stripped control — the exact request with the payload
//     replaced by the parameter's original safe value. The exploit
//     signal must NOT reproduce.
//
//  2. Benign-randomized control — the exact request with the payload
//     replaced by a random alphanumeric marker of the same length and
//     shape. The exploit signal must NOT reproduce.
//
// If either control reproduces the signal, the candidate is treated
// as a false-positive artefact of the target's own baseline behaviour
// and suppressed.
//
// This module is deliberately transport-agnostic: callers supply the
// probe-specific "did the signal appear?" oracle as a closure so any
// probe (SQLi timing, XSS reflection, SSRF OAST, ...) can reuse the
// same differential harness.

// DifferentialOracle inspects a request/response and returns true when
// the exploit signal is present. Probes provide their own oracle;
// e.g. for reflection XSS it checks that the payload's break-out is
// still in the body in an executable context.
type DifferentialOracle func(ctx context.Context, probeVariant string, resp *http.Response, body []byte) (signalPresent bool, err error)

// DifferentialRequestExec issues a probe request with the supplied
// substituted-payload value and returns the response so the oracle
// can inspect it. Probes provide a closure that rebuilds the request
// with `payload` in the tested parameter and executes it.
type DifferentialRequestExec func(ctx context.Context, payload string) (*http.Response, []byte, error)

// DifferentialReVerifyInput configures a single differential
// re-verification pass.
type DifferentialReVerifyInput struct {
	// ProbeName identifies the probe for metrics accounting.
	ProbeName string
	// OriginalPayload is the exploit payload the probe fired.
	OriginalPayload string
	// SafePayload is the parameter's original (pre-injection) value.
	// When empty, the payload-stripped control uses an empty string.
	SafePayload string
	// Exec issues a probe variant with the supplied payload. Called
	// twice: once with SafePayload, once with a random benign marker.
	Exec DifferentialRequestExec
	// Oracle inspects each control response and reports whether the
	// exploit signal reproduced.
	Oracle DifferentialOracle
}

// DifferentialReVerifyOutcome is the result of a differential
// re-verification. Confirmed is true only when BOTH controls returned
// "signal absent" — the exploit is specific to the original payload.
type DifferentialReVerifyOutcome struct {
	// Confirmed is true when the exploit is specific to the payload
	// (both controls returned signal absent, no errors).
	Confirmed bool
	// Ran is true when at least one control executed. When Ran is
	// false the caller should treat the candidate as not-differentially
	// -verified (fall through to normal proof-policy handling).
	Ran bool
	// PayloadStrippedSignal is true when the payload-stripped control
	// reproduced the signal — a strong FP indicator.
	PayloadStrippedSignal bool
	// BenignRandomSignal is true when the benign random control
	// reproduced the signal — a strong FP indicator (target echoes
	// arbitrary input into the same sink).
	BenignRandomSignal bool
	// Reason is a short label for the decision:
	//   "confirmed" / "signal-in-stripped-control" /
	//   "signal-in-benign-control" / "exec-error"
	Reason string
}

var (
	differentialTotal       atomic.Uint64
	differentialConfirmed   atomic.Uint64
	differentialFPStripped  atomic.Uint64
	differentialFPBenign    atomic.Uint64
	differentialExecErrors  atomic.Uint64
)

// DifferentialMetrics is a snapshot of the process-wide differential
// re-verification counters exposed via AutomationMetrics.Extra.
type DifferentialMetrics struct {
	Total          uint64  `json:"total"`
	Confirmed      uint64  `json:"confirmed"`
	FPStripped     uint64  `json:"fpStripped"`
	FPBenign       uint64  `json:"fpBenign"`
	ExecErrors     uint64  `json:"execErrors"`
	ConfirmedRate  float64 `json:"confirmedRate"`
}

// GetDifferentialMetrics returns a snapshot of the process-wide
// differential re-verification metrics.
func GetDifferentialMetrics() DifferentialMetrics {
	total := differentialTotal.Load()
	confirmed := differentialConfirmed.Load()
	var rate float64
	if total > 0 {
		rate = float64(confirmed) / float64(total)
	}
	return DifferentialMetrics{
		Total:         total,
		Confirmed:     confirmed,
		FPStripped:    differentialFPStripped.Load(),
		FPBenign:      differentialFPBenign.Load(),
		ExecErrors:    differentialExecErrors.Load(),
		ConfirmedRate: rate,
	}
}

// ResetDifferentialMetrics resets the counters. Intended for tests.
func ResetDifferentialMetrics() {
	differentialTotal.Store(0)
	differentialConfirmed.Store(0)
	differentialFPStripped.Store(0)
	differentialFPBenign.Store(0)
	differentialExecErrors.Store(0)
}

// randomBenignMarker generates a random alphanumeric string of the
// requested length. Falls back to a fixed placeholder when the OS
// random source is unavailable (extremely rare).
func randomBenignMarker(minLen int) string {
	length := minLen
	if length < 8 {
		length = 8
	}
	if length > 32 {
		length = 32
	}
	buf := make([]byte, length/2+1)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("q", length)
	}
	return hex.EncodeToString(buf)[:length]
}

// DifferentialReVerify runs the two-control differential test. When
// Confirmed is true the caller may proceed with the finding; when
// Confirmed is false and Ran is true the caller MUST suppress the
// finding as a false positive. When Ran is false the caller falls
// through to normal proof-policy handling.
func DifferentialReVerify(ctx context.Context, in DifferentialReVerifyInput) DifferentialReVerifyOutcome {
	out := DifferentialReVerifyOutcome{}
	if in.Exec == nil || in.Oracle == nil {
		return out
	}
	if ctx == nil {
		ctx = context.Background()
	}
	differentialTotal.Add(1)
	out.Ran = true

	// Control 1: payload stripped (parameter's safe original value).
	resp1, body1, err := in.Exec(ctx, in.SafePayload)
	if err != nil {
		differentialExecErrors.Add(1)
		out.Reason = "exec-error"
		return out
	}
	if resp1 != nil && resp1.Body != nil {
		defer resp1.Body.Close()
	}
	signal1, err := in.Oracle(ctx, "payload-stripped", resp1, body1)
	if err != nil {
		differentialExecErrors.Add(1)
		out.Reason = "exec-error"
		return out
	}
	if signal1 {
		out.PayloadStrippedSignal = true
		differentialFPStripped.Add(1)
		out.Reason = "signal-in-stripped-control"
		return out
	}

	// Control 2: benign random marker of comparable length.
	benign := randomBenignMarker(len(in.OriginalPayload))
	resp2, body2, err := in.Exec(ctx, benign)
	if err != nil {
		differentialExecErrors.Add(1)
		out.Reason = "exec-error"
		return out
	}
	if resp2 != nil && resp2.Body != nil {
		defer resp2.Body.Close()
	}
	signal2, err := in.Oracle(ctx, "benign-random", resp2, body2)
	if err != nil {
		differentialExecErrors.Add(1)
		out.Reason = "exec-error"
		return out
	}
	if signal2 {
		out.BenignRandomSignal = true
		differentialFPBenign.Add(1)
		out.Reason = "signal-in-benign-control"
		return out
	}

	out.Confirmed = true
	differentialConfirmed.Add(1)
	out.Reason = "confirmed"
	return out
}

// RequiresUnconditionalVerification returns true when a candidate's
// severity is High or Critical — those categories must be routed
// through the pre-report verifier and (when the probe is capable)
// through DifferentialReVerify before emission. Callers use this as
// a policy gate:
//
//	if RequiresUnconditionalVerification(f.Severity) { ... }
//
// The helper exists so probes stop reasoning about which categories
// need verification and instead all pay the same tax on High+.
func RequiresUnconditionalVerification(sev model.Severity) bool {
	switch sev {
	case model.SeverityHigh, model.SeverityCritical:
		return true
	}
	return false
}

// AttachDifferentialEvidence records the differential outcome on the
// finding's EvidenceFields so operators can see why the verifier
// accepted or suppressed the candidate. Safe to call with a zero
// outcome (no-op when Ran is false).
func AttachDifferentialEvidence(f *model.Finding, out DifferentialReVerifyOutcome) {
	if f == nil || !out.Ran {
		return
	}
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["differentialReVerify"] = out.Reason
	f.EvidenceFields["differentialConfirmed"] = fmt.Sprintf("%t", out.Confirmed)
	if out.PayloadStrippedSignal {
		f.EvidenceFields["differentialPayloadStrippedSignal"] = "true"
	}
	if out.BenignRandomSignal {
		f.EvidenceFields["differentialBenignRandomSignal"] = "true"
	}
}
