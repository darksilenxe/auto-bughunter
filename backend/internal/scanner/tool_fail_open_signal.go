package scanner

import (
	"fmt"
	"strings"
	"time"
)

// This file guards against a specific "fail-open" failure mode common to any
// scanner that shells out to (or calls an HTTP sidecar for) an external tool:
// when the TARGET rate-limits, blocks, or otherwise refuses the tool partway
// through a run, the tool frequently still exits 0 with zero findings. That
// reads identically to a genuinely clean scan, so an operator has no way to
// tell "nothing was there" apart from "the target never actually answered".
//
// The pattern below is adapted from ars0n-framework-v2's
// server/utils/vectorThrottleDetect.go and server/utils/discoveryScanGuards.go
// (https://github.com/R-s0n/ars0n-framework-v2), which reads a wrapped tool's
// own stdout/stderr for an HTTP 429, and separately distinguishes a legitimate
// empty result from a tool that produced no output at all in implausibly
// little time. Reused here for our own sidecar/exec-mode tool integrations
// (nuclei, ZAP baseline, kiterunner) rather than a separate ad hoc copy per
// integration, with more integrations expected to adopt it over time.

// refusalKeywords are phrasings that mean a target actively refused or
// challenged a request, rather than the tool simply finding nothing to
// report. Kept narrow and specific to minimise false positives on output that
// merely mentions rate limiting as a scanned-for condition.
var refusalKeywords = []string{
	"too many requests",
	"rate limit",
	"rate-limit",
	"ratelimit",
	"retry-after",
	"retry after",
	"quota exceeded",
	"checking your browser",
	"attention required",
	"please wait while we verify",
}

// hasStatus429 reports whether s contains "429" as a standalone number rather
// than as part of a longer number or the fractional-seconds portion of an
// RFC3339 timestamp (e.g. "...431.723429961+00:00"). A digit immediately
// before or after disqualifies a match, and so does a preceding decimal
// point.
func hasStatus429(s string) bool {
	for i := 0; i+3 <= len(s); i++ {
		if s[i:i+3] != "429" {
			continue
		}
		if i > 0 && (isASCIIDigit(s[i-1]) || s[i-1] == '.') {
			continue
		}
		if i+3 < len(s) && isASCIIDigit(s[i+3]) {
			continue
		}
		return true
	}
	return false
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// detectTargetRefusalSignal inspects a completed tool's own stdout+stderr for
// evidence that the target refused or challenged it. A non-empty return is a
// human-readable reason a caller can attach as evidence; an empty return
// means nothing in the output suggests a refusal.
func detectTargetRefusalSignal(output string) string {
	if strings.TrimSpace(output) == "" {
		return ""
	}
	if hasStatus429(output) {
		return "the tool's output contains an HTTP 429 (Too Many Requests) response from the target"
	}
	lower := strings.ToLower(output)
	for _, kw := range refusalKeywords {
		if strings.Contains(lower, kw) {
			return fmt.Sprintf("the tool's output indicates the target rate-limited or challenged it (matched %q)", kw)
		}
	}
	return ""
}

// toolFailOpenSignal reports, for a tool run that reported zero findings,
// whether that "clean" result should instead be treated as unverified
// because the target refused the tool rather than the tool finding nothing.
//
// Two independent signals are checked:
//  1. detectTargetRefusalSignal against the combined stdout/stderr (an
//     explicit 429 or rate-limit/challenge wording).
//  2. A "totally silent" run: zero bytes on both stdout and stderr, finished
//     in less than minRuntime. A tool that never printed anything at all and
//     returned almost instantly did not get far enough to have an honest
//     answer about the target; minRuntime should be set to the shortest
//     plausible duration for a real network round trip against the target
//     (network dial, TLS handshake, at least one HTTP exchange).
//
// minRuntime <= 0 disables the silence check (some call sites cannot cheaply
// measure elapsed wall-clock time and should rely on signal 1 alone).
func toolFailOpenSignal(stdout, stderr string, elapsed, minRuntime time.Duration) string {
	if sig := detectTargetRefusalSignal(stdout + "\n" + stderr); sig != "" {
		return sig
	}
	if minRuntime > 0 && elapsed < minRuntime &&
		strings.TrimSpace(stdout) == "" && strings.TrimSpace(stderr) == "" {
		return fmt.Sprintf(
			"the tool produced no output at all and finished in %s, under the %s expected for an honest network round trip against the target",
			elapsed.Round(time.Millisecond), minRuntime)
	}
	return ""
}
