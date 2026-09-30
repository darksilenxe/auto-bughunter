package scanner

import (
	"strings"
	"testing"
	"time"
)

func TestHasStatus429IgnoresTimestampFraction(t *testing.T) {
	// Regression case adapted from ars0n-framework-v2's stored-trace corpus:
	// "429" appearing inside the nanosecond fraction of an RFC3339 timestamp
	// must not be read as an HTTP status code.
	line := "2026-09-07T00:44:31.723429961+00:00 request completed"
	if hasStatus429(line) {
		t.Fatalf("hasStatus429(%q) = true, want false (429 is part of a timestamp fraction)", line)
	}
}

func TestHasStatus429MatchesStandaloneCode(t *testing.T) {
	for _, line := range []string{
		"HTTP/1.1 429 Too Many Requests",
		"status=429",
		"got a 429 from the server",
		"| 429           |     479 |",
	} {
		if !hasStatus429(line) {
			t.Errorf("hasStatus429(%q) = false, want true", line)
		}
	}
}

func TestHasStatus429RejectsLongerNumbers(t *testing.T) {
	for _, line := range []string{
		"14295 bytes written",
		"request id 4429001",
		"version 1.4290",
	} {
		if hasStatus429(line) {
			t.Errorf("hasStatus429(%q) = true, want false (429 is part of a longer number)", line)
		}
	}
}

func TestDetectTargetRefusalSignalOnBareStatus(t *testing.T) {
	sig := detectTargetRefusalSignal("scanning...\nHTTP 429 received\ndone")
	if sig == "" {
		t.Fatal("expected a refusal signal for output containing a bare HTTP 429")
	}
}

func TestDetectTargetRefusalSignalOnWording(t *testing.T) {
	for _, output := range []string{
		"warning: rate limit exceeded, backing off",
		"Retry-After: 30",
		"quota exceeded for this API key",
		"Checking your browser before accessing example.com",
	} {
		if detectTargetRefusalSignal(output) == "" {
			t.Errorf("expected a refusal signal for output %q", output)
		}
	}
}

func TestDetectTargetRefusalSignalOnCleanOutput(t *testing.T) {
	clean := "scanning https://example.com\nfound 0 issues\ndone in 4.2s"
	if sig := detectTargetRefusalSignal(clean); sig != "" {
		t.Fatalf("expected no refusal signal for clean output, got %q", sig)
	}
}

func TestDetectTargetRefusalSignalOnEmptyOutput(t *testing.T) {
	if sig := detectTargetRefusalSignal(""); sig != "" {
		t.Fatalf("expected no refusal signal for empty output, got %q", sig)
	}
}

func TestToolFailOpenSignalDetectsWording(t *testing.T) {
	sig := toolFailOpenSignal("", "429 Too Many Requests", 5*time.Second, 2*time.Second)
	if sig == "" {
		t.Fatal("expected a fail-open signal when stderr reports a 429")
	}
	if !strings.Contains(sig, "429") {
		t.Fatalf("expected the signal to mention the 429, got %q", sig)
	}
}

func TestToolFailOpenSignalDetectsTotalSilence(t *testing.T) {
	// A tool that printed nothing at all and returned almost instantly never
	// got far enough to have an honest answer about the target.
	sig := toolFailOpenSignal("", "", 50*time.Millisecond, 2*time.Second)
	if sig == "" {
		t.Fatal("expected a fail-open signal for a totally silent, implausibly fast run")
	}
}

func TestToolFailOpenSignalTrustsASlowSilentRun(t *testing.T) {
	// No archive/API history to report is a legitimate empty result as long
	// as the tool spent a plausible amount of time actually trying.
	sig := toolFailOpenSignal("", "", 30*time.Second, 2*time.Second)
	if sig != "" {
		t.Fatalf("expected no fail-open signal for a slow, genuinely empty run, got %q", sig)
	}
}

func TestToolFailOpenSignalTrustsACleanFastRunWithOutput(t *testing.T) {
	// Speed alone is never the complaint: a fast run that printed normal
	// output (even if it reports zero findings) is a legitimate result.
	sig := toolFailOpenSignal("scanned 3 endpoints, 0 issues found\n", "", 50*time.Millisecond, 2*time.Second)
	if sig != "" {
		t.Fatalf("expected no fail-open signal for a fast run with normal output, got %q", sig)
	}
}

func TestToolFailOpenSignalDisablesSilenceCheckWhenFloorIsZero(t *testing.T) {
	// Call sites that cannot cheaply measure elapsed time pass minRuntime<=0
	// to rely on the wording/429 signal alone.
	sig := toolFailOpenSignal("", "", 1*time.Millisecond, 0)
	if sig != "" {
		t.Fatalf("expected the silence check to be disabled when minRuntime<=0, got %q", sig)
	}
}
