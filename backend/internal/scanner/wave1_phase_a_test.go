package scanner

import (
	"context"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestBuildVerificationTraceFromTranscript_WithHTTPMethod verifies that a
// transcript starting with an HTTP method is parsed into RequestLine.
func TestBuildVerificationTraceFromTranscript_WithHTTPMethod(t *testing.T) {
	t.Parallel()
	transcript := "POST https://example.com/login\n{\"user\":\"admin\",\"pass\":\"test\"}"
	vt := buildVerificationTraceFromTranscript(transcript)
	if vt == nil {
		t.Fatal("expected non-nil VerificationTrace")
	}
	if vt.RequestLine != "POST https://example.com/login" {
		t.Fatalf("unexpected RequestLine: %q", vt.RequestLine)
	}
	if !strings.Contains(vt.ResponseSnippet, "admin") {
		t.Fatalf("unexpected ResponseSnippet: %q", vt.ResponseSnippet)
	}
	if vt.CapturedAt == "" {
		t.Fatal("expected CapturedAt to be set")
	}
}

// TestBuildVerificationTraceFromTranscript_PlainText verifies that a plain-text
// transcript is stored as the ResponseSnippet.
func TestBuildVerificationTraceFromTranscript_PlainText(t *testing.T) {
	t.Parallel()
	transcript := "reflected payload found in response: <script>alert(1)</script>"
	vt := buildVerificationTraceFromTranscript(transcript)
	if vt == nil {
		t.Fatal("expected non-nil VerificationTrace")
	}
	if vt.RequestLine != "" {
		t.Fatalf("expected empty RequestLine for plain-text transcript, got %q", vt.RequestLine)
	}
	if !strings.Contains(vt.ResponseSnippet, "reflected payload") {
		t.Fatalf("unexpected ResponseSnippet: %q", vt.ResponseSnippet)
	}
}

// TestBuildVerificationTraceFromTranscript_Empty verifies that an empty
// transcript returns nil.
func TestBuildVerificationTraceFromTranscript_Empty(t *testing.T) {
	t.Parallel()
	if got := buildVerificationTraceFromTranscript(""); got != nil {
		t.Fatalf("expected nil for empty transcript, got %+v", got)
	}
}

// TestBuildVerificationTraceFromTranscript_Truncation verifies that transcripts
// longer than 2 KB are truncated.
func TestBuildVerificationTraceFromTranscript_Truncation(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 4096)
	vt := buildVerificationTraceFromTranscript(long)
	if vt == nil {
		t.Fatal("expected non-nil VerificationTrace")
	}
	if len(vt.ResponseSnippet) > 2100 {
		t.Fatalf("expected ResponseSnippet to be truncated, got length %d", len(vt.ResponseSnippet))
	}
	if !strings.HasSuffix(vt.ResponseSnippet, "…") {
		t.Fatal("expected truncated snippet to end with ellipsis")
	}
}

// TestAttachPoCTranscript_PopulatesVerificationTrace verifies that a successful
// PoC replay populates Finding.VerificationTrace via attachPoCTranscript.
func TestAttachPoCTranscript_PopulatesVerificationTrace(t *testing.T) {
	t.Parallel()
	f := model.Finding{ID: "f1", Category: "xss"}
	attachPoCTranscript(&f, "GET https://example.com/x?q=<script>alert(1)</script>\nHTTP/1.1 200 OK")
	if f.VerificationTrace == nil {
		t.Fatal("expected VerificationTrace to be populated")
	}
	if f.VerificationTrace.RequestLine == "" {
		t.Fatal("expected RequestLine to be set")
	}
}

// TestAttachPoCTranscript_DoesNotOverwriteExisting verifies that an existing
// VerificationTrace is not overwritten by attachPoCTranscript.
func TestAttachPoCTranscript_DoesNotOverwriteExisting(t *testing.T) {
	t.Parallel()
	existing := &model.VerificationTrace{RequestLine: "PUT https://existing.com"}
	f := model.Finding{ID: "f2", VerificationTrace: existing}
	attachPoCTranscript(&f, "GET https://new.com\nResponse body")
	if f.VerificationTrace.RequestLine != "PUT https://existing.com" {
		t.Fatalf("expected existing VerificationTrace to be preserved, got %+v", f.VerificationTrace)
	}
}

// TestSubmitVerifiedFinding_ThrottledProbeIsSuppressed verifies that the
// auto-throttle gate immediately suppresses candidates from throttled probes.
func TestSubmitVerifiedFinding_ThrottledProbeIsSuppressed(t *testing.T) {
	t.Parallel()
	// Reset global ledger to a fresh state for this test.
	old := globalProbeOutcomeLedger
	defer func() { globalProbeOutcomeLedger = old }()

	ledger := NewProbeOutcomeLedger()
	ledger.ThrottleMinSamples = 2
	ledger.ThrottleFPThreshold = 0.30
	ledger.ThrottleWindowSize = 10
	globalProbeOutcomeLedger = ledger

	// Trigger throttle.
	ledger.RecordOutcome("noisy_probe", OutcomeFP)
	ledger.RecordOutcome("noisy_probe", OutcomeFP)

	if !ledger.IsThrottled("noisy_probe") {
		t.Fatal("probe should be throttled after 2 FPs with minSamples=2")
	}

	outcome := SubmitVerifiedFinding(context.Background(), VerifyCandidate{
		ProbeName: "noisy_probe",
		Finding: model.Finding{
			ID:       "f1",
			Category: "xss",
			Severity: model.SeverityMedium,
			Evidence: "reflected",
			AffectedURL: "https://example.com",
		},
		Signals: []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved},
	})
	if !outcome.Suppressed {
		t.Fatal("expected throttled probe finding to be suppressed")
	}
	if outcome.Reason != "probe-auto-throttled" {
		t.Fatalf("expected reason 'probe-auto-throttled', got %q", outcome.Reason)
	}
}
