package scanner

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proofpolicy"
)

// stubClassifier is a test implementation of FPClassifierClient.
type stubClassifier struct {
	isFP       bool
	confidence float64
	hint       string
	called     int
}

func (s *stubClassifier) ClassifyFalsePositive(_ context.Context, _ model.FPClassificationInput) model.FPClassification {
	s.called++
	return model.FPClassification{
		IsFalsePositive: s.isFP,
		Confidence:      s.confidence,
		CorrectionHint:  s.hint,
	}
}

func makeTestOutcome(suppressed bool) *VerificationOutcome {
	return &VerificationOutcome{
		Verified:   !suppressed,
		Suppressed: suppressed,
		Reason:     "proof-and-evidence-met",
		Policy:     proofpolicy.Result{Coverage: 1.0, MinCoverage: 1.0},
		Confidence: 0.85,
		EmittedFinding: model.Finding{
			ID:          "test-finding",
			Category:    "xss",
			Severity:    model.SeverityHigh,
			AffectedURL: "https://example.com/search",
		},
	}
}

func makeTestCandidate() VerifyCandidate {
	return VerifyCandidate{
		Finding: model.Finding{
			ID:          "test-finding",
			Category:    "xss",
			Severity:    model.SeverityHigh,
			AffectedURL: "https://example.com/search",
			Title:       "Reflected XSS",
			Evidence:    "<script>alert(1)</script> echoed in response",
			EvidenceFields: map[string]string{
				"param": "q",
			},
		},
		Signals:   []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved},
		ProbeName: "active_xss",
	}
}

// TestProbeCorrectionNilSafe verifies a nil ProbeCorrection is safe to use.
func TestProbeCorrectionNilSafe(t *testing.T) {
	t.Parallel()
	var pc *ProbeCorrection
	cand := makeTestCandidate()
	outcome := makeTestOutcome(false)
	if pc.Evaluate(context.Background(), cand, "probe", outcome) {
		t.Fatal("nil ProbeCorrection.Evaluate should return false")
	}
	if pc.DrainCorrectedRecords() != nil {
		t.Fatal("nil DrainCorrectedRecords should return nil")
	}
}

// TestProbeCorrectionUnknown verifies that too-few samples → no correction.
func TestProbeCorrectionUnknown(t *testing.T) {
	t.Parallel()
	classifier := &stubClassifier{isFP: true}
	pc := NewProbeCorrection(classifier)
	cand := makeTestCandidate()
	outcome := makeTestOutcome(false)

	// Only 2 firings (below minSamples=5); correction must not fire.
	for i := 0; i < 2; i++ {
		if pc.Evaluate(context.Background(), cand, "active_xss", outcome) {
			t.Fatal("correction fired before minSamples")
		}
	}
	if classifier.called != 0 {
		t.Fatalf("AI classifier should not be called before minSamples, got %d calls", classifier.called)
	}
	if outcome.Suppressed {
		t.Fatal("finding should not be suppressed before minSamples")
	}
}

// TestProbeCorrectionLikelyFP verifies high-FP-rate suppression without AI.
func TestProbeCorrectionLikelyFP(t *testing.T) {
	t.Parallel()
	classifier := &stubClassifier{isFP: false} // AI says NOT FP, but rule should override
	pc := NewProbeCorrection(classifier)
	cand := makeTestCandidate()

	// Seed 5 suppressed firings into the store to exceed the 70% threshold.
	for i := 0; i < 5; i++ {
		pc.store.Record("active_xss", cand.Finding.AffectedURL, true)
	}

	outcome := makeTestOutcome(false)
	corrected := pc.Evaluate(context.Background(), cand, "active_xss", outcome)
	if !corrected {
		t.Fatal("expected correction (suppression) at LikelyFP")
	}
	if !outcome.Suppressed {
		t.Fatal("outcome.Suppressed must be true after correction")
	}
	if outcome.Reason != "fp-rate-above-threshold" {
		t.Fatalf("unexpected reason %q", outcome.Reason)
	}
	if outcome.CorrectionHint == "" {
		t.Fatal("CorrectionHint should be set")
	}
	// AI classifier must NOT be called at LikelyFP.
	if classifier.called != 0 {
		t.Fatalf("AI should not be called at LikelyFP, got %d calls", classifier.called)
	}
}

// TestProbeCorrectionBorderlineAISaysFP verifies AI-driven suppression.
func TestProbeCorrectionBorderlineAISaysFP(t *testing.T) {
	t.Parallel()
	classifier := &stubClassifier{isFP: true, confidence: 0.85, hint: "baseline behavior matches payload"}
	pc := NewProbeCorrection(classifier)
	cand := makeTestCandidate()

	// Seed 3 suppressed + 2 verified = 60% → Borderline.
	for i := 0; i < 3; i++ {
		pc.store.Record("active_xss", cand.Finding.AffectedURL, true)
	}
	for i := 0; i < 2; i++ {
		pc.store.Record("active_xss", cand.Finding.AffectedURL, false)
	}

	outcome := makeTestOutcome(false)
	corrected := pc.Evaluate(context.Background(), cand, "active_xss", outcome)
	if !corrected {
		t.Fatal("expected AI-driven correction")
	}
	if classifier.called != 1 {
		t.Fatalf("AI should be called once, got %d", classifier.called)
	}
	if !outcome.Suppressed {
		t.Fatal("outcome.Suppressed must be true after AI correction")
	}
	if outcome.Reason != "ai-fp-classification" {
		t.Fatalf("unexpected reason %q", outcome.Reason)
	}
	if outcome.CorrectionHint != "baseline behavior matches payload" {
		t.Fatalf("unexpected CorrectionHint %q", outcome.CorrectionHint)
	}
	recs := pc.DrainCorrectedRecords()
	if len(recs) != 1 {
		t.Fatalf("expected 1 corrected record, got %d", len(recs))
	}
	if recs[0].Category != "xss" {
		t.Fatalf("unexpected category %q", recs[0].Category)
	}
}

// TestProbeCorrectionBorderlineAISaysReal verifies AI allows borderline real finding.
func TestProbeCorrectionBorderlineAISaysReal(t *testing.T) {
	t.Parallel()
	classifier := &stubClassifier{isFP: false, confidence: 0.9}
	pc := NewProbeCorrection(classifier)
	cand := makeTestCandidate()

	// Seed 3 suppressed + 2 verified = 60% → Borderline.
	for i := 0; i < 3; i++ {
		pc.store.Record("active_xss", cand.Finding.AffectedURL, true)
	}
	for i := 0; i < 2; i++ {
		pc.store.Record("active_xss", cand.Finding.AffectedURL, false)
	}

	outcome := makeTestOutcome(false)
	corrected := pc.Evaluate(context.Background(), cand, "active_xss", outcome)
	if corrected {
		t.Fatal("AI said not FP — finding should be admitted")
	}
	if outcome.Suppressed {
		t.Fatal("outcome should remain not-suppressed")
	}
}

// TestProbeCorrectionBorderlineNoAIClient verifies admission when no AI client.
func TestProbeCorrectionBorderlineNoAIClient(t *testing.T) {
	t.Parallel()
	pc := NewProbeCorrection(nil) // no AI
	cand := makeTestCandidate()

	// Seed 3 suppressed + 2 verified = 60% → Borderline.
	for i := 0; i < 3; i++ {
		pc.store.Record("active_xss", cand.Finding.AffectedURL, true)
	}
	for i := 0; i < 2; i++ {
		pc.store.Record("active_xss", cand.Finding.AffectedURL, false)
	}

	outcome := makeTestOutcome(false)
	corrected := pc.Evaluate(context.Background(), cand, "active_xss", outcome)
	if corrected {
		t.Fatal("without AI client, borderline finding should be admitted")
	}
}

// TestProbeCorrectionAlreadySuppressed verifies that already-suppressed outcomes
// are recorded but not double-suppressed.
func TestProbeCorrectionAlreadySuppressed(t *testing.T) {
	t.Parallel()
	classifier := &stubClassifier{isFP: true}
	pc := NewProbeCorrection(classifier)
	cand := makeTestCandidate()
	outcome := makeTestOutcome(true) // already suppressed

	corrected := pc.Evaluate(context.Background(), cand, "active_xss", outcome)
	if corrected {
		t.Fatal("already-suppressed outcome should not be double-corrected")
	}
	if classifier.called != 0 {
		t.Fatalf("AI should not be called for already-suppressed outcome")
	}
}

// TestWithProbeCorrection verifies context injection and extraction.
func TestWithProbeCorrection(t *testing.T) {
	t.Parallel()
	pc := NewProbeCorrection(nil)
	ctx := WithProbeCorrection(context.Background(), pc)
	got := probeCorrectionFromCtx(ctx)
	if got != pc {
		t.Fatalf("expected same ProbeCorrection pointer from context, got %v", got)
	}

	// Empty context returns nil.
	if probeCorrectionFromCtx(context.Background()) != nil {
		t.Fatal("expected nil from context without ProbeCorrection")
	}
}
