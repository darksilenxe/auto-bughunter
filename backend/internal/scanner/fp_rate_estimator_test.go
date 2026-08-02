package scanner

import (
	"testing"
)

func TestFPRateEstimator_Assess(t *testing.T) {
	t.Parallel()

	store := NewFPSignalStore()
	est := NewFPRateEstimator(store)
	const probe = "xss_probe"
	const url = "https://example.com/search"

	// Unknown — not enough samples.
	assessment, _, samples := est.Assess(probe, url)
	if assessment != FPAssessmentUnknown || samples != 0 {
		t.Fatalf("expected Unknown before minSamples, got %v (samples=%d)", assessment, samples)
	}

	// Add 5 firings, all suppressed → LikelyFP (100% > 70%).
	for i := 0; i < 5; i++ {
		store.Record(probe, url, true)
	}
	assessment, rate, _ := est.Assess(probe, url)
	if assessment != FPAssessmentLikelyFP {
		t.Fatalf("expected LikelyFP (rate=%.2f), got %v", rate, assessment)
	}

	// Reset and add 5 firings: 0 suppressed → LikelyReal.
	store2 := NewFPSignalStore()
	est2 := NewFPRateEstimator(store2)
	for i := 0; i < 5; i++ {
		store2.Record(probe, url, false)
	}
	assessment, _, _ = est2.Assess(probe, url)
	if assessment != FPAssessmentLikelyReal {
		t.Fatalf("expected LikelyReal, got %v", assessment)
	}

	// 3 suppressed of 5 → 60% → Borderline (0.30 ≤ 0.60 < 0.70).
	store3 := NewFPSignalStore()
	est3 := NewFPRateEstimator(store3)
	for i := 0; i < 3; i++ {
		store3.Record(probe, url, true)
	}
	for i := 0; i < 2; i++ {
		store3.Record(probe, url, false)
	}
	assessment, _, _ = est3.Assess(probe, url)
	if assessment != FPAssessmentBorderline {
		t.Fatalf("expected Borderline, got %v", assessment)
	}

	// Exact threshold at 70% → LikelyFP (>= 0.70).
	store4 := NewFPSignalStore()
	est4 := NewFPRateEstimator(store4)
	for i := 0; i < 7; i++ {
		store4.Record(probe, url, true)
	}
	for i := 0; i < 3; i++ {
		store4.Record(probe, url, false)
	}
	assessment, rate, _ = est4.Assess(probe, url)
	if assessment != FPAssessmentLikelyFP {
		t.Fatalf("expected LikelyFP at 70%% rate (got %v, rate=%.2f)", assessment, rate)
	}
}
